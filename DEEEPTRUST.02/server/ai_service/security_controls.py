"""Backend access controls and signed, append-only audit records."""
import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from bson import ObjectId
from fastapi import HTTPException, Depends
from fastapi.responses import JSONResponse

PLATFORM = {'DEEPTRUST_OWNER', 'DEEPTRUST_ADMIN', 'OWNER', 'ADMIN'}
MANAGERS = PLATFORM | {'HOSPITAL_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN', 'HOSPITAL_SECURITY_ADMIN'}
READERS = MANAGERS | {'AUDITOR'}

def session_deadline(session, policy=None):
    policy = policy or {}
    login = float(session.get('login_at') or session.get('created_at') or 0)
    last = float(session.get('last_activity_at') or login)
    idle = max(60, min(86400, int(policy.get('session_idle_timeout') or 1800)))
    absolute = max(60, min(86400, int(policy.get('session_absolute_timeout') or 28800)))
    return min(last + idle, login + absolute, float(session.get('expires_at') or login + absolute))

def enforce_session(db, decoded, now=None, on_expire=None):
    now = time.time() if now is None else now
    if db is None:
        raise HTTPException(503, 'Session database unavailable')
    sid = decoded.get('session_id')
    if not sid:
        raise HTTPException(401, 'Access token must identify a session')
    session = db.auth_sessions.find_one({'$or': [{'_id':sid}, {'session_id':sid}]})
    if not session or session.get('revoked') or session.get('status') not in {'ACTIVE','IDLE'}:
        raise HTTPException(401, 'Session is missing, revoked or ended')
    identity = str(session.get('identity_id') or session.get('user_id') or '')
    if not identity or identity != str(decoded.get('sub') or ''):
        raise HTTPException(401, 'Session identity mismatch')
    if (session.get('email') or '').lower() != (decoded.get('email') or '').lower():
        raise HTTPException(401, 'Session account mismatch')
    policy = db.security_policies.find_one({'organization_id':session.get('organization_id')}) or {}
    deadline = session_deadline(session, policy)
    if now >= deadline:
        result = db.auth_sessions.update_one({'_id':session['_id'], 'status':{'$in':['ACTIVE','IDLE']}},
            {'$set':{'status':'EXPIRED', 'revoked':True, 'ended_at':deadline, 'revoked_at':deadline,
                     'session_duration_seconds':max(0,int(deadline-float(session.get('login_at') or session.get('created_at') or deadline))),
                     'end_reason':'SESSION_TIMEOUT'}})
        if on_expire and result.modified_count:
            on_expire(session, deadline)
        raise HTTPException(401, 'Session expired due to inactivity or maximum lifetime')
    return session

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), default=str, ensure_ascii=False)

class AuditChain:
    """Single backend writer; anchor is stored outside MongoDB, never supplied by the client.

    Deleting/editing database rows is detectable. Protect the anchor and signing key
    with host access controls; this does not claim to withstand host administrator compromise.
    """
    def __init__(self, secret, anchor_path):
        self.key = hmac.new(secret.encode(), b'DeepTrust audit signing v1', hashlib.sha256).digest()
        self.path = Path(anchor_path)
        self.lock = threading.RLock()

    def mac(self, payload):
        return hmac.new(self.key, canonical(payload).encode(), hashlib.sha256).hexdigest()

    def anchor(self):
        if not self.path.exists():
            return {'sequence':0, 'hash':'GENESIS'}
        stored = json.loads(self.path.read_text(encoding='utf-8'))
        signature = stored.pop('signature', '')
        if not hmac.compare_digest(signature, self.mac(stored)):
            raise ValueError('Audit checkpoint signature invalid')
        return stored

    def append(self, collection, record):
        with self.lock:
            anchor = self.anchor()
            # Detect tail deletion or an interrupted commit before signing a new record.
            tail = collection.find_one({'integrity.sequence':anchor['sequence']}) if anchor['sequence'] else None
            if anchor['sequence'] and (not tail or tail.get('integrity',{}).get('hash') != anchor['hash']):
                raise ValueError('Audit checkpoint does not match the database')
            if collection.count_documents({'integrity.version':1}) != anchor['sequence']:
                raise ValueError('Audit chain count does not match the checkpoint')
            row = dict(record)
            row['_id'] = row.get('_id') or ObjectId()
            proof = {'version':1, 'sequence':anchor['sequence']+1, 'previous':anchor['hash']}
            proof['hash'] = self.mac({'record':row, 'sequence':proof['sequence'], 'previous':proof['previous']})
            row['integrity'] = proof
            collection.insert_one(row)
            next_anchor = {'sequence':proof['sequence'], 'hash':proof['hash']}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix('.tmp')
            temporary.write_text(canonical({**next_anchor, 'signature':self.mac(next_anchor)}), encoding='utf-8')
            os.replace(temporary, self.path)

    def verify(self, collection):
        with self.lock:
            legacy = collection.count_documents({'integrity.version':{'$ne':1}})
            try:
                anchor = self.anchor()
                previous = 'GENESIS'
                count = 0
                for row in collection.find({'integrity.version':1}).sort('integrity.sequence',1):
                    proof = row.pop('integrity')
                    count += 1
                    if proof.get('sequence') != count or proof.get('previous') != previous:
                        raise ValueError('Audit sequence gap or chain link mismatch')
                    expected = self.mac({'record':row, 'sequence':count, 'previous':previous})
                    if not hmac.compare_digest(proof.get('hash',''), expected):
                        raise ValueError('Audit record signature mismatch')
                    previous = expected
                if count != anchor['sequence'] or previous != anchor['hash']:
                    raise ValueError('Audit deletion or checkpoint mismatch detected')
                return {'status':'VERIFIED' if count else 'NO_SIGNED_RECORDS', 'signed_records':count,
                        'legacy_unsigned_records':legacy, 'checked_at':time.time(), 'coverage':'New records only'}
            except (ValueError, KeyError, TypeError, OSError) as error:
                return {'status':'TAMPER_DETECTED', 'legacy_unsigned_records':legacy,
                        'reason':str(error), 'checked_at':time.time()}

def route_permission(path, method, user):
    role = user.get('role')
    own = path.startswith(('/api/v1/profile', '/api/v1/session/')) or path == '/api/v1/auth/me'
    if own:
        return
    tenant_admin = path.startswith(('/api/v1/admin/sessions/', '/api/v1/admin/audit/', '/api/v1/admin/dashboard/features/', '/api/v1/admin/alerts/'))
    platform_only = path.startswith(('/api/v1/admin/', '/api/v1/integrations', '/api/v1/settings')) and not tenant_admin
    if platform_only and role not in PLATFORM:
        raise HTTPException(403, 'Platform administrator permission required')
    if role not in READERS:
        raise HTTPException(403, 'Security dashboard permission required')
    if method not in {'GET','HEAD','OPTIONS'} and role not in MANAGERS:
        raise HTTPException(403, 'Auditor access is read-only')
    if role not in PLATFORM and not user.get('organization_id'):
        raise HTTPException(403, 'Organization scope required')

def register_security_controls(app, g, audit_chain):
    auth = g['get_authenticated_user_from_header']
    prefixes = ('/api/v1/admin/', '/api/v1/dashboard/', '/api/v1/identities', '/api/v1/security-events',
                '/api/v1/access-requests', '/api/v1/audit-logs', '/api/v1/reports/', '/api/v1/alerts',
                '/api/v1/incidents', '/api/v1/security/', '/api/v1/devices', '/api/v1/security-policies',
                '/api/v1/integrations', '/api/v1/settings', '/api/v1/profile', '/api/v1/session/', '/api/v1/telemetry/')
    public = {'/api/v1/admin/register', '/api/v1/admin/email/send-code', '/api/v1/admin/email/resend-code', '/api/v1/admin/email/verify-code',
              '/api/v1/access-requests/request', '/api/v1/access-requests/verify'}

    @app.middleware('http')
    async def security_guard(request, call_next):
        path = request.url.path.rstrip('/')
        if request.method != 'OPTIONS' and path not in public and (path == '/api/v1/auth/me' or path.startswith(prefixes)):
            user = None
            try:
                from starlette.concurrency import run_in_threadpool
                user = await run_in_threadpool(auth, request.headers.get('authorization'))
                route_permission(path, request.method, user)
                if user.get('role') not in PLATFORM:
                    requested = request.query_params.get('organization_id')
                    if requested and requested != user.get('organization_id'):
                        raise HTTPException(403, 'Cross-organization access denied')
                    if request.method == 'POST' and path.startswith('/api/v1/telemetry/'):
                        try:
                            body = await request.json()
                        except ValueError:
                            raise HTTPException(422, 'Invalid telemetry payload')
                        if body.get('organization_id') != user.get('organization_id'):
                            raise HTTPException(403, 'Telemetry must belong to your organization')
            except HTTPException as error:
                if error.status_code == 403 and user and g.get('log_audit_event'):
                    await run_in_threadpool(g['log_audit_event'], 'AUTHORIZATION_DENIED', str(user['_id']),
                        user.get('email',''), user.get('organization_name',''), 'Backend permission denied',
                        risk='MEDIUM', details={'route':path,'method':request.method}, session_id=user.get('session_id'))
                return JSONResponse({'detail':error.detail}, status_code=error.status_code)
        return await call_next(request)

    @app.get('/api/v1/admin/audit/integrity')
    def audit_integrity(user:dict=Depends(auth)):
        if user.get('role') not in PLATFORM:
            raise HTTPException(403, 'Platform administrator permission required')
        if g.get('db') is None:
            raise HTTPException(503, 'Audit database unavailable')
        return {'success':True, 'integrity':audit_chain.verify(g['db'].audit_logs)}
