"""Monthly metrics from stored audit events, with explicit source and coverage."""
from datetime import datetime, timezone
from collections import defaultdict
from fastapi import HTTPException

def month_bounds(year, month):
    try:
        start = datetime(year, month, 1, tzinfo=timezone.utc)
        end = datetime(year+1, 1, 1, tzinfo=timezone.utc) if month == 12 else datetime(year, month+1, 1, tzinfo=timezone.utc)
    except (ValueError, TypeError):
        raise HTTPException(422, 'Choose a valid year and month')
    return {'$gte':start.timestamp(), '$lt':end.timestamp()}

def aggregate_month(db, year, month):
    if db is None:
        raise HTTPException(503, 'Report database unavailable')
    query = {'created_at':month_bounds(year, month), 'is_demo':{'$ne':True}}
    audits = list(db.audit_logs.find(query))
    security = list(db.security_events.find(query))
    auth_links = {str(s.get('session_id') or s['_id']):s.get('verification_session_id')
                  for s in db.auth_sessions.find({})}
    buckets = defaultdict(set)
    groups = {}
    names = {str(o.get('organization_id') or o['_id']):o.get('name') or o.get('organization_name')
             for o in db.organizations.find({})}

    def row_key(row):
        sid = row.get('session_id') or row.get('auth_session_id') or row.get('verification_session_id')
        return str(auth_links.get(str(sid)) or sid or row.get('event_id') or row['_id'])

    def group(row):
        oid = row.get('organization_id') or 'UNASSIGNED'
        return groups.setdefault(oid, {'name':names.get(str(oid)) or ('Unassigned historical records' if oid=='UNASSIGNED' else str(oid)),
            'auth_count':set(), 'successful_access':set(), 'blocked_access':set(), 'security_events':set()})

    successes = {'FINAL_ACCESS_GRANTED','LOGIN_SUCCESS'}
    failures = {'LOGIN_FAILED','CREDENTIALS_FAILED'}
    stages = {
        'FACE_VERIFIED':'face_verified', 'FACE_MISMATCH':'face_failed', 'FACE_VERIFICATION_FAILED':'face_failed',
        'LIVENESS_VERIFIED':'liveness_verified', 'LIVENESS_FAILED':'liveness_failed',
        'VOICE_VERIFIED':'voice_verified', 'VOICE_VERIFICATION_SUCCESS':'voice_verified',
        'VOICE_MISMATCH':'voice_failed', 'VOICE_VERIFICATION_FAILED':'voice_failed',
        'VOICE_VERIFICATION_FAILED_ATTEMPT_1':'voice_failed',
        'MFA_VERIFIED':'mfa_verified', 'MFA_FAILED':'mfa_failed',
    }
    for row in audits:
        event = row.get('event_type')
        key = row_key(row)
        org = group(row)
        if event == 'LOGIN_ATTEMPT' or event in failures or event in successes:
            buckets['total_login_attempts'].add(key)
            org['auth_count'].add(key)
        if event in successes:
            buckets['successful_authentications'].add(key)
            org['successful_access'].add(key)
        if event in failures:
            buckets['failed_authentications'].add(key)
        if event == 'ACCESS_ALLOWED':
            buckets['legacy_access_allowed'].add(key)
        if event in stages:
            buckets[stages[event]].add(key)

    for row in security:
        key = str(row.get('event_id') or row['_id'])
        org = group(row)
        buckets['security_events_total'].add(key)
        org['security_events'].add(key)
        if row.get('decision') == 'BLOCK' or row.get('risk_decision') == 'BLOCK':
            buckets['blocked_attempts'].add(key)
            org['blocked_access'].add(key)
        if row.get('severity') in {'HIGH','CRITICAL'}:
            buckets['high_risk_events'].add(key)
        if row.get('status') == 'OPEN':buckets['open_alerts'].add(key)
        if row.get('status') == 'RESOLVED':buckets['resolved_alerts'].add(key)

    keys = ['total_login_attempts','successful_authentications','failed_authentications','blocked_attempts',
            'security_events_total','high_risk_events','open_alerts','resolved_alerts','legacy_access_allowed'] + list(set(stages.values()))
    result = {key:len(buckets[key]) for key in keys}
    for stage in ['face','liveness','voice','mfa']:
        # Outcomes per correlated session; a retried session can have both a failure and a success.
        result[stage+'_attempts'] = len(buckets[stage+'_verified'] | buckets[stage+'_failed'])
    result.update({
        'face_verification_failures':result['face_failed'], 'liveness_failures':result['liveness_failed'],
        'voice_verification_failures':result['voice_failed'], 'mfa_success':result['mfa_verified'],
        'organizations':[{**row, **{k:len(v) for k,v in row.items() if isinstance(v,set)}} for row in groups.values()],
        'demo_records_excluded':db.audit_logs.count_documents({'created_at':query['created_at'], 'is_demo':True}) + db.security_events.count_documents({'created_at':query['created_at'], 'is_demo':True}),
        'data_source':'MongoDB stored events',
        'counting_note':'Login counts use credential attempts/failures and final login grants, grouped by session ID where available. Legacy ACCESS_ALLOWED events are reported separately because they do not prove full login completion. Blocked counts use security events only. Explicit demo records are excluded; unmarked historical records may include test activity.',
    })
    return result
