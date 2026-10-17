"""Scoped dashboard enhancements; no biometric or authentication scoring changes."""
import csv
import io
import time
import re
from datetime import datetime, timezone, timedelta
from fastapi import Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
try:
    from .session_monitor import PLATFORM_ROLES, MONITOR_ROLES, masked_ip, iso_time, lifecycle
except ImportError:
    from session_monitor import PLATFORM_ROLES, MONITOR_ROLES, masked_ip, iso_time, lifecycle

VERSION='2026-10-06.2'
STAGES={'credentials':'credential_status','face':'face_status','liveness':'liveness_status','voice':'voice_status','mfa':'mfa_status'}

def scope(user, requested=None):
    if user.get('role') not in MONITOR_ROLES:raise HTTPException(403,'Administrator role required')
    if user.get('role') in PLATFORM_ROLES:return {'organization_id':requested} if requested else {}
    org=user.get('organization_id')
    if not org or (requested and requested!=org):raise HTTPException(403,'Organization access denied')
    return {'organization_id':org}

def date_range(start=None,end=None):
    try:
        finish=datetime.strptime(end,'%Y-%m-%d').replace(tzinfo=timezone.utc)+timedelta(days=1) if end else datetime.now(timezone.utc)+timedelta(seconds=1)
        begin=datetime.strptime(start,'%Y-%m-%d').replace(tzinfo=timezone.utc) if start else finish-timedelta(days=30)
    except ValueError:raise HTTPException(422,'Dates must use YYYY-MM-DD')
    if begin>=finish or finish-begin>timedelta(days=366):raise HTTPException(422,'Choose a valid period of at most 366 days')
    return {'$gte':begin.timestamp(),'$lt':finish.timestamp()}

def factor_counts(records):
    result=[]
    for stage,field in STAGES.items():
        counts={'verified':0,'failed':0,'pending':0,'not_recorded':0,'recovery_used':0}
        for row in records:
            state=row.get(field)
            key='verified' if state=='VERIFIED' else 'recovery_used' if state=='FAILED_RECOVERY_USED' else 'failed' if state and ('FAIL' in state or state in {'MISMATCH','DENIED','BLOCKED'}) else 'pending' if state=='PENDING' else 'not_recorded'
            counts[key]+=1
        attempted=counts['verified']+counts['failed']+counts['recovery_used']
        result.append({'stage':stage,**counts,'failure_rate':round(counts['failed']/attempted*100,1) if attempted else None})
    return result

def redact_ips(text):
    # Allowlisted audit text may contain a legacy IP literal; mask those too.
    text=re.sub(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',lambda m:masked_ip(m.group()),str(text or ''))
    return re.sub(r'(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])',lambda m:masked_ip(m.group()) if masked_ip(m.group())!='Unavailable' else m.group(),text)

def csv_text(rows):
    output=io.StringIO(newline='');keys=['timestamp','event_type','email','organization_id','session_id','action','risk','ip_masked']
    writer=csv.DictWriter(output,fieldnames=keys);writer.writeheader()
    for row in rows:
        safe={k:str(row.get(k) or '') for k in keys}
        for k,v in safe.items():
            if v.lstrip().startswith(('=','+','-','@','\t','\r','\n')):safe[k]="'"+v
        writer.writerow(safe)
    return '\ufeff'+output.getvalue()

class ReverifyRequest(BaseModel):
    reason: str=Field(default='Administrator requested full authentication',min_length=5,max_length=240)

def register_dashboard_features(app,g):
    auth=g['get_authenticated_user_from_header']
    def database():
        if g.get('db') is None:raise HTTPException(503,'Database unavailable')
        return g['db']
    def target_session(sid,user):
        db=database();q=scope(user)
        s=db.auth_sessions.find_one({'$or':[{'session_id':sid},{'_id':sid}],**q})
        if not s and g['ObjectId'].is_valid(sid):s=db.auth_sessions.find_one({'_id':g['ObjectId'](sid),**q})
        if not s:raise HTTPException(404,'Session not found in your scope')
        return s
    def event_scope(user,requested=None):
        q=scope(user,requested)
        if not q:return {}
        db=database();ids=[]
        for collection in [db.auth_sessions,db.verification_sessions]:
            for s in collection.find(q,{'_id':1,'session_id':1,'verification_session_id':1}):
                ids.extend(str(s[k]) for k in ['_id','session_id','verification_session_id'] if s.get(k))
        return {'$or':[q,{'session_id':{'$in':ids}}]}

    @app.get('/api/v1/admin/dashboard/features/overview')
    def overview(organization_id: str=None,user:dict=Depends(auth)):
        q=scope(user,organization_id);db=database();now=time.time();groups={}
        orgs=list(db.organizations.find(q).limit(200))
        for org in orgs:
            oid=str(org.get('organization_id') or org['_id'])
            groups[oid]={'organization_id':oid,'name':org.get('organization_name') or org.get('name') or oid,'users':0,'roles':{},'active_sessions':0,'pending_accounts':0,'pending_requests':0,'open_alerts':0}
        def group(oid):
            return groups.setdefault(oid,{'organization_id':oid,'name':oid,'users':0,'roles':{},'active_sessions':0,'pending_accounts':0,'pending_requests':0,'open_alerts':0})
        seen=set()
        for collection in [db.users,db.healthcare_admins,db.deeptrust_admins]:
            for u in collection.find(q):
                key=(u.get('organization_id'),u.get('email_normalized') or u.get('email') or str(u['_id']))
                if key in seen:continue
                seen.add(key);row=group(u.get('organization_id') or 'UNASSIGNED');row['users']+=1
                role=u.get('role','UNKNOWN');row['roles'][role]=row['roles'].get(role,0)+1
                if str(u.get('status','')).startswith('PENDING'):row['pending_accounts']+=1
        for s in db.auth_sessions.find(q):
            if lifecycle(s,now)['running']:group(s.get('organization_id') or 'UNASSIGNED')['active_sessions']+=1
        for r in db.access_requests.find({**q,'status':'PENDING'}):group(r.get('organization_id') or 'UNASSIGNED')['pending_requests']+=1
        for r in db.security_events.find({**q,'status':{'$in':['OPEN','ACKNOWLEDGED','ESCALATED']}}):group(r.get('organization_id') or 'UNASSIGNED')['open_alerts']+=1
        return {'success':True,'organizations':list(groups.values()),'server_time':now,'version':VERSION}

    @app.get('/api/v1/admin/dashboard/features/auth-analytics')
    def analytics(start:str=None,end:str=None,organization_id:str=None,user:dict=Depends(auth)):
        q=scope(user,organization_id);period=date_range(start,end);db=database()
        records=list(db.verification_sessions.find({**q,'created_at':period}).sort('created_at',-1).limit(10001))
        truncated=len(records)>10000;records=records[:10000]
        return {'success':True,'stages':factor_counts(records),'verification_sessions':len(records),'truncated':truncated,'period':period,
            'engines':{'face_detection':'READY' if g.get('detector') is not None else 'UNAVAILABLE',
                'face_matching':'READY' if g.get('recognizer') is not None else 'UNAVAILABLE',
                'passive_liveness':'READY' if g.get('passive_pad') is not None else 'UNAVAILABLE',
                'phone_detection':'READY' if g.get('phone_guard') is not None else 'UNAVAILABLE',
                'voice':'AVAILABLE' if callable(g.get('verify_voice')) else 'UNAVAILABLE',
                'mfa':'AVAILABLE' if callable(g.get('verify_mfa')) else 'UNAVAILABLE'},
            'note':'Stored stage outcomes, not individual retry counts. Voice/MFA availability is not an end-to-end health probe.'}

    @app.post('/api/v1/admin/sessions/{session_id}/reverify')
    def reverify(session_id:str,req:ReverifyRequest,user:dict=Depends(auth)):
        s=target_session(session_id,user);db=database();now=time.time()
        if not lifecycle(s,now)['running']:raise HTTPException(409,'Session is already inactive')
        changed=db.auth_sessions.update_one({'_id':s['_id'],'revoked':{'$ne':True},'status':{'$in':['ACTIVE','IDLE']}}, {'$set':{'status':'STEP_UP_REQUIRED','revoked':True,'revoked_at':now,'ended_at':now,
            'reverification_requested_at':now,'reverification_requested_by':user.get('email'),'reverification_reason':req.reason,'updated_at':now}})
        if not changed.modified_count:raise HTTPException(409,'Session changed; refresh before requesting re-verification')
        uid=str(s.get('user_id') or s.get('identity_id'))
        g['log_audit_event']('REVERIFICATION_REQUESTED',uid,s.get('email',''),s.get('organization_name',''),
            'Administrator requested a fresh five-stage login',risk='MEDIUM',details={'actor':user.get('email'),'reason':req.reason},session_id=session_id,identity_id=uid)
        g['publish_security_event']('REVERIFICATION_REQUESTED',uid,organization_id=s.get('organization_id'),auth_session_id=session_id,severity='MEDIUM',risk_decision='STEP_UP',source='ADMIN_CONSOLE')
        return {'success':True,'status':'STEP_UP_REQUIRED','message':'Current access is invalidated. User must sign in through all normal verification stages again.'}

    @app.get('/api/v1/admin/dashboard/features/alerts/{event_id}')
    def alert(event_id:str,user:dict=Depends(auth)):
        db=database();q=scope(user);evt=db.security_events.find_one({'event_id':event_id,**q})
        if not evt:raise HTTPException(404,'Alert not found in your scope')
        sid=evt.get('auth_session_id');vsid=evt.get('verification_session_id');s=None
        if sid:
            try:s=target_session(sid,user)
            except HTTPException:s=None
        if not s and vsid:s=db.auth_sessions.find_one({'verification_session_id':vsid,**q})
        ids=[str(x) for x in [sid,vsid,s.get('session_id') if s else None,s.get('verification_session_id') if s else None] if x]
        timeline=list(db.audit_logs.find({'session_id':{'$in':ids},**event_scope(user)}).sort('created_at',1).limit(500)) if ids else []
        safe={k:evt.get(k) for k in ['event_id','event_type','identity','user_id','organization_id','severity','decision','risk_decision','reason_codes','status','timestamp','description']}
        safe['auth_session_id']=str(s.get('session_id') or s['_id']) if s else None
        safe['identity_id']=str(s.get('identity_id') or s.get('user_id')) if s else None
        safe['audit_timeline']=[{'event_type':e.get('event_type'),'action':e.get('action'),'timestamp':iso_time(e.get('created_at')) or e.get('timestamp')} for e in timeline]
        safe['correlation_status']='LINKED_SESSION' if s else 'VERIFICATION_ONLY' if vsid else 'NO_SESSION_RECORDED'
        return {'success':True,'event':safe}

    @app.get('/api/v1/admin/dashboard/features/audit')
    def audit(start:str=None,end:str=None,email:str=Query(default=None,max_length=254),organization_id:str=None,download:bool=False,user:dict=Depends(auth)):
        db=database();period=date_range(start,end);q={'$and':[event_scope(user,organization_id),{'created_at':period}]}
        if email:
            email=email.strip();identities=[]
            for collection in [db.users,db.healthcare_admins,db.deeptrust_admins]:
                identities.extend(str(u['_id']) for u in collection.find({'$or':[{'email':email},{'email_normalized':email.lower()}]}))
            q['$and'].append({'$or':[{'email':email},{'identity_id':{'$in':identities}},{'user_id':{'$in':identities}}]})
        records=list(db.audit_logs.find(q).sort('created_at',-1).limit(5001));truncated=len(records)>5000;records=records[:5000]
        email_cache={}
        def recorded_email(event):
            value=event.get('email') or ''
            if '@' in value:return value
            uid=str(event.get('identity_id') or event.get('user_id') or '')
            if uid not in email_cache:
                target=None
                for collection in [db.users,db.healthcare_admins,db.deeptrust_admins]:
                    target=collection.find_one({'_id':g['ObjectId'](uid) if g['ObjectId'].is_valid(uid) else uid})
                    if target:break
                email_cache[uid]=(target or {}).get('email') or 'Not recorded'
            return email_cache[uid]
        rows=[{'timestamp':iso_time(e.get('created_at')) or e.get('timestamp'),'event_type':e.get('event_type'),
            'email':recorded_email(e),'organization_id':e.get('organization_id') or 'Not recorded','session_id':str(e.get('session_id') or ''),
            'action':redact_ips(e.get('action')),'risk':e.get('risk'),'ip_masked':masked_ip((e.get('details') or {}).get('ip_address'))} for e in records]
        if download:
            if truncated:raise HTTPException(422,'More than 5000 events: narrow the dates, hospital or user filter before exporting')
            g['log_audit_event']('AUDIT_EXPORTED',str(user['_id']),user.get('email',''),user.get('organization_name',''),'Filtered audit CSV exported',details={'rows':len(rows)},session_id=user.get('session_id'))
            return Response(csv_text(rows),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename="DeepTrust-audit.csv"','Cache-Control':'no-store'})
        return {'success':True,'events':rows,'count':len(rows),'truncated':truncated,'period':period}

    return {"alert":alert}
