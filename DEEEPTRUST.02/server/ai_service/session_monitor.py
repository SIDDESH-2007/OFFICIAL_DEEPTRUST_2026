"""Session lifecycle and privacy-safe monitoring projections. No app startup."""
import ipaddress
import math
from datetime import datetime, timezone

PLATFORM_ROLES={'DEEPTRUST_OWNER','DEEPTRUST_ADMIN','OWNER','ADMIN'}
MONITOR_ROLES=PLATFORM_ROLES|{'HOSPITAL_ADMIN','ORG_ADMIN','SECURITY_ADMIN','HOSPITAL_SECURITY_ADMIN','AUDITOR'}

def masked_ip(value):
    try:
        ip=ipaddress.ip_address(str(value).replace('::ffff:',''))
        if ip.version==4:
            parts=str(ip).split('.')
            return f'{parts[0]}.{parts[1]}.**.**'
        return ':'.join(ip.exploded.split(':')[:2])+':****:****:****:****:****:****'
    except ValueError:return 'Unavailable'

def iso_time(value):
    try:return datetime.fromtimestamp(float(value),timezone.utc).isoformat() if value is not None else None
    except (ValueError,TypeError,OverflowError,OSError):return None

def duration_text(seconds):
    seconds=max(0,int(seconds));return f'{seconds//3600:02d}:{seconds//60%60:02d}:{seconds%60:02d}'

def lifecycle(s,now):
    login=float(s.get('login_at') or s.get('created_at') or now)
    last=float(s.get('last_activity_at') or login)
    expiry=float(s.get('expires_at') or login+8*3600)
    status=s.get('status','ACTIVE')
    end=None
    if status=='EXPIRED':end=s.get('ended_at') or expiry
    elif status=='STEP_UP_REQUIRED':end=s.get('ended_at') or s.get('revoked_at') or last
    elif status=='LOGGED_OUT':end=s.get('logout_at') or s.get('revoked_at') or last
    elif status=='REVOKED' or s.get('revoked'):
        status='REVOKED';end=s.get('revoked_at') or s.get('logout_at') or last
    elif s.get('logout_at'):
        status='LOGGED_OUT';end=s['logout_at']
    elif now>=expiry:
        status='EXPIRED';end=expiry
    elif status in {'ACTIVE','IDLE'}:
        status='IDLE' if now-last>=1800 else 'ACTIVE'
    else:end=s.get('ended_at') or last
    seconds=max(0,int(min(now,end if end is not None else now)-login))
    return {'status':status,'login':login,'last':last,'end':end,'duration_seconds':seconds,
            'duration_formatted':duration_text(seconds),'running':status in {'ACTIVE','IDLE'}}

def session_projection(s,now):
    life=lifecycle(s,now);dev=s.get('device_context') or {}
    behavior=dict(s.get('behavior_summary') or {'status':'INSUFFICIENT_DATA','reason_codes':['NO_TELEMETRY']})
    if not behavior.get('updated_at'):
        behavior={'status':'INSUFFICIENT_DATA','reason_codes':['NO_TELEMETRY'],'assessment':'No measured interaction data'}
    if behavior.get('updated_at'):
        age=max(0,now-float(behavior['updated_at']))
        behavior['data_age_seconds']=int(age)
        behavior['freshness']='LIVE' if life['running'] and age<=45 else ('STALE' if life['running'] else 'HISTORICAL')
        if behavior['freshness']=='STALE':
            behavior['last_measured_status']=behavior.get('status','INSUFFICIENT_DATA')
            behavior['last_automation_assessment']=behavior.get('automation_assessment','INSUFFICIENT_DATA')
            behavior['status']='STALE_DATA'
            behavior['automation_assessment']='STALE_DATA'
            behavior['assessment']='No recent interaction summary received. Last measured results are shown below.'
            behavior['reason_codes']=list(behavior.get('reason_codes') or [])+['TELEMETRY_STALE']
    else:behavior['freshness']='NOT_MEASURED'
    sid=str(s.get('session_id') or s.get('_id'))
    return {
        'session_id':sid,'identity_id':str(s.get('identity_id') or s.get('user_id') or ''),
        'user_id':str(s.get('user_id') or s.get('identity_id') or ''),'email':s.get('email') or s.get('email_snapshot') or 'Unavailable',
        'full_name':s.get('full_name') or s.get('email') or 'Unavailable','role':s.get('role','UNKNOWN'),
        'organization':s.get('organization_name','Unavailable'),'organization_name':s.get('organization_name','Unavailable'),
        'application':s.get('application_name','Unavailable'),'application_name':s.get('application_name','Unavailable'),
        'login_at':life['login'],'login_time_iso':iso_time(life['login']),'login_time_formatted':iso_time(life['login']),
        'logout_at':s.get('logout_at'),'logout_time_iso':iso_time(s.get('logout_at')),
        'logout_time_formatted':iso_time(s.get('logout_at')),'last_activity_at':life['last'],
        'last_activity_iso':iso_time(life['last']),'last_activity_formatted':iso_time(life['last']),
        'duration_seconds':life['duration_seconds'],'duration_formatted':life['duration_formatted'],'duration_display':life['duration_formatted'],
        'server_time':now,'duration_running':life['running'],'status':life['status'],'is_active':life['running'],
        'ip_address':masked_ip(s.get('current_ip_address') or s.get('ip_address') or s.get('ip')),'ip_masked':masked_ip(s.get('current_ip_address') or s.get('ip_address') or s.get('ip')),
        'ip_address_display':masked_ip(s.get('current_ip_address') or s.get('ip_address') or s.get('ip')),'network_status':s.get('network_status','UNKNOWN'),
        'device':dev.get('display_device') or s.get('device') or 'Unavailable',
        'device_formatted':dev.get('display_device') or s.get('device') or 'Unavailable',
        'browser':dev.get('browser','Unknown'),'os':dev.get('os','Unknown'),'device_category':dev.get('category','Unknown'),
        'device_trust':s.get('device_trust') or dev.get('device_trust') or 'UNKNOWN',
        'risk_score':s.get('risk_score',0),'risk_level':s.get('risk_level','UNKNOWN'),
        'behavior_summary':behavior,'current_view':s.get('current_view','Not recorded'),
        'last_heartbeat_iso':iso_time(s.get('last_heartbeat_at')),
        'connection_status':'ONLINE' if life['running'] and now-float(s.get('last_heartbeat_at') or life['login'])<60 else 'OFFLINE',
        'observed_active_seconds':s.get('observed_active_seconds',0),
    }

def assurance_projection(vs):
    vs=vs or {}
    return {key:vs.get(field,'NOT_RECORDED') for key,field in [
        ('credentials','credential_status'),('face','face_status'),('liveness','liveness_status'),
        ('voice','voice_status'),('authenticator','mfa_status')]}

def behavior_signal(data):
    numeric=['average_velocity','velocity_variance','movement_rate','click_rate','idle_ratio','sample_count','trusted_events','synthetic_events','window_seconds','scroll_events','wheel_events','swipe_count','pointer_interval_cv','path_straightness','path_segments']
    for key in numeric:
        value=float(data.get(key,0))
        if not math.isfinite(value) or value<0:raise ValueError('Behavior metrics must be finite and non-negative')
    if data.get('idle_ratio',0)>1:raise ValueError('Invalid idle ratio')
    if data.get('path_straightness',0)>1:raise ValueError('Invalid path straightness')
    reasons=[]
    if data.get('webdriver') or data.get('synthetic_events',0)>=3:reasons.append('CLIENT_AUTOMATION_INDICATOR')
    if data.get('sample_count',0)>=10 and (data.get('movement_rate',0)>2000 or data.get('click_rate',0)>20):reasons.append('UNUSUAL_EVENT_RATE')
    if data.get('sample_count',0)>=10 and data.get('average_velocity',0)>12000:reasons.append('UNUSUAL_POINTER_SPEED')
    if (not data.get('is_touch_device') and data.get('sample_count',0)>=60 and
            data.get('path_segments',0)>=4 and data.get('path_straightness',0)>.995 and
            data.get('pointer_interval_cv',0)<.02 and data.get('average_velocity',0)>100 and
            data.get('velocity_variance',0)<(data.get('average_velocity',0)*.03)**2):
        reasons.append('REPETITIVE_POINTER_PATTERN')
    window=max(1,float(data.get('window_seconds',15)))
    if data.get('wheel_events',0)/window>100 or data.get('swipe_count',0)/window>8:
        reasons.append('UNUSUAL_SCROLL_SWIPE_RATE')
    measured=(data.get('sample_count',0)>=5 or data.get('trusted_events',0)>=5 or data.get('scroll_events',0)>=3 or data.get('swipe_count',0)>=2)
    status='DEVIATION' if reasons else ('NORMAL' if measured else 'INSUFFICIENT_DATA')
    return {'status':status,'reason_codes':reasons or (['NO_POINTER_SAMPLES'] if status=='INSUFFICIENT_DATA' else []),
        'assessment':'Suspicious interaction indicators' if reasons else ('No unusual indicators observed' if status=='NORMAL' else 'Insufficient interaction data'),
        'evidence_source':'CLIENT_REPORTED','identity_claim':'UNDETERMINED',
        'algorithm':'INTERACTION_RULES_V2','automation_assessment':'INDICATORS_PRESENT' if reasons else ('NO_INDICATORS_OBSERVED' if measured else 'INSUFFICIENT_DATA'),
        'scroll_rate':data.get('scroll_events',0)/window,'swipe_rate':data.get('swipe_count',0)/window,
        'interaction_velocity':f"{data.get('average_velocity',0):.1f} px/s",
        **{k:data.get(k,0) for k in numeric},'webdriver':bool(data.get('webdriver',False)),
        'is_touch_device':bool(data.get('is_touch_device',False))}
