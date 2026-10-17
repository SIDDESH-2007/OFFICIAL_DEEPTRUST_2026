import sys,unittest,copy,time,ast
from pathlib import Path
from types import SimpleNamespace
from fastapi import FastAPI,HTTPException
from fastapi.testclient import TestClient
from bson import ObjectId
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server/ai_service'))
from dashboard_features import register_dashboard_features,factor_counts,csv_text,date_range,scope
from session_monitor import lifecycle
from security_controls import enforce_session

def match(d,q):
    for k,v in q.items():
        if k=='$or':
            if not any(match(d,x) for x in v):return False
        elif k=='$and':
            if not all(match(d,x) for x in v):return False
        elif isinstance(v,dict):
            for op,value in v.items():
                x=d.get(k)
                if op=='$in' and x not in value:return False
                if op=='$ne' and x==value:return False
                if op=='$gte' and (x is None or x<value):return False
                if op=='$lt' and (x is None or x>=value):return False
        elif d.get(k)!=v:return False
    return True
class Cursor(list):
    def sort(self,k,order):return Cursor(sorted(self,key=lambda d:d.get(k,0),reverse=order<0))
    def limit(self,n):return Cursor(self[:n])
class Collection:
    def __init__(self,docs=()):self.docs=copy.deepcopy(list(docs))
    def find(self,q=None,projection=None):return Cursor([copy.deepcopy(d) for d in self.docs if match(d,q or {})])
    def find_one(self,q):return next(iter(self.find(q)),None)
    def update_one(self,q,u):
        for d in self.docs:
            if match(d,q):d.update(u['$set']);return SimpleNamespace(modified_count=1)
        return SimpleNamespace(modified_count=0)

class FeatureTests(unittest.TestCase):
    def setUp(self):
        now=time.time();self.user={'_id':'admin-a','email':'admin@a.test','role':'HOSPITAL_ADMIN','organization_id':'a','session_id':'admin-s'}
        def session(sid,org):return {'_id':sid,'session_id':sid,'user_id':'user-'+org,'identity_id':'user-'+org,'email':org+'@test.test','organization_id':org,'verification_session_id':'v-'+org,'created_at':now-50,'login_at':now-50,'expires_at':now+500,'last_activity_at':now-2,'status':'ACTIVE'}
        self.db=SimpleNamespace(auth_sessions=Collection([session('s-a','a'),session('s-b','b')]),verification_sessions=Collection([
            {'_id':'va','session_id':'v-a','organization_id':'a','created_at':now-55,'credential_status':'VERIFIED','face_status':'FAILED','voice_status':'PENDING'},
            {'_id':'vb','session_id':'v-b','organization_id':'b','created_at':now-55,'face_status':'VERIFIED'}]),
            organizations=Collection([{'_id':'a','organization_id':'a','name':'Hospital A'},{'_id':'b','organization_id':'b','name':'Hospital B'}]),
            users=Collection([{'_id':'user-a','organization_id':'a','email':'a@test.test','role':'DOCTOR','status':'ACTIVE'},{'_id':'user-b','organization_id':'b','email':'b@test.test','role':'NURSE'}]),
            healthcare_admins=Collection(),deeptrust_admins=Collection(),access_requests=Collection([{'organization_id':'a','status':'PENDING'}]),
            security_events=Collection([{'event_id':'e-a','organization_id':'a','auth_session_id':'s-a','verification_session_id':'v-a','status':'OPEN'}, {'event_id':'e-b','organization_id':'b','auth_session_id':'s-b'}]),
            audit_logs=Collection([{'email':'a@test.test','identity_id':'user-a','session_id':'v-a','created_at':now-55,'event_type':'FACE_MISMATCH','action':'Face mismatch from 192.168.34.56','details':{'password':'PRIVATE','ip_address':'192.168.34.56'}},
                {'organization_id':'b','email':'b@test.test','session_id':'s-b','created_at':now-40,'event_type':'SECRET_OTHER_ORG'},
                {'email':'a@test.test','session_id':'unrelated','created_at':now-40,'event_type':'UNRELATED_SESSION'}]))
        self.logs=[];self.events=[]
        self.g={'db':self.db,'ObjectId':ObjectId,'get_authenticated_user_from_header':lambda:self.user,
            'log_audit_event':lambda *a,**k:self.logs.append((a,k)), 'publish_security_event':lambda *a,**k:self.events.append((a,k)),
            'verify_voice':lambda:None,'verify_mfa':lambda:None,'detector':None,'recognizer':None,'passive_pad':None,'phone_guard':None}
        app=FastAPI();register_dashboard_features(app,self.g);self.client=TestClient(app)
    def get(self,suffix):return self.client.get('/api/v1/admin/dashboard/features/'+suffix)
    def test_hospital_counts_and_pending_approvals_scoped(self):
        r=self.get('overview');self.assertEqual(r.status_code,200);orgs=r.json()['organizations'];self.assertEqual(len(orgs),1)
        self.assertEqual(orgs[0]['users'],1);self.assertEqual(orgs[0]['active_sessions'],1);self.assertEqual(orgs[0]['pending_requests'],1)
    def test_platform_sees_both_hospitals(self):
        self.user['role']='DEEPTRUST_OWNER';self.assertEqual(len(self.get('overview').json()['organizations']),2)
    def test_doctor_and_missing_scope_cannot_monitor(self):
        self.user['role']='DOCTOR';self.assertEqual(self.get('overview').status_code,403)
        self.user['role']='HOSPITAL_ADMIN';self.user.pop('organization_id');self.assertEqual(self.get('overview').status_code,403)
    def test_cross_hospital_filter_rejected(self):self.assertEqual(self.get('overview?organization_id=b').status_code,403)
    def test_factor_counts_real_outcomes_unknown_not_success(self):
        data=self.get('auth-analytics').json();face=next(s for s in data['stages'] if s['stage']=='face')
        self.assertEqual(face['failed'],1);self.assertEqual(face['verified'],0);self.assertEqual(face['failure_rate'],100)
        self.assertEqual(data['engines']['passive_liveness'],'UNAVAILABLE')
        self.assertEqual(next(s for s in data['stages'] if s['stage']=='mfa')['not_recorded'],1)
    def test_recovery_is_separate_not_biometric_verified(self):
        row=next(x for x in factor_counts([{'voice_status':'FAILED_RECOVERY_USED'}]) if x['stage']=='voice')
        self.assertEqual(row['recovery_used'],1);self.assertEqual(row['verified'],0)
    def test_invalid_dates_and_reversed_dates_fail(self):
        for query in ['start=bad','start=2026-12-01&end=2026-01-01','start=2020-01-01&end=2026-10-06']:
            self.assertEqual(self.get('audit?'+query).status_code,422)
    def test_audit_excludes_other_org_and_uncorrelated_legacy(self):
        data=self.get('audit').json();self.assertEqual(data['count'],1);self.assertNotIn('SECRET_OTHER_ORG',str(data));self.assertNotIn('UNRELATED_SESSION',str(data))
        self.assertNotIn('PRIVATE',str(data));self.assertNotIn('192.168.34.56',str(data));self.assertEqual(data['events'][0]['ip_masked'],'192.168.**.**')
    def test_mismatch_counted_as_failed(self):
        row=next(x for x in factor_counts([{'face_status':'MISMATCH'}]) if x['stage']=='face')
        self.assertEqual(row['failed'],1)
    def test_large_export_requires_narrow_filters(self):
        event=self.db.audit_logs.docs[0]
        self.db.audit_logs.docs=[dict(event) for _ in range(5001)]
        self.assertTrue(self.get('audit').json()['truncated'])
        self.assertEqual(self.get('audit?download=true').status_code,422)
    def test_user_filter_includes_legacy_numeric_email_records(self):
        self.db.audit_logs.docs[0]['email']='user-a'
        self.assertEqual(self.get('audit?email=a@test.test').json()['count'],1)
    def test_audit_exact_user_filter(self):self.assertEqual(self.get('audit?email=missing@test.test').json()['count'],0)
    def test_csv_response_and_export_audit(self):
        r=self.get('audit?download=true');self.assertEqual(r.status_code,200);self.assertIn('text/csv',r.headers['content-type'])
        self.assertNotIn('PRIVATE',r.text);self.assertIn('FACE_MISMATCH',r.text);self.assertEqual(self.logs[-1][0][0],'AUDIT_EXPORTED')
    def test_csv_formula_injection_neutralized(self):
        text=csv_text([{'action':'=HYPERLINK("evil")','email':' +CMD()'}]);self.assertIn("'=HYPERLINK",text);self.assertIn("' +CMD",text)
    def test_alert_exact_session_and_cross_org_protection(self):
        data=self.get('alerts/e-a').json()['event'];self.assertEqual(data['auth_session_id'],'s-a');self.assertEqual(len(data['audit_timeline']),1)
        self.assertEqual(self.get('alerts/e-b').status_code,404)
    def test_reverify_invalidates_only_target_keeps_enrollment(self):
        r=self.client.post('/api/v1/admin/sessions/s-a/reverify',json={'reason':'Suspicious access investigation'})
        self.assertEqual(r.status_code,200);s=self.db.auth_sessions.docs[0];self.assertTrue(s['revoked']);self.assertEqual(s['status'],'STEP_UP_REQUIRED')
        self.assertEqual(lifecycle(s,time.time()+100)['status'],'STEP_UP_REQUIRED');self.assertFalse(lifecycle(s,time.time()+100)['running'])
        self.assertEqual(self.db.auth_sessions.docs[1]['status'],'ACTIVE');self.assertEqual(self.db.users.docs[0]['status'],'ACTIVE')
        self.assertEqual(self.events[-1][1]['organization_id'],'a');self.assertEqual(self.logs[-1][1]['session_id'],'s-a')
    def test_reverify_inactive_and_wrong_org_rejected(self):
        self.assertEqual(self.client.post('/api/v1/admin/sessions/s-b/reverify',json={}).status_code,404)
        self.db.auth_sessions.docs[0].update(status='LOGGED_OUT',logout_at=time.time())
        self.assertEqual(self.client.post('/api/v1/admin/sessions/s-a/reverify',json={}).status_code,409)
    def test_reverify_blocked_at_existing_auth_gate(self):
        self.client.post('/api/v1/admin/sessions/s-a/reverify',json={})
        tree=ast.parse((ROOT/'server/ai_service/face_service.py').read_text(encoding='utf-8'));fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='get_authenticated_user_from_header');fn.decorator_list=[]
        env={'enforce_session':enforce_session,'Header':lambda _:None,'Optional':__import__('typing').Optional,'Dict':__import__('typing').Dict,'Any':__import__('typing').Any,'db':self.db,'HTTPException':HTTPException,'time':time,
            'decode_jwt_token':lambda token:{'token_type':'ACCESS','session_id':'s-a','email':'a@test.test'}}
        exec(compile(ast.Module(body=[fn],type_ignores=[]),'<actual auth gate>','exec'),env)
        with self.assertRaises(HTTPException) as err:env['get_authenticated_user_from_header']('Bearer test')
        self.assertEqual(err.exception.status_code,401)

if __name__=='__main__':unittest.main()
