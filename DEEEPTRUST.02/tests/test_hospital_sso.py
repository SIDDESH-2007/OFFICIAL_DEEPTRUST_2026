import ast, json, secrets, time, unittest, urllib.parse
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
import sys
from fastapi import HTTPException, Response
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server/ai_service'))
from hospital_sso import staff_role,check_staff_identity,login_notification

class Collection:
    def __init__(self,rows=()):self.rows=list(rows)
    def find_one(self,query):
        return next((r for r in self.rows if all(r.get(k)==v for k,v in query.items())),None)
    def insert_one(self,row):self.rows.append(row)

class StaffTests(unittest.TestCase):
    def test_all_staff_roles_accept_personal_email(self):
        for role in ('HOSPITAL_ADMIN','DOCTOR','NURSE','RECEPTIONIST','LAB_TECH','LAB_TECHNICIAN','PHARMACIST'):
            user={'email':'person@gmail.com','role':role,'organization_id':'hospital'}
            self.assertTrue(check_staff_identity(user,'hospital'))
    def test_platform_role_cannot_become_hospital_admin(self):
        with self.assertRaises(HTTPException):check_staff_identity({'role':'DEEPTRUST_OWNER','organization_id':'hospital'},'hospital','admin')
    def test_other_hospital_denied(self):
        with self.assertRaises(HTTPException):check_staff_identity({'role':'DOCTOR','organization_id':'other'},'hospital')
    def test_role_escalation_denied(self):
        with self.assertRaises(HTTPException):check_staff_identity({'role':'NURSE','organization_id':'hospital'},'hospital','admin')
    def test_notification_uses_actual_risk_and_device(self):
        s={'session_id':'as_1','organization_id':'hospital','risk_score':72,'risk_level':'HIGH','device_trust':'UNTRUSTED'}
        n=login_notification({'email':'doctor@gmail.com','role':'DOCTOR'},s,'client','NovaCare Medical Center')
        self.assertEqual(n['risk_score'],72);self.assertEqual(n['device_trust'],'UNTRUSTED')
        self.assertIn('doctor@gmail.com',n['message']);self.assertIn('Doctor',n['message'])
        self.assertEqual(n['notification_id'],login_notification({},s,'client','hospital')['notification_id'])
        self.assertNotIn('password',n);self.assertNotIn('embedding',n)
    def test_unknown_device_not_reported_trusted(self):
        n=login_notification({}, {'session_id':'as_1'},'client','hospital')
        self.assertEqual(n['device_trust'],'UNKNOWN');self.assertIsNone(n['risk_score'])

class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.user={'email':'doctor@gmail.com','role':'DOCTOR','organization_id':'hospital','status':'ACTIVE'}
        self.session={'session_id':'as_1','verification_session_id':'vs_1','email':'doctor@gmail.com','organization_id':'hospital','risk_status':'ALLOW','risk_score':21,'risk_level':'LOW','device_trust':'UNKNOWN'}
        self.db=SimpleNamespace(integrations=Collection([{'client_id':'client','organization_id':'hospital','allowed_redirects':['http://localhost:5176']}]),organizations=Collection([{'organization_id':'hospital','status':'ACTIVE'}]),auth_sessions=Collection([self.session]),security_policies=Collection(),oauth_authorization_codes=Collection())
        def authenticate(header):
            if header!='Bearer final-token':raise HTTPException(401,'Missing final token')
            return self.user
        scope={'Optional':Optional,'OAuthAuthorizeInput':object,'Header':lambda x:x,'HTTPException':HTTPException,'Response':Response,'json':json,'secrets':secrets,'time':time,'urllib':urllib,'db':self.db,'get_authenticated_user_from_header':authenticate,'decode_jwt_token':lambda t:{'session_id':'as_1'},'check_staff_identity':check_staff_identity,'validate_redirect_uri':lambda u:False}
        node=next(n for n in ast.parse((ROOT/'server/ai_service/face_service.py').read_text(encoding='utf-8')).body if isinstance(n,ast.FunctionDef) and n.name=='oauth_authorize')
        node.decorator_list=[]
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual oauth_authorize>','exec'),scope)
        self.authorize=scope['oauth_authorize']
    def call(self,**kwargs):
        return self.authorize(client_id='client',redirect_uri='http://localhost:5176',requested_role='doctor',**kwargs)
    def test_role_click_cannot_issue_demo_code(self):
        result=self.call();self.assertEqual(result['action'],'AUTHENTICATE');self.assertFalse(self.db.oauth_authorization_codes.rows)
    def test_session_id_without_final_token_denied(self):
        with self.assertRaises(HTTPException):self.call(auth_session_id='vs_1')
    def test_verified_personal_identity_issues_code(self):
        result=self.call(auth_session_id='vs_1',authorization='Bearer final-token')
        self.assertIn('code=',result['redirect_url']);doc=self.db.oauth_authorization_codes.rows[0]
        self.assertEqual(doc['email'],'doctor@gmail.com');self.assertEqual(doc['auth_session_id'],'as_1');self.assertEqual(doc['risk_score'],21)
    def test_another_session_id_denied(self):
        with self.assertRaises(HTTPException):self.call(auth_session_id='other',authorization='Bearer final-token')
    def test_cross_hospital_user_denied(self):
        self.user['organization_id']='other'
        with self.assertRaises(HTTPException):self.call(auth_session_id='vs_1',authorization='Bearer final-token')
    def test_wrong_role_denied(self):
        self.user['role']='NURSE'
        with self.assertRaises(HTTPException):self.call(auth_session_id='vs_1',authorization='Bearer final-token')
    def test_blocked_risk_cannot_issue_code(self):
        self.session['risk_status']='BLOCK'
        result=self.call(auth_session_id='vs_1',authorization='Bearer final-token');self.assertEqual(result.status_code,403);self.assertFalse(self.db.oauth_authorization_codes.rows)

if __name__=='__main__':unittest.main()
