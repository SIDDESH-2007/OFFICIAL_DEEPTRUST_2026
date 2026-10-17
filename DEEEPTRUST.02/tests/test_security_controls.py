import sys
import copy
import tempfile
import unittest
import ast
import time
from typing import Optional, Dict, Any
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server/ai_service'))
from security_controls import AuditChain, enforce_session, route_permission, register_security_controls
from monthly_metrics import aggregate_month, month_bounds

def value(row, key):
    for part in key.split('.'):
        row=row.get(part) if isinstance(row,dict) else None
    return row

def matches(row, query):
    for key, expected in query.items():
        if key=='$or':
            if not any(matches(row,q) for q in expected):return False
            continue
        actual=value(row,key)
        if isinstance(expected,dict):
            for op,wanted in expected.items():
                if op=='$in' and actual not in wanted:return False
                if op=='$ne' and actual==wanted:return False
                if op=='$gte' and (actual is None or actual<wanted):return False
                if op=='$lt' and (actual is None or actual>=wanted):return False
        elif actual!=expected:return False
    return True

class Cursor(list):
    def sort(self,key,direction):return Cursor(sorted(self,key=lambda d:value(d,key) or 0,reverse=direction<0))
class Collection:
    def __init__(self,rows=()):self.rows=copy.deepcopy(list(rows))
    def find(self,query=None):return Cursor(copy.deepcopy([r for r in self.rows if matches(r,query or {})]))
    def find_one(self,q):return next(iter(self.find(q)),None)
    def count_documents(self,q):return len(self.find(q))
    def insert_one(self,row):self.rows.append(copy.deepcopy(row))
    def update_one(self,q,changes):
        for row in self.rows:
            if matches(row,q):row.update(changes['$set']);return SimpleNamespace(modified_count=1)
        return SimpleNamespace(modified_count=0)

class SessionTests(unittest.TestCase):
    def setUp(self):
        self.db=SimpleNamespace(auth_sessions=Collection([{'_id':'s','session_id':'s','user_id':'u','email':'u@test','status':'ACTIVE','created_at':100,'last_activity_at':100,'expires_at':10000,'organization_id':'a'}]),security_policies=Collection())
        self.token={'session_id':'s','sub':'u','email':'u@test'}
    def test_active(self):self.assertEqual(enforce_session(self.db,self.token,101)['_id'],'s')
    def test_missing_database(self):
        with self.assertRaises(HTTPException) as error:enforce_session(None,self.token,101)
        self.assertEqual(error.exception.status_code,503)
    def test_missing_session(self):
        with self.assertRaises(HTTPException):enforce_session(self.db,{**self.token,'session_id':'missing'},101)
    def test_missing_token_session(self):
        with self.assertRaises(HTTPException):enforce_session(self.db,{'sub':'u'},101)
    def test_wrong_owner(self):
        with self.assertRaises(HTTPException):enforce_session(self.db,{**self.token,'sub':'other'},101)
    def test_wrong_email(self):
        with self.assertRaises(HTTPException):enforce_session(self.db,{**self.token,'email':'other'},101)
    def test_revoked(self):
        self.db.auth_sessions.rows[0]['revoked']=True
        with self.assertRaises(HTTPException):enforce_session(self.db,self.token,101)
    def test_step_up(self):
        self.db.auth_sessions.rows[0]['status']='STEP_UP_REQUIRED'
        with self.assertRaises(HTTPException):enforce_session(self.db,self.token,101)
    def test_idle_exact_boundary(self):
        with self.assertRaises(HTTPException):enforce_session(self.db,self.token,1900)
        self.assertEqual(self.db.auth_sessions.rows[0]['status'],'EXPIRED')
        self.assertEqual(self.db.auth_sessions.rows[0]['ended_at'],1900)
    def test_polling_does_not_extend(self):
        enforce_session(self.db,self.token,1899)
        self.assertEqual(self.db.auth_sessions.rows[0]['last_activity_at'],100)
    def test_policy_timeout(self):
        self.db.security_policies.rows=[{'organization_id':'a','session_idle_timeout':60}]
        with self.assertRaises(HTTPException):enforce_session(self.db,self.token,160)
    def test_absolute_timeout_despite_activity(self):
        self.db.security_policies.rows=[{'organization_id':'a','session_absolute_timeout':90}]
        self.db.auth_sessions.rows[0]['last_activity_at']=189
        with self.assertRaises(HTTPException):enforce_session(self.db,self.token,190)

class RoleTests(unittest.TestCase):
    def test_staff_security_denied(self):
        with self.assertRaises(HTTPException):route_permission('/api/v1/devices/d/trust','POST',{'role':'DOCTOR','organization_id':'a'})
    def test_hospital_platform_denied(self):
        with self.assertRaises(HTTPException):route_permission('/api/v1/admin/accounts','GET',{'role':'HOSPITAL_ADMIN','organization_id':'a'})
    def test_hospital_session_allowed(self):route_permission('/api/v1/admin/sessions/s/revoke','POST',{'role':'HOSPITAL_ADMIN','organization_id':'a'})
    def test_auditor_write_denied(self):
        with self.assertRaises(HTTPException):route_permission('/api/v1/devices/d/revoke','POST',{'role':'AUDITOR','organization_id':'a'})
    def test_auditor_read_allowed(self):route_permission('/api/v1/audit-logs','GET',{'role':'AUDITOR','organization_id':'a'})
    def test_staff_own_profile_allowed(self):route_permission('/api/v1/profile','GET',{'role':'DOCTOR'})
    def test_middleware_denies_before_endpoint(self):
        app=FastAPI();calls=[]
        @app.get('/api/v1/admin/accounts')
        def endpoint():calls.append(1);return {}
        register_security_controls(app,{'get_authenticated_user_from_header':lambda header:{'role':'HOSPITAL_ADMIN','organization_id':'a'}},None)
        self.assertEqual(TestClient(app).get('/api/v1/admin/accounts').status_code,403)
        self.assertEqual(calls,[])
    def test_cross_org_query(self):
        app=FastAPI()
        @app.get('/api/v1/devices')
        def endpoint():return {}
        register_security_controls(app,{'get_authenticated_user_from_header':lambda header:{'role':'HOSPITAL_ADMIN','organization_id':'a'}},None)
        self.assertEqual(TestClient(app).get('/api/v1/devices?organization_id=b').status_code,403)

class ActualAuthTests(unittest.TestCase):
    def setUp(self):
        now=time.time()
        self.db=SimpleNamespace(auth_sessions=Collection([{'_id':'s','session_id':'s','user_id':'u','email':'u@test','status':'ACTIVE','created_at':now,'last_activity_at':now,'expires_at':now+500,'organization_id':'a'}]),
            security_policies=Collection(),users=Collection([{'_id':'u','email':'u@test','email_normalized':'u@test','role':'HOSPITAL_ADMIN','organization_id':'a','status':'ACTIVE'}]),deeptrust_admins=Collection(),healthcare_admins=Collection())
        self.token={'token_type':'ACCESS','session_id':'s','sub':'u','email':'u@test','role':'DEEPTRUST_OWNER'}
        tree=ast.parse((ROOT/'server/ai_service/face_service.py').read_text(encoding='utf-8'))
        node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='get_authenticated_user_from_header')
        node.decorator_list=[]
        self.env={'db':self.db,'HTTPException':HTTPException,'Header':lambda _:None,'Optional':Optional,'Dict':Dict,'Any':Any,
            'enforce_session':enforce_session,'PLATFORM_ROLES':{'DEEPTRUST_OWNER','DEEPTRUST_ADMIN','OWNER','ADMIN'},'log_audit_event':lambda *a,**kw:None,
            'decode_jwt_token':lambda token:self.token}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<real access dependency>','exec'),self.env)
    def auth(self):return self.env['get_authenticated_user_from_header']('Bearer test')
    def test_role_is_database_authoritative(self):self.assertEqual(self.auth()['role'],'HOSPITAL_ADMIN')
    def test_missing_database_role_not_taken_from_token(self):
        self.db.users.rows[0].pop('role')
        with self.assertRaises(HTTPException):self.auth()
    def test_verification_token_denied(self):
        self.token['token_type']='VERIFICATION'
        with self.assertRaises(HTTPException):self.auth()
    def test_unknown_demo_account_no_fallback(self):
        self.db.users.rows=[]
        self.token['email']='owner@deeptrust.demo'
        self.db.auth_sessions.rows[0]['email']='owner@deeptrust.demo'
        with self.assertRaises(HTTPException):self.auth()
    def test_recreated_account_cannot_reuse_old_session(self):
        self.db.users.rows[0]['_id']='replacement-user'
        with self.assertRaises(HTTPException):self.auth()
    def test_moved_account_cannot_reuse_old_tenant_session(self):
        self.db.users.rows[0]['organization_id']='b'
        with self.assertRaises(HTTPException):self.auth()
    def test_revoked_session_real_gate(self):
        self.db.auth_sessions.rows[0]['revoked']=True
        with self.assertRaises(HTTPException):self.auth()
    def test_account_disabled(self):
        self.db.users.rows[0]['status']='DISABLED'
        with self.assertRaises(HTTPException):self.auth()

class AuditTests(unittest.TestCase):
    def setUp(self):
        scratch=Path(__file__).resolve().parent/'audit_test_temp'
        scratch.mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=scratch);self.addCleanup(self.temp.cleanup)
        self.chain=AuditChain('test-key',Path(self.temp.name)/'anchor.json');self.logs=Collection([{'_id':'legacy','action':'old'}])
        self.chain.append(self.logs,{'action':'login','details':{'resource':'dashboard'}})
        self.chain.append(self.logs,{'action':'logout'})
    def test_verify(self):
        result=self.chain.verify(self.logs)
        self.assertEqual(result['status'],'VERIFIED');self.assertEqual(result['signed_records'],2);self.assertEqual(result['legacy_unsigned_records'],1)
    def test_edit_detected(self):
        self.logs.rows[1]['details']['resource']='changed'
        self.assertEqual(self.chain.verify(self.logs)['status'],'TAMPER_DETECTED')
    def test_middle_deletion(self):
        del self.logs.rows[1]
        self.assertEqual(self.chain.verify(self.logs)['status'],'TAMPER_DETECTED')
    def test_tail_deletion(self):
        self.logs.rows.pop()
        self.assertEqual(self.chain.verify(self.logs)['status'],'TAMPER_DETECTED')
    def test_entire_chain_deletion(self):
        self.logs.rows=[]
        self.assertEqual(self.chain.verify(self.logs)['status'],'TAMPER_DETECTED')
    def test_anchor_deleted(self):
        self.chain.path.unlink()
        self.assertEqual(self.chain.verify(self.logs)['status'],'TAMPER_DETECTED')
    def test_anchor_changed(self):
        self.chain.path.write_text('{"sequence":0,"hash":"GENESIS","signature":"fake"}')
        self.assertEqual(self.chain.verify(self.logs)['status'],'TAMPER_DETECTED')
    def test_resume_same_key(self):
        restarted=AuditChain('test-key',self.chain.path)
        restarted.append(self.logs,{'action':'after restart'})
        self.assertEqual(restarted.verify(self.logs)['signed_records'],3)
    def test_wrong_key(self):self.assertEqual(AuditChain('wrong-key',self.chain.path).verify(self.logs)['status'],'TAMPER_DETECTED')
    def test_append_after_tail_deletion_denied(self):
        self.logs.rows.pop()
        with self.assertRaises(ValueError):self.chain.append(self.logs,{'action':'new'})

class ReportTests(unittest.TestCase):
    def setUp(self):
        ts=datetime(2026,9,10,tzinfo=timezone.utc).timestamp()
        def row(id,event,sid=None,**extra):return {'_id':id,'event_type':event,'session_id':sid,'created_at':ts,'organization_id':'a',**extra}
        self.db=SimpleNamespace(audit_logs=Collection([row('1','LOGIN_ATTEMPT','v'),row('2','FINAL_ACCESS_GRANTED','s'),row('3','ACCESS_ALLOWED','s'),row('4','FACE_MISMATCH','v'),row('5','FACE_VERIFIED','v'),row('6','VOICE_VERIFIED','v'),row('7','VOICE_VERIFICATION_FAILED_ATTEMPT_1','v'),row('8','MFA_VERIFIED','v'),row('9','LOGIN_ATTEMPT','demo',is_demo=True)]),
            auth_sessions=Collection([{'_id':'s','verification_session_id':'v'}]),
            security_events=Collection([{'_id':'e','event_id':'e','created_at':ts,'decision':'BLOCK','severity':'HIGH','organization_id':'a'}]),
            organizations=Collection([{'_id':'a','name':'Hospital A'}]))
    def test_no_login_double_count(self):
        result=aggregate_month(self.db,2026,9)
        self.assertEqual(result['total_login_attempts'],1);self.assertEqual(result['successful_authentications'],1)
    def test_demo_excluded(self):self.assertEqual(aggregate_month(self.db,2026,9)['demo_records_excluded'],1)
    def test_factor_aliases_and_retries(self):
        result=aggregate_month(self.db,2026,9)
        self.assertEqual(result['face_verification_failures'],1);self.assertEqual(result['voice_verification_failures'],1);self.assertEqual(result['mfa_success'],1);self.assertEqual(result['face_attempts'],1)
    def test_no_block_double_count(self):
        self.db.audit_logs.rows.append({**self.db.audit_logs.rows[0],'_id':'blocked','event_type':'ACCESS_BLOCKED'})
        self.assertEqual(aggregate_month(self.db,2026,9)['blocked_attempts'],1)
    def test_empty_month(self):self.assertEqual(aggregate_month(self.db,2026,10)['total_login_attempts'],0)
    def test_invalid_month(self):
        with self.assertRaises(HTTPException):month_bounds(2026,13)
    def test_database_unavailable(self):
        with self.assertRaises(HTTPException):aggregate_month(None,2026,9)
    def test_next_month_boundary(self):
        self.db.audit_logs.rows.append({'_id':'boundary','event_type':'LOGIN_ATTEMPT','created_at':datetime(2026,10,1,tzinfo=timezone.utc).timestamp()})
        self.assertEqual(aggregate_month(self.db,2026,9)['total_login_attempts'],1)

if __name__=='__main__':unittest.main(verbosity=2)
