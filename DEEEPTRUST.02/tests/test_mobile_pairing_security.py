import sys,time,unittest,ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from fastapi import HTTPException
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server/ai_service'))
from mobile_pairing_security import authorize_pairing_identity,verify_pairing_totp,consume_pairing
class PairingTests(unittest.TestCase):
    def setUp(self):
        self.user={'_id':'u','email':'u@test','role':'DEEPTRUST_ADMIN','status':'ACTIVE'}
        self.pair={'_id':'p','status':'CREDENTIALS_VERIFIED','verified_admin_id':'u','verified_admin_email':'u@test'}
    def test_authorized_identity(self):authorize_pairing_identity(self.pair,self.user)
    def test_unverified_wrong_identity_role_and_disabled(self):
        for pair,user in [({**self.pair,'status':'PENDING'},self.user),({**self.pair,'verified_admin_id':'x'},self.user),({**self.pair,'verified_admin_email':'x@test'},self.user),(self.pair,{**self.user,'role':'HOSPITAL_ADMIN'}),(self.pair,{**self.user,'status':'DISABLED'})]:
            with self.assertRaises(HTTPException):authorize_pairing_identity(pair,user)
    def test_no_secret_cannot_use_default(self):
        with self.assertRaises(HTTPException) as e:verify_pairing_totp(None,'123456')
        self.assertEqual(e.exception.status_code,403)
    def test_fixed_code_has_no_bypass(self):
        with patch('mobile_pairing_security.pyotp.TOTP') as totp:
            totp.return_value.verify.return_value=False
            with self.assertRaises(HTTPException):verify_pairing_totp('secret','123456')
            totp.return_value.verify.assert_called_once_with('123456',valid_window=1)
    def test_current_real_code_accepted(self):
        import pyotp
        secret=pyotp.random_base32();verify_pairing_totp(secret,pyotp.TOTP(secret).now())
    def test_bad_code_and_broken_secret_fail_closed(self):
        for secret,code in [('x','abc'),('%%%','654321')]:
            with self.assertRaises(HTTPException):verify_pairing_totp(secret,code)
    def test_atomic_consumption_allows_only_one_winner(self):
        class Collection:
            used=False
            def update_one(inner,q,u):
                self.assertEqual(q['status'],'CREDENTIALS_VERIFIED');self.assertEqual(q['verified_admin_id'],'u');self.assertEqual(q['expires_at'],{'$gt':100})
                won=not inner.used;inner.used=True
                return SimpleNamespace(modified_count=int(won))
        c=Collection();consume_pairing(c,self.pair,self.user,100)
        with self.assertRaises(HTTPException) as e:consume_pairing(c,self.pair,self.user,100)
        self.assertEqual(e.exception.status_code,409)
    def test_endpoint_uses_guards_before_session_creation(self):
        source=(ROOT/'server/ai_service/face_service.py').read_text(encoding='utf-8')
        tree=ast.parse(source);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='verify_mobile_admin_totp')
        body=ast.get_source_segment(source,node)
        self.assertNotIn('DEMO_ADMIN_TOTP_SECRET',body);self.assertNotIn('"123456"',body)
        self.assertLess(body.index('authorize_pairing_identity('),body.index('verify_pairing_totp('))
        self.assertLess(body.index('consume_pairing('),body.index('db.mobile_sessions.insert_one('))
if __name__=='__main__':unittest.main()
