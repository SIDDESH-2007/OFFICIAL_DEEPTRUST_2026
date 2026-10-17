import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import unittest
import re
import hashlib

ROOT = Path(__file__).resolve().parents[1]

class HTTPException(Exception):
    def __init__(self, status_code, detail):
        self.status_code, self.detail = status_code, detail

class Collection:
    def __init__(self): self.record = None
    def find_one(self, query): return self.record
    def insert_one(self, doc):
        self.record = dict(doc)
        return SimpleNamespace(inserted_id='test-user')
    def update_one(self, query, update, **kwargs):
        self.record = dict(self.record or {}, **update['$set'])

class DeliveryTests(unittest.TestCase):
    def setUp(self):
        tree = ast.parse((ROOT / 'server/ai_service/face_service.py').read_text(encoding='utf-8'))
        funcs = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in {'register_admin_account', 'resend_email_code'}:
                node.decorator_list = []
                node.args.args[0].annotation = None
                funcs.append(node)
        self.db = SimpleNamespace(**{name: Collection() for name in ['users', 'deeptrust_admins', 'healthcare_admins', 'email_verifications']})
        self.send = Mock(return_value=(True, 'Sent'))
        self.env = dict(db=self.db, re=re, time=SimpleNamespace(time=lambda: 1000),
            bcrypt=SimpleNamespace(hashpw=lambda *_: b'hash', gensalt=lambda *_: b'salt'),
            DuplicateKeyError=type('DuplicateKeyError', (Exception,), {}), HTTPException=HTTPException,
            log_audit_event=lambda *a, **k: None, generate_secure_otp=lambda: '123456',
            hash_otp=lambda s: hashlib.sha256(s.encode()).hexdigest(),
            send_real_email_otp=self.send, is_email_configured=lambda: True,
            mask_email_address=lambda _: 'masked')
        exec(compile(ast.Module(body=funcs, type_ignores=[]), '<real routes>', 'exec'), self.env)
        self.req = SimpleNamespace(full_name='Test User', email='test@example.com', password='password123',
            confirm_password='password123', role=None, organization_id=None)

    def register(self): return self.env['register_admin_account'](self.req)
    def resend(self): return self.env['resend_email_code'](self.req)

    def test_registration_sends_and_only_stores_hash(self):
        result = self.register()
        self.send.assert_called_once_with('test@example.com', '123456')
        self.assertTrue(result['email_sent'])
        self.assertNotIn('123456', repr(self.db.email_verifications.record))
        self.assertEqual(self.db.email_verifications.record['last_sent_at'], 1000)
        self.assertFalse(self.db.users.record['email_verified'])

    def test_failed_registration_preserves_pending_account(self):
        self.send.return_value = (False, 'Email service is not configured.')
        result = self.register()
        self.assertFalse(result['email_sent'])
        self.assertIn('not sent', result['message'])
        self.assertEqual(self.db.users.record['status'], 'PENDING_EMAIL_VERIFICATION')
        self.assertNotIn('last_sent_at', self.db.email_verifications.record)

    def test_old_unsent_record_does_not_block_resend(self):
        self.db.email_verifications.record = {'created_at': 999, 'status': 'PENDING'}
        self.assertTrue(self.resend()['email_sent'])

    def test_successful_send_enforces_cooldown(self):
        self.register()
        with self.assertRaises(HTTPException) as caught: self.resend()
        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(self.send.call_count, 1)

    def test_resend_failure_is_not_success_and_is_rate_limited(self):
        self.send.return_value = (False, 'Delivery failed')
        with self.assertRaises(HTTPException) as caught: self.resend()
        self.assertEqual(caught.exception.status_code, 500)
        self.assertEqual(self.db.email_verifications.record['delivery_status'], 'FAILED')
        with self.assertRaises(HTTPException) as caught: self.resend()
        self.assertEqual(caught.exception.status_code, 429)

    def test_not_configured_never_claims_success(self):
        self.env['is_email_configured'] = lambda: False
        self.assertFalse(self.resend()['success'])
        self.send.assert_not_called()

if __name__ == '__main__': unittest.main()
