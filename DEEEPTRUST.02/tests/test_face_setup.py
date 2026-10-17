"""Offline tests: no production app imports, MongoDB writes or biometric capture."""
import copy
from pathlib import Path
import sys
import time
import unittest
from types import SimpleNamespace
from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError
import pyotp
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server/ai_service'))
from face_setup import FaceSetup, fingerprint

def matches(doc,query):
    for key,value in query.items():
        if key=='$or':
            if not any(matches(doc,q) for q in value):return False
        elif isinstance(value,dict):
            if '$exists' in value and (key in doc)!=value['$exists']:return False
            if '$lte' in value and (key not in doc or doc[key]>value['$lte']):return False
        elif doc.get(key)!=value:return False
    return True

class Collection:
    def __init__(self,*docs):self.docs=list(docs)
    def find_one(self,q):return next((copy.deepcopy(d) for d in self.docs if matches(d,q)),None)
    def update_one(self,q,u):
        d=next((d for d in self.docs if matches(d,q)),None)
        if d is None:return SimpleNamespace(matched_count=0)
        d.update(copy.deepcopy(u.get('$set',{})))
        for k,v in u.get('$inc',{}).items():d[k]=d.get(k,0)+v
        for k,v in u.get('$push',{}).items():d.setdefault(k,[]).append(copy.deepcopy(v))
        for k in u.get('$unset',{}):d.pop(k,None)
        return SimpleNamespace(matched_count=1)
    def insert_one(self,d):
        if self.find_one({'_id':d['_id']}):raise DuplicateKeyError('duplicate')
        self.docs.append(copy.deepcopy(d))

class SetupTests(unittest.TestCase):
    def setUp(self):
        self.secret=pyotp.random_base32()
        self.user={'_id':'alice','email':'admin@example.test','biometric_setup_allowed':True,'mfa_secret':self.secret}
        self.session={'session_id':'s','user_id':'alice','email':self.user['email'],'credential_status':'VERIFIED','expires_at':time.time()+500}
        self.original={'_id':'face1','user_id':'alice','status':'ACTIVE','embedding':[1.0]*128,'updated_at':1}
        self.db=SimpleNamespace(users=Collection(self.user),verification_sessions=Collection(self.session),face_profiles=Collection(self.original),
            mfa_profiles=Collection(),biometric_setup_totp_uses=Collection())
        self.audit=[]
        self.ns={'db':self.db,'decode_jwt_token':lambda t:{'token_type':'VERIFICATION','session_id':'s','sub':'alice'} if t=='valid' else None,
            'require_face_session':lambda sid:self.db.verification_sessions.find_one({'session_id':sid}),
            'face_profile_query':lambda s:{'user_id':s['user_id']},'normalized_face_template':lambda p:p['embedding'],
            'FACE_MATCH_REFERENCES':{'s':{}},'LIVENESS_SESSIONS':{'s':{}},'log_audit_event':lambda *a,**k:self.audit.append(a)}
        self.setup=FaceSetup(self.ns)
    def authorize(self):return self.setup.authorize({'session_id':'s','code':pyotp.TOTP(self.secret).now()},'Bearer valid')
    def staged(self):
        self.authorize()
        s=self.db.verification_sessions.find_one({'session_id':'s'})
        self.setup.stage(s,{'user_id':'alice','status':'ACTIVE','embedding':[2.0]*128,'updated_at':2})
        return self.db.verification_sessions.find_one({'session_id':'s'})
    def ready(self):
        s=self.staged()
        s.update({k:'VERIFIED' for k in ('credential_status','face_status','liveness_status','voice_status','mfa_status')})
        s['risk_status']='ALLOW'
        return s
    def test_no_token_cannot_authorize(self):
        with self.assertRaises(HTTPException):self.setup.authorize({'session_id':'s','code':'123456'},None)
        self.assertEqual(self.db.face_profiles.find_one({'_id':'face1'}),self.original)
    def test_ungranted_account_cannot_setup(self):
        self.user['biometric_setup_allowed']=False
        with self.assertRaises(HTTPException):self.authorize()
    def test_wrong_mfa_does_not_change_profile(self):
        bad=next(x for x in ('000000','111111','222222') if x!=pyotp.TOTP(self.secret).now())
        with self.assertRaises(HTTPException):self.setup.authorize({'session_id':'s','code':bad},'Bearer valid')
        self.assertEqual(self.db.face_profiles.find_one({'_id':'face1'}),self.original)
    def test_authorization_only_stages_setup_does_not_complete_factors(self):
        self.authorize()
        s=self.db.verification_sessions.find_one({'session_id':'s'})
        self.assertTrue(s['face_setup_authorized'])
        self.assertEqual(s['mfa_status'],'PENDING')
        self.assertEqual(self.db.face_profiles.find_one({'_id':'face1'}),self.original)
        self.assertNotIn('s',self.ns['FACE_MATCH_REFERENCES'])
    def test_staged_face_does_not_overwrite_saved_face(self):
        s=self.staged()
        self.assertIn('face_pending_template',s)
        self.assertEqual(self.db.face_profiles.find_one({'_id':'face1'}),self.original)
    def test_incomplete_face_voice_mfa_each_block_commit(self):
        for key in ('face_status','liveness_status','voice_status','mfa_status'):
            self.setUp();s=self.ready();s[key]='PENDING'
            with self.assertRaises(HTTPException):self.setup.commit(s,self.user)
            self.assertEqual(self.db.face_profiles.find_one({'_id':'face1'}),self.original)
    def test_other_account_template_is_rejected(self):
        s=self.ready();s['face_pending_template']['user_id']='bob'
        with self.assertRaises(HTTPException):self.setup.commit(s,self.user)
    def test_blocked_risk_rejects_commit(self):
        s=self.ready();s['risk_status']='BLOCK'
        with self.assertRaises(HTTPException):self.setup.commit(s,self.user)
    def test_changed_original_profile_is_preserved(self):
        s=self.ready();self.original['embedding']=[3.0]*128
        with self.assertRaises(HTTPException):self.setup.commit(s,self.user)
        self.assertEqual(self.db.face_profiles.find_one({'_id':'face1'})['embedding'],[3.0]*128)
    def test_expired_setup_cannot_commit(self):
        s=self.ready();s['expires_at']=0
        with self.assertRaises(HTTPException):self.setup.commit(s,self.user)
    def test_success_archives_old_face_and_closes_one_time_setup(self):
        s=self.ready();self.setup.commit(s,self.user)
        current=self.db.face_profiles.find_one({'_id':'face1'})
        self.assertEqual(current['embedding'],[2.0]*128)
        self.assertEqual(current['setup_history'][0]['embedding'],[1.0]*128)
        self.assertFalse(self.db.users.find_one({'_id':'alice'})['biometric_setup_allowed'])
        self.assertNotIn('face_pending_template',self.db.verification_sessions.find_one({'session_id':'s'}))
        with self.assertRaises(HTTPException):self.authorize()

if __name__=='__main__':unittest.main()
