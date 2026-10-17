import copy
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
import numpy as np
import pyotp
from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server/ai_service'))
from voice_engine import VoiceError, quality, normal_vector, phrase_matches, speaker_matches, MODEL_ID
from voice_security import VoiceSecurity, ADMIN_VOICE_COMMAND

def matches(row,query):
    for key,want in query.items():
        if key=='$or':
            if not any(matches(row,q) for q in want):return False
            continue
        actual=row.get(key)
        if isinstance(want,dict):
            for op,value in want.items():
                if op=='$gt' and (actual is None or actual<=value):return False
                if op=='$lte' and (actual is None or actual>value):return False
                if op=='$exists' and (key in row)!=value:return False
                if op=='$nin' and actual in value:return False
                if op=='$ne' and actual==value:return False
        elif actual!=want:return False
    return True

class Collection:
    def __init__(self,rows=()):self.rows=copy.deepcopy(list(rows))
    def find_one(self,q):return next((copy.deepcopy(r) for r in self.rows if matches(r,q)),None)
    def update_one(self,q,changes):
        for row in self.rows:
            if matches(row,q):
                for key,value in changes.get('$set',{}).items():row[key]=copy.deepcopy(value)
                for key,value in changes.get('$inc',{}).items():row[key]=row.get(key,0)+value
                for key in changes.get('$unset',{}):row.pop(key,None)
                return SimpleNamespace(modified_count=1)
        return SimpleNamespace(modified_count=0)
    def find_one_and_update(self,q,changes):
        old=self.find_one(q)
        if old:self.update_one(q,changes)
        return old
    def replace_one(self,q,replacement):
        for index,row in enumerate(self.rows):
            if matches(row,q):
                self.rows[index]=copy.deepcopy(replacement)
                return SimpleNamespace(modified_count=1)
        return SimpleNamespace(modified_count=0)
    def insert_one(self,row):
        if self.find_one({'_id':row['_id']}):raise DuplicateKeyError('duplicate')
        self.rows.append(copy.deepcopy(row))

VECTOR=np.zeros(256,dtype=np.float32);VECTOR[0]=1
class Engine:
    error=None
    vector=VECTOR
    def decode(self,audio):return np.zeros(64000),f'raw-{audio}',f'pcm-{audio}'
    def analyze(self,wave,phrase):
        if self.error:raise self.error
        return self.vector,np.asarray([self.vector]*3),{'snr_db':25,'replay_logit':4}

class GateTests(unittest.TestCase):
    def setUp(self):
        self.session={'session_id':'session','user_id':'user','email':'u@test','expires_at':time.time()+600,
            'credential_status':'VERIFIED','face_status':'VERIFIED','liveness_status':'VERIFIED','voice_status':'PENDING'}
        self.secret=pyotp.random_base32()
        self.db=SimpleNamespace(verification_sessions=Collection([self.session]),users=Collection([{'_id':'user','email':'u@test','mfa_secret':self.secret}]),
            voice_templates_v2=Collection(),voice_profiles=Collection([{'_id':'legacy','user_id':'user','spectral_baseline':[.85,.92,.78,.88]}]),voice_audio_fingerprints=Collection())
        self.payload={'token_type':'VERIFICATION','session_id':'session','sub':'user'}
        self.events=[];self.engine=Engine()
        self.gate=VoiceSecurity({'db':self.db,'decode_jwt_token':lambda _:self.payload,'log_audit_event':lambda *a,**kw:self.events.append(a)},self.engine)
        self.request={'session_id':'session','user_id':'user'}
    def challenge(self):return self.gate.challenge(self.request,'Bearer token')
    def submit(self,enroll=False,audio='new',mfa=None):
        c=self.challenge()
        return self.gate.submit({**self.request,'challenge_id':c['challenge_id'],'audio_data':audio,'mfa_code':mfa or pyotp.TOTP(self.secret).now()},'Bearer token',enroll)
    def enroll_profile(self):self.db.voice_templates_v2.rows=[{'_id':'user','model_id':MODEL_ID,'enrolled':True,'embedding':VECTOR.tolist()}]
    def assertDenied(self,call,status=None):
        with self.assertRaises(HTTPException) as caught:call()
        if status:self.assertEqual(caught.exception.status_code,status)
        return caught.exception
    def test_missing_token(self):self.assertDenied(lambda:self.gate.challenge(self.request,None),401)
    def test_access_token_cannot_authenticate_voice(self):
        self.payload['token_type']='ACCESS';self.assertDenied(self.challenge,401)
    def test_wrong_account(self):
        self.payload['sub']='other';self.assertDenied(self.challenge,403)
    def test_client_cannot_choose_account(self):
        self.request['user_id']='other';self.assertDenied(self.challenge,403)
    def test_face_required(self):
        self.db.verification_sessions.rows[0]['face_status']='PENDING';self.assertDenied(self.challenge,403)
    def test_expired_session(self):
        self.db.verification_sessions.rows[0]['expires_at']=0;self.assertDenied(self.challenge,403)
    def test_missing_profile_never_passes(self):
        self.assertDenied(lambda:self.submit(),409);self.assertEqual(self.db.voice_templates_v2.rows,[])
    def test_dummy_legacy_preserved(self):
        before=copy.deepcopy(self.db.voice_profiles.rows);self.assertDenied(lambda:self.submit(),409)
        self.assertEqual(self.db.voice_profiles.rows,before)
    def test_enrollment_without_inline_mfa_is_only_temporary(self):
        self.assertEqual(self.submit(True,'a',mfa='wrong')['status'],'ENROLLED')
        self.assertEqual(self.db.voice_templates_v2.rows,[])
    def pending_setup(self):
        self.submit(True,'a',mfa='wrong')
    def test_pending_setup_requires_final_mfa_before_saving(self):
        self.pending_setup()
        self.assertEqual(self.db.voice_templates_v2.rows,[])
        self.assertDenied(lambda:self.gate.commit_enrollment(self.session,self.db.users.rows[0]),403)
        self.db.verification_sessions.rows[0].update(mfa_status='VERIFIED',risk_status='ALLOW')
        self.gate.commit_enrollment(self.session,self.db.users.rows[0])
        self.assertEqual(len(self.db.voice_templates_v2.rows),1)
        self.assertNotIn('voice_pending_template',self.db.verification_sessions.rows[0])
    def test_pending_setup_cannot_commit_after_voice_recovery(self):
        self.pending_setup();self.db.verification_sessions.rows[0].update(voice_status='FAILED_RECOVERY_USED',mfa_status='VERIFIED',risk_status='ALLOW')
        self.assertDenied(lambda:self.gate.commit_enrollment(self.session,self.db.users.rows[0]),403)
    def test_pending_setup_cannot_overwrite_existing_voice(self):
        self.pending_setup();self.enroll_profile()
        before=copy.deepcopy(self.db.voice_templates_v2.rows)
        self.db.verification_sessions.rows[0].update(mfa_status='VERIFIED',risk_status='ALLOW')
        self.assertDenied(lambda:self.gate.commit_enrollment(self.session,self.db.users.rows[0]),409)
        self.assertEqual(before,self.db.voice_templates_v2.rows)
    def test_pending_setup_commit_checks_risk_expiry_and_account(self):
        for mutation in [{'risk_status':'BLOCK'},{'expires_at':0},{'user_id':'another'},{'revoked':True}]:
            self.setUp();self.pending_setup()
            self.db.verification_sessions.rows[0].update(mfa_status='VERIFIED',risk_status='ALLOW',**mutation) if 'risk_status' not in mutation else self.db.verification_sessions.rows[0].update(mfa_status='VERIFIED',**mutation)
            self.assertDenied(lambda:self.gate.commit_enrollment(self.session,self.db.users.rows[0]),403)

    def test_one_sample_enrollment_pending_until_final_mfa(self):
        before=copy.deepcopy(self.db.voice_profiles.rows)
        challenge=self.challenge()
        self.assertEqual(challenge['challenge_phrase'],ADMIN_VOICE_COMMAND)
        self.assertEqual(challenge['samples_required'],1)
        response=self.gate.submit({**self.request,'challenge_id':challenge['challenge_id'],'audio_data':'a'},'Bearer token',True)
        self.assertEqual(response['status'],'ENROLLED')
        self.assertFalse(response['matched'])
        self.assertEqual(self.db.verification_sessions.rows[0]['voice_status'],'VERIFIED')
        self.assertEqual(self.db.voice_profiles.rows,before)
        self.assertEqual(self.db.voice_templates_v2.rows,[])
    def test_verification_does_not_modify_profile(self):
        self.enroll_profile();before=copy.deepcopy(self.db.voice_templates_v2.rows)
        self.submit();self.assertEqual(before,self.db.voice_templates_v2.rows)
    def test_existing_profile_not_reenrolled(self):
        self.enroll_profile();self.assertDenied(lambda:self.submit(True),409)
    def test_same_audio_rejected_after_failed_phrase(self):
        self.enroll_profile();self.engine.error=VoiceError('PHRASE_MISMATCH','Mismatch')
        self.assertDenied(lambda:self.submit(audio='same'),400);self.engine.error=None
        error=self.assertDenied(lambda:self.submit(audio='same'),400)
        self.assertEqual(error.detail['code'],'AUDIO_REUSED')
    def test_single_use_challenge(self):
        self.enroll_profile();challenge=self.challenge();request={**self.request,'challenge_id':challenge['challenge_id'],'audio_data':'sample'}
        self.engine.error=VoiceError('NO_CLEAR_SPEECH','Retry',True)
        self.assertDenied(lambda:self.gate.submit(request,'Bearer token'),400)
        self.assertDenied(lambda:self.gate.submit(request,'Bearer token'),409)
    def test_expired_challenge(self):
        self.enroll_profile();challenge=self.challenge();self.db.verification_sessions.rows[0]['voice_challenge_expires_at']=0
        self.assertDenied(lambda:self.gate.submit({**self.request,'challenge_id':challenge['challenge_id']},'Bearer token'),409)
    def test_failure_diagnostics_do_not_leak_into_response_or_change_profile(self):
        self.enroll_profile();before=copy.deepcopy(self.db.voice_templates_v2.rows)
        self.engine.error=VoiceError('SPEAKER_MISMATCH','Wrong voice',metrics={'speaker_score':.65,'transcript':'private'})
        error=self.assertDenied(self.submit,400)
        self.assertEqual(self.db.verification_sessions.rows[0]['voice_last_failure_metrics'],{'speaker_score':.65})
        self.assertNotIn('speaker_score',error.detail)
        self.assertEqual(before,self.db.voice_templates_v2.rows)
    def test_misrecognized_command_is_returned_but_not_persisted(self):
        self.enroll_profile()
        self.engine.error=VoiceError('PHRASE_MISMATCH','Read command',metrics={'recognized_command':'Deep trust identity bravo five','snr_db':25})
        error=self.assertDenied(self.submit,400)
        self.assertEqual(error.detail['recognized_command'],'Deep trust identity bravo five')
        self.assertEqual(self.db.verification_sessions.rows[0]['voice_last_failure_metrics'],{'snr_db':25})
        self.assertNotIn('recognized_command',str(self.db.verification_sessions.rows))
    def test_quality_retries_do_not_consume_attempts(self):
        self.enroll_profile();self.engine.error=VoiceError('BACKGROUND_TOO_LOUD','Retry',True)
        error=self.assertDenied(self.submit,400);self.assertEqual(error.detail['attempts'],0)
    def test_unavailable_engine_fails_closed_without_attempt_penalty(self):
        self.enroll_profile();self.engine.error=VoiceError('VOICE_ENGINE_UNAVAILABLE','Unavailable')
        error=self.assertDenied(self.submit,503);self.assertEqual(error.detail['attempts'],0)
    def test_replay_rejected(self):
        self.enroll_profile();self.engine.error=VoiceError('REPLAY_SUSPECTED','Replay')
        error=self.assertDenied(self.submit,400);self.assertEqual(error.detail['code'],'REPLAY_SUSPECTED')
    def test_two_security_failures_require_recovery(self):
        self.enroll_profile();self.engine.error=VoiceError('SPEAKER_MISMATCH','Wrong voice')
        self.assertDenied(lambda:self.submit(audio='a'),400)
        error=self.assertDenied(lambda:self.submit(audio='b'),400);self.assertTrue(error.detail['recovery_required'])
        self.assertDenied(self.challenge,403)
    def test_challenge_blocked_while_processing(self):
        self.db.verification_sessions.rows[0]['voice_processing_until']=time.time()+100
        self.assertDenied(self.challenge,409)
    def test_invalid_duplicate_does_not_clear_processing_lock(self):
        self.enroll_profile();challenge=self.challenge();self.db.verification_sessions.rows[0].update(voice_processing_until=time.time()+100,voice_challenge_consumed=True)
        self.assertDenied(lambda:self.gate.submit({**self.request,'challenge_id':challenge['challenge_id']},'Bearer token'),409)
        self.assertIn('voice_processing_until',self.db.verification_sessions.rows[0])
    def test_completed_enrollment_cannot_replace_pending_voice(self):
        self.submit(True,'a')
        self.assertDenied(lambda:self.submit(True,'b'),409)
        self.assertEqual(self.db.verification_sessions.rows[0]['voice_pending_template']['sample_count'],1)

    def test_revoked_and_finalized_sessions_cannot_request_voice(self):
        for mutation in ({'revoked':True},{'final_decision':'FINALIZED'},{'final_decision':'BLOCK'}):
            self.setUp();self.db.verification_sessions.rows[0].update(mutation)
            self.assertDenied(self.challenge,403)
    def test_disabled_account_cannot_request_voice(self):
        self.db.users.rows[0]['status']='DISABLED'
        self.assertDenied(self.challenge,403)
    def test_revocation_during_inference_cannot_verify(self):
        self.enroll_profile()
        original=self.engine.analyze
        def revoke(*args):
            self.db.verification_sessions.rows[0]['revoked']=True
            return original(*args)
        self.engine.analyze=revoke
        self.assertDenied(self.submit,403)
        self.assertEqual(self.db.verification_sessions.rows[0]['voice_status'],'PENDING')
        self.assertNotIn('voice_processing_until',self.db.verification_sessions.rows[0])
    def test_account_disabled_during_inference_cannot_enroll(self):
        original=self.engine.analyze
        def disable(*args):
            self.db.users.rows[0]['status']='DISABLED'
            return original(*args)
        self.engine.analyze=disable
        self.assertDenied(lambda:self.submit(True),403)
        self.assertNotIn('voice_pending_template',self.db.verification_sessions.rows[0])
    def test_atomic_claim_rejects_revocation_after_context_read(self):
        self.enroll_profile();c=self.challenge()
        original=self.db.verification_sessions.find_one_and_update
        def revoke(query,changes):
            self.db.verification_sessions.rows[0]['revoked']=True
            return original(query,changes)
        self.db.verification_sessions.find_one_and_update=revoke
        self.assertDenied(lambda:self.gate.submit({**self.request,'challenge_id':c['challenge_id'],'audio_data':'race'},'Bearer token'),409)
        self.assertEqual(self.db.voice_audio_fingerprints.rows,[])

class ScopedRepairTests(unittest.TestCase):
    setUp=GateTests.setUp
    enroll_profile=GateTests.enroll_profile
    assertDenied=GateTests.assertDenied
    challenge=GateTests.challenge
    submit=GateTests.submit
    def repair_fixture(self):
        self.enroll_profile()
        self.db.voice_template_archives=Collection()
        self.db.users.rows[0].update(email='siddeshwar220407@gmail.com',voice_repair_request_id='one-time')
        self.db.verification_sessions.rows[0]['email']='siddeshwar220407@gmail.com'
        self.before=copy.deepcopy(self.db.voice_templates_v2.rows)
    def authorize(self):
        self.gate.authorize_repair(self.db.verification_sessions.rows[0],self.db.users.rows[0])
    def test_repair_is_scoped_to_requested_account(self):
        self.repair_fixture();self.db.users.rows[0]['email']='other@example.com'
        self.assertDenied(self.authorize,403)
        self.assertEqual(self.before,self.db.voice_templates_v2.rows)
    def test_repair_requires_pending_request(self):
        self.repair_fixture();self.db.users.rows[0].pop('voice_repair_request_id')
        self.assertDenied(self.authorize,403)
    def test_repair_keeps_old_profile_until_final_mfa_then_archives(self):
        self.repair_fixture();self.authorize()
        self.assertEqual(self.challenge()['purpose'],'ENROLL')
        self.assertEqual(self.submit(True)['status'],'ENROLLED')
        self.assertEqual(self.before,self.db.voice_templates_v2.rows)
        self.assertDenied(lambda:self.gate.commit_enrollment(self.session,self.db.users.rows[0]),403)
        self.db.verification_sessions.rows[0].update(mfa_status='VERIFIED',risk_status='ALLOW')
        self.gate.commit_enrollment(self.session,self.db.users.rows[0])
        self.assertEqual(self.db.voice_template_archives.rows[0]['embedding'],self.before[0]['embedding'])
        self.assertEqual(self.db.voice_templates_v2.rows[0]['enrollment_session_id'],'session')
        self.assertNotIn('voice_repair_request_id',self.db.users.rows[0])
    def test_expired_repair_cannot_overwrite_profile(self):
        self.repair_fixture();self.authorize();self.submit(True)
        self.db.verification_sessions.rows[0].update(mfa_status='VERIFIED',risk_status='ALLOW',voice_repair_authorized_until=0)
        self.assertDenied(lambda:self.gate.commit_enrollment(self.session,self.db.users.rows[0]),409)
        self.assertEqual(self.before,self.db.voice_templates_v2.rows)
    def test_failed_repair_sample_cannot_overwrite_profile(self):
        self.repair_fixture();self.authorize();self.engine.error=VoiceError('REPLAY_SUSPECTED','Replay')
        self.assertDenied(lambda:self.submit(True),400)
        self.assertEqual(self.before,self.db.voice_templates_v2.rows)
        self.assertNotIn('voice_pending_template',self.db.verification_sessions.rows[0])
    def test_repair_cannot_replace_concurrently_changed_profile(self):
        self.repair_fixture();self.authorize();self.submit(True)
        self.db.verification_sessions.rows[0].update(mfa_status='VERIFIED',risk_status='ALLOW')
        self.db.voice_templates_v2.replace_one=lambda *args:SimpleNamespace(modified_count=0)
        self.assertDenied(lambda:self.gate.commit_enrollment(self.session,self.db.users.rows[0]),409)
        self.assertEqual(self.before,self.db.voice_templates_v2.rows)
    def test_repair_request_cannot_be_reused_after_success(self):
        self.test_repair_keeps_old_profile_until_final_mfa_then_archives()
        self.assertDenied(self.authorize,403)
    def test_requested_repair_can_start_after_face_without_another_voice_failure(self):
        import ast
        self.repair_fixture()
        source=ast.parse((ROOT/'server/ai_service/face_service.py').read_text(encoding='utf-8'))
        function=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='voice_recovery_context')
        ns={'voice_security':self.gate,'HTTPException':HTTPException}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'repair_entry','exec'),ns)
        self.request['repair_voice']=True
        # The real request is a Pydantic object; this adapter keeps context binding real.
        request=SimpleNamespace(repair_voice=True,model_dump=lambda:self.request)
        self.assertEqual(ns['voice_recovery_context'](request,'Bearer token')[3],'user')
        self.db.users.rows[0].pop('voice_repair_request_id')
        self.assertDenied(lambda:ns['voice_recovery_context'](request,'Bearer token'),403)
        self.db.users.rows[0]['voice_repair_request_id']='one-time'
        self.db.verification_sessions.rows[0]['face_status']='PENDING'
        self.assertDenied(lambda:ns['voice_recovery_context'](request,'Bearer token'),403)
    def test_incorrect_totp_cannot_authorize_repair(self):
        import ast,hashlib,re,secrets
        from unittest.mock import Mock
        self.repair_fixture()
        source=ast.parse((ROOT/'server/ai_service/face_service.py').read_text(encoding='utf-8'))
        route=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='verify_voice_recovery_alternate')
        route.decorator_list=[];route.returns=None
        for arg in route.args.args:arg.annotation=None
        route.args.defaults=[]
        ns={'HTTPException':HTTPException,'time':time,'re':re,'pyotp':pyotp,'secrets':secrets,'hashlib':hashlib,
            'DuplicateKeyError':DuplicateKeyError,'log_audit_event':Mock(),'voice_security':self.gate,
            'voice_recovery_context':lambda *a:(self.db,self.db.verification_sessions.rows[0],self.db.users.rows[0],'user')}
        self.db.voice_recovery_totp_uses=Collection()
        exec(compile(ast.Module(body=[route],type_ignores=[]),'voice_repair_route','exec'),ns)
        real=self.gate.authorize_repair;self.gate.authorize_repair=Mock(wraps=real)
        wrong=next(str(i).zfill(6) for i in range(100) if not pyotp.TOTP(self.secret).verify(str(i).zfill(6),valid_window=1))
        request=SimpleNamespace(session_id='session',totp_code=wrong,repair_voice=True)
        self.assertDenied(lambda:ns['verify_voice_recovery_alternate'](request,'Bearer token'),400)
        self.gate.authorize_repair.assert_not_called()
        request.totp_code=pyotp.TOTP(self.secret).now()
        self.assertEqual(ns['verify_voice_recovery_alternate'](request,'Bearer token')['status'],'REPAIR_AUTHORIZED')
        self.assertDenied(lambda:ns['verify_voice_recovery_alternate'](request,'Bearer token'),409)

class AudioTests(unittest.TestCase):
    def recording(self,noise):
        rng=np.random.default_rng(4);y=rng.normal(0,noise,6*16000).astype(np.float32)
        y[16000:5*16000]+=.1*np.sin(np.arange(4*16000)*.15)
        return y
    def test_low_background_allowed(self):self.assertGreater(quality(self.recording(.001))[1]['snr_db'],12)
    def test_clean_audio_stays_float32_for_whisper(self):
        clean,_=quality(self.recording(.001))
        self.assertEqual(clean.dtype,np.float32)

    def test_low_microphone_gain_with_clear_speech(self):
        self.assertGreater(quality(self.recording(.001)*.02)[1]['snr_db'],12)
    def test_startup_transient_does_not_mask_command(self):
        y=self.recording(.001);y[:1600]=.4
        self.assertGreater(quality(y)[1]['snr_db'],12)
    def test_short_command_and_early_speech_preserved(self):
        rng=np.random.default_rng(4)
        y=rng.normal(0,.001,4*16000).astype(np.float32)
        y[3200:22400]+=.1*np.sin(np.arange(19200)*.15)
        clean,metrics=quality(y)
        self.assertGreaterEqual(metrics['speech_seconds'],1.0)
        self.assertGreaterEqual(len(clean),19200)
    def test_noise_only_rejected(self):
        y=np.random.default_rng(4).normal(0,.01,64000).astype(np.float32)
        with self.assertRaises(VoiceError):quality(y)
    def test_loud_background_rejected(self):
        with self.assertRaises(VoiceError):quality(self.recording(.05))
    def test_silence_rejected(self):
        with self.assertRaises(VoiceError):quality(np.zeros(64000))
    def test_clipping_rejected(self):
        with self.assertRaises(VoiceError):quality(np.ones(64000))
    def test_nonfinite_rejected(self):
        with self.assertRaises(VoiceError):normal_vector([float('nan')]*256)
    def test_dummy_rejected(self):
        with self.assertRaises(VoiceError):normal_vector([.85,.92,.78,.88])
    def test_exact_phrase_punctuation(self):self.assertTrue(phrase_matches('Blue, river.','blue river'))
    def test_command_numeral_and_spacing(self):self.assertTrue(phrase_matches('Deep Trust Identity Bravo 4',ADMIN_VOICE_COMMAND))
    def test_command_homophones(self):
        for word in ('for','fore','four','4'):
            self.assertTrue(phrase_matches('Deep Trust Identity Bravo '+word,ADMIN_VOICE_COMMAND))
    def test_homophone_rule_does_not_accept_wrong_command(self):
        for text in ('DeepTrust Identity Alpha for','DeepTrust Identity Bravo five',
                     'DeepTrust Identity Bravo for please','DeepTrust Bravo for'):
            self.assertFalse(phrase_matches(text,ADMIN_VOICE_COMMAND))
        self.assertFalse(phrase_matches('blue for','blue four'))
    def test_near_phrase_cannot_pass(self):self.assertFalse(phrase_matches('blue river summer','blue river winter'))
    def test_identical_speaker(self):self.assertGreater(speaker_matches(VECTOR,VECTOR,np.asarray([VECTOR]*4))['speaker_score'],.99)
    def test_wrong_speaker(self):
        other=np.roll(VECTOR,1)
        with self.assertRaises(VoiceError):speaker_matches(VECTOR,other,np.asarray([other]*4))
    def test_loud_other_speaker_windows_rejected(self):
        other=np.roll(VECTOR,1)
        with self.assertRaises(VoiceError):speaker_matches(VECTOR,VECTOR,np.asarray([VECTOR,VECTOR,other,other]))

class DecoderProtectionTests(unittest.TestCase):
    def test_oversized_encoded_upload_rejected_before_decoding(self):
        from voice_engine import VoiceEngine
        with self.assertRaises(VoiceError) as caught:VoiceEngine().decode('A'*(4*1024*1024+257))
        self.assertEqual(caught.exception.code,'AUDIO_SIZE')
    def test_external_playlist_is_not_a_microphone_recording(self):
        import base64
        from voice_engine import VoiceEngine
        data=b'#EXTM3U\nhttp://127.0.0.1/private\n'+b' '*1200
        with self.assertRaises(VoiceError) as caught:VoiceEngine().decode(base64.b64encode(data).decode())
        self.assertEqual(caught.exception.code,'AUDIO_INVALID')
    def test_real_wav_still_decodes_with_pipe_only_protocol(self):
        import wave,io,base64
        from voice_engine import VoiceEngine
        audio=np.zeros(4*16000,dtype='<i2');out=io.BytesIO()
        with wave.open(out,'wb') as wav:
            wav.setnchannels(1);wav.setsampwidth(2);wav.setframerate(16000);wav.writeframes(audio.tobytes())
        decoded,_,_=VoiceEngine().decode(base64.b64encode(out.getvalue()).decode())
        self.assertEqual(decoded.shape,(64000,))
    def test_microphone_dc_offset_does_not_hide_clear_speech(self):
        test=AudioTests();wave=test.recording(.001)
        clean,metrics=quality(wave+.05)
        self.assertGreater(metrics['snr_db'],12)
        self.assertLess(abs(float(np.median(clean))),.01)
    def test_replay_analysis_keeps_early_speech(self):
        import torch
        from voice_engine import VoiceEngine
        from unittest.mock import Mock
        engine=VoiceEngine();engine.models=Mock()
        engine.replay=Mock();engine.replay._compute_embedding.return_value=torch.tensor(4.)
        engine.whisper=Mock();engine.whisper.transcribe.return_value={'text':ADMIN_VOICE_COMMAND}
        engine.embeddings=Mock(return_value=(VECTOR,np.asarray([VECTOR]*3)))
        audio=np.random.default_rng(5).normal(0,.001,4*16000).astype(np.float32)
        audio[3200:22400]+=.1*np.sin(np.arange(19200)*.15)
        engine.analyze(audio,ADMIN_VOICE_COMMAND)
        options=engine.whisper.transcribe.call_args.kwargs
        self.assertEqual(options['temperature'],0)
        self.assertNotIn(ADMIN_VOICE_COMMAND,options['initial_prompt'])
        captured=engine.replay._compute_embedding.call_args.args[0].numpy().ravel()
        self.assertGreaterEqual(len(captured),19200)
        self.assertGreater(np.max(np.abs(captured[:8000])),.05)


class CommandDecodeRetryTests(unittest.TestCase):
    def engine(self,texts):
        import torch
        from voice_engine import VoiceEngine
        from unittest.mock import Mock
        engine=VoiceEngine();engine.models=Mock()
        engine.replay=Mock();engine.replay._compute_embedding.return_value=torch.tensor(4.)
        engine.whisper=Mock();engine.whisper.transcribe.side_effect=[{'text':text} for text in texts]
        engine.embeddings=Mock(return_value=(VECTOR,np.asarray([VECTOR]*3)))
        return engine
    def test_exact_command_does_not_pay_for_second_decode(self):
        engine=self.engine([ADMIN_VOICE_COMMAND])
        engine.analyze(AudioTests().recording(.001),ADMIN_VOICE_COMMAND)
        self.assertEqual(engine.whisper.transcribe.call_count,1)
    def test_beam_retry_recovers_full_command_without_prompting_answer(self):
        engine=self.engine(['Deep trust identity',ADMIN_VOICE_COMMAND])
        engine.analyze(AudioTests().recording(.001),ADMIN_VOICE_COMMAND)
        first,second=engine.whisper.transcribe.call_args_list
        self.assertEqual(second.kwargs['beam_size'],5)
        self.assertEqual(len(second.args[0])-len(first.args[0]),8000)
        self.assertNotIn(ADMIN_VOICE_COMMAND,second.kwargs['initial_prompt'])
        engine.embeddings.assert_called_once()
    def test_wrong_or_incomplete_command_still_rejected(self):
        for wrong in ('DeepTrust Identity Bravo five','DeepTrust identity', 'silence'):
            engine=self.engine(['unrecognized',wrong])
            with self.assertRaises(VoiceError) as caught:
                engine.analyze(AudioTests().recording(.001),ADMIN_VOICE_COMMAND)
            self.assertEqual(caught.exception.code,'PHRASE_MISMATCH')
            self.assertEqual(caught.exception.metrics['recognized_command'],wrong)
            engine.embeddings.assert_not_called()
    def test_replay_rejected_before_either_decode(self):
        import torch
        engine=self.engine([ADMIN_VOICE_COMMAND]);engine.replay._compute_embedding.return_value=torch.tensor(-4.)
        with self.assertRaises(VoiceError) as caught:
            engine.analyze(AudioTests().recording(.001),ADMIN_VOICE_COMMAND)
        self.assertEqual(caught.exception.code,'REPLAY_SUSPECTED')
        engine.whisper.transcribe.assert_not_called()
    def test_recognized_command_does_not_bypass_speaker(self):
        engine=self.engine(['unrecognized',ADMIN_VOICE_COMMAND])
        other=np.roll(VECTOR,1)
        engine.embeddings.return_value=(other,np.asarray([other]*3))
        mean,windows,_=engine.analyze(AudioTests().recording(.001),ADMIN_VOICE_COMMAND)
        with self.assertRaises(VoiceError) as caught:speaker_matches(VECTOR,mean,windows)
        self.assertEqual(caught.exception.code,'SPEAKER_MISMATCH')

if __name__=='__main__':unittest.main()
