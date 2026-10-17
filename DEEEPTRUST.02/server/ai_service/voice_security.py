"""Authenticated voice challenges; enrollment is committed after the separate MFA stage.

Legacy templates are retained. Verification never creates or updates a template.
"""
import time
import uuid
import os
from bson import ObjectId
from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError
try:
    from .voice_engine import VoiceEngine, VoiceError, MODEL_ID, VERSION, normal_vector, speaker_matches
except ImportError:
    from voice_engine import VoiceEngine, VoiceError, MODEL_ID, VERSION, normal_vector, speaker_matches

ADMIN_VOICE_COMMAND = 'DeepTrust Identity Bravo Four'

class VoiceSecurity:
    def __init__(self, namespace, engine=None):
        self.ns=namespace
        self.engine=engine or VoiceEngine()

    def context(self, req, authorization, recovery=False):
        data=req if isinstance(req,dict) else req.model_dump()
        token=(authorization or '').removeprefix('Bearer ')
        payload=self.ns['decode_jwt_token'](token) if authorization and authorization.startswith('Bearer ') else None
        if not payload or payload.get('token_type')!='VERIFICATION' or payload.get('session_id')!=data.get('session_id'):
            raise HTTPException(401,'Valid verification token required.')
        db=self.ns['db']
        if db is None:raise HTTPException(503,'Database unavailable.')
        session=db.verification_sessions.find_one({'session_id':data.get('session_id')})
        uid=str(payload.get('sub',''))
        if not session or str(session.get('user_id'))!=uid:
            raise HTTPException(403,'Verification session does not belong to this account.')
        if data.get('user_id') and str(data['user_id']) not in (uid,session.get('email')):
            raise HTTPException(403,'Account mismatch.')
        if session.get('revoked') or session.get('final_decision') in ('FINALIZED','BLOCK','DENY'):
            raise HTTPException(403,'Verification session has ended or been revoked. Sign in again.')
        if time.time()>session.get('expires_at',0):raise HTTPException(403,'Verification session expired. Sign in again.')
        if any(session.get(key)!='VERIFIED' for key in ('credential_status','face_status','liveness_status')):
            raise HTTPException(403,'Complete account and live face verification first.')
        if not recovery and session.get('voice_status') in ('VERIFIED','FAILED_RECOVERY_USED'):
            raise HTTPException(409,'Voice stage already completed.')
        if not recovery and (session.get('voice_attempt_count',0)>=2 or session.get('recovery_required')):
            raise HTTPException(403,{'message':'Recovery verification is required.','recovery_required':True,'attempts':2})
        user=db.users.find_one({'_id':ObjectId(uid)}) if ObjectId.is_valid(uid) else db.users.find_one({'_id':uid})
        if not user or user.get('email')!=session.get('email') or user.get('status','ACTIVE')!='ACTIVE':raise HTTPException(403,'Account unavailable.')
        return data,db,session,user,uid

    def active_guard(self,session):
        return {'session_id':session['session_id'],'user_id':session['user_id'],
            'revoked':{'$ne':True},'final_decision':{'$nin':['FINALIZED','BLOCK','DENY']},
            'expires_at':{'$gt':time.time()},'credential_status':'VERIFIED',
            'face_status':'VERIFIED','liveness_status':'VERIFIED'}

    def profile(self,db,uid):
        profile=db.voice_templates_v2.find_one({'_id':uid})
        if profile:
            if profile.get('model_id')!=MODEL_ID or not profile.get('enrolled'):raise VoiceError('INVALID_VOICE_PROFILE','Saved profile requires administrator recovery. It has been preserved.')
            normal_vector(profile.get('embedding'))
        return profile

    def audit(self,session,event,message,risk='LOW'):
        self.ns['log_audit_event'](event,str(session['user_id']),session['email'],session.get('organization_name','DeepTrust'),message,risk=risk,session_id=session['session_id'])

    def challenge(self,req,authorization):
        data,db,session,user,uid=self.context(req,authorization)
        if session.get('voice_processing_until',0)>time.time():raise HTTPException(409,'A voice recording is still being processed.')
        try:profile=self.profile(db,uid) or self.pending_profile(session,uid)
        except VoiceError as error:raise HTTPException(409,{'code':error.code,'message':str(error)})
        repair=self.repair_authorized(session,user)
        purpose='ENROLL' if repair else ('VERIFY' if profile else 'ENROLL')
        phrase=ADMIN_VOICE_COMMAND
        challenge_id=uuid.uuid4().hex
        updated=db.verification_sessions.update_one({**self.active_guard(session),
            '$or':[{'voice_processing_until':{'$lte':time.time()}},{'voice_processing_until':{'$exists':False}}]}, {'$set':{
            'voice_challenge_id':challenge_id,'voice_challenge_phrase':phrase,
            'voice_challenge_expires_at':time.time()+120,'voice_challenge_consumed':False,'voice_challenge_purpose':purpose}})
        if updated.modified_count!=1:raise HTTPException(409,'A voice recording is still being processed.')
        return {'success':True,'challenge_id':challenge_id,'challenge_phrase':phrase,'purpose':purpose,
            'samples_collected':0,'samples_required':1,
            'instruction':'Stay quiet for one second, then say the displayed DeepTrust command in your natural voice.',
            'mfa_required':False,'enrollment_commit':'AFTER_FINAL_MFA',
            'voice_security_version':VERSION,
            'repair_available':bool(user.get('voice_repair_request_id')) and user.get('email')=='siddeshwar220407@gmail.com',
            'repair_authorized':repair}

    def repair_authorized(self,session,user):
        return (user.get('email')=='siddeshwar220407@gmail.com'
            and bool(user.get('voice_repair_request_id'))
            and user.get('voice_repair_request_id')==session.get('voice_repair_request_id')
            and session.get('voice_repair_authorized_until',0)>time.time())

    def authorize_repair(self,session,user):
        # Called only after the existing, rate-limited and single-use TOTP gate.
        if user.get('email')!='siddeshwar220407@gmail.com' or not user.get('voice_repair_request_id'):
            raise HTTPException(403,'No voice repair was requested for this account.')
        db=self.ns['db']
        if not self.profile(db,str(user['_id'])):
            raise HTTPException(409,'No existing voice profile to repair.')
        result=db.verification_sessions.update_one({**self.active_guard(session),
            'voice_status':{'$nin':['VERIFIED','FAILED_RECOVERY_USED']},
            '$or':[{'voice_processing_until':{'$exists':False}},{'voice_processing_until':{'$lte':time.time()}}]},
            {'$set':{'voice_repair_request_id':user['voice_repair_request_id'],
                'voice_repair_authorized_until':time.time()+600,'voice_status':'PENDING',
                'voice_attempt_count':0,'recovery_required':False,'recovery_status':'NONE'},
             '$unset':{'voice_pending_template':'','voice_challenge_id':''}})
        if result.modified_count!=1:raise HTTPException(409,'Session changed or recording is processing. Retry.')
        self.audit(session,'VOICE_REPAIR_AUTHORIZED','Authenticator authorized one-time voice replacement; existing profile retained.')
        return {'success':True,'status':'REPAIR_AUTHORIZED','message':'Record one fresh live command. Your old profile stays until final MFA.'}

    def pending_profile(self,session,uid):
        profile=session.get('voice_pending_template')
        if not profile:return None
        if profile.get('_id')!=uid or profile.get('model_id')!=MODEL_ID or profile.get('sample_count') not in (1, 3):
            raise VoiceError('INVALID_VOICE_PROFILE','Voice setup needs to be restarted.')
        normal_vector(profile.get('embedding'))
        return profile

    def commit_enrollment(self,session,user):
        """Only the final all-factor gate may persist a first-time voice template."""
        db=self.ns['db'];uid=str(user['_id'])
        session=db.verification_sessions.find_one({'session_id':session['session_id']})
        if not session:raise HTTPException(403,'Verification session unavailable.')
        profile=self.pending_profile(session,uid)
        if not profile:return
        if (str(session.get('user_id'))!=uid or session.get('email')!=user.get('email')
            or session.get('expires_at',0)<=time.time() or session.get('revoked')
            or session.get('final_decision')=='FINALIZED'
            or any(session.get(key)!='VERIFIED' for key in
                ('credential_status','face_status','liveness_status','voice_status','mfa_status'))
            or (session.get('risk_decision') or session.get('risk_status')) not in ('ALLOW','STEP_UP','VERIFIED')):
            raise HTTPException(403,'Complete voice, MFA and access checks before saving voice setup.')
        existing=db.voice_templates_v2.find_one({'_id':uid})
        if existing and self.repair_authorized(session,user) and existing.get('enrollment_session_id')!=session['session_id']:
            # Archive first; CAS replacement cannot overwrite a concurrently changed profile.
            archive_id=uid+':'+session['voice_repair_request_id']
            archived={**existing,'_id':archive_id,'user_id':uid,'archived_at':time.time(),
                'reason':'AUTHENTICATOR_AUTHORIZED_VOICE_REPAIR'}
            try:db.voice_template_archives.insert_one(archived)
            except DuplicateKeyError:
                previous=db.voice_template_archives.find_one({'_id':archive_id})
                if not previous or previous.get('embedding')!=existing['embedding']:
                    raise HTTPException(409,'Profile changed since its backup. Administrator review required.')
            changed=db.voice_templates_v2.replace_one({'_id':uid,'embedding':existing['embedding'],
                'enrollment_session_id':existing.get('enrollment_session_id')},profile)
            if changed.modified_count!=1:raise HTTPException(409,'Voice profile changed during repair. Original data preserved.')
            db.users.update_one({'_id':user['_id'],'voice_repair_request_id':session['voice_repair_request_id']},
                {'$unset':{'voice_repair_request_id':''}})
            self.audit(session,'VOICE_PROFILE_REPAIRED','Live voice replaced after Authenticator authorization and final MFA; original archived.')
        elif existing:
            if existing.get('enrollment_session_id')!=session['session_id']:
                raise HTTPException(409,'A voice profile already exists. It was preserved.')
        else:
            try:db.voice_templates_v2.insert_one(profile)
            except DuplicateKeyError:raise HTTPException(409,'A voice profile already exists. It was preserved.')
        db.users.update_one({'_id':user['_id']},{'$set':{'voice_enrolled':True}})
        db.verification_sessions.update_one({'session_id':session['session_id']},{'$unset':{'voice_pending_template':''}})
        self.audit(session,'VOICE_ENROLLED','One live voice sample saved after separate MFA and access checks; existing data preserved.')

    def submit(self,req,authorization,enroll=False):
        data,db,session,user,uid=self.context(req,authorization)
        claimed=None
        metrics={}
        try:
            profile=self.profile(db,uid) or self.pending_profile(session,uid)
            if self.repair_authorized(session,user):profile=None
            if enroll and profile:raise HTTPException(409,'Voice already enrolled. Existing profile is preserved.')
            if not enroll and not profile:raise HTTPException(409,{'code':'ENROLLMENT_REQUIRED','message':'No compatible enrolled voice profile. Complete secure enrollment first.'})
            purpose='ENROLL' if enroll else 'VERIFY'
            challenge_id=data.get('challenge_id')
            if not challenge_id:raise HTTPException(400,'Fresh challenge_id required.')
            # Claim before expensive analysis: concurrent requests cannot reuse one challenge.
            claimed=db.verification_sessions.find_one_and_update({**self.active_guard(session),
                'voice_challenge_id':challenge_id,'voice_challenge_purpose':purpose,'voice_challenge_consumed':False,
                'voice_challenge_expires_at':{'$gt':time.time()}},{'$set':{'voice_challenge_consumed':True,'voice_processing_until':time.time()+180}})
            if not claimed:raise HTTPException(409,{'code':'CHALLENGE_EXPIRED_OR_USED','message':'Load a new phrase and record again.','retryable':True})
            wave,raw_hash,pcm_hash=self.engine.decode(data.get('audio_data'))
            # Both container and decoded waveform fingerprints are reserved atomically.
            for digest in (raw_hash,pcm_hash):
                try:db.voice_audio_fingerprints.insert_one({'_id':digest,'session_id':session['session_id'],'created_at':time.time()})
                except DuplicateKeyError:raise VoiceError('AUDIO_REUSED','Previously submitted audio detected. Record a fresh live phrase.')
            mean,windows,metrics=self.engine.analyze(wave,claimed['voice_challenge_phrase'])
            # Re-check account and session after potentially slow model inference.
            self.context(req,authorization)
            if enroll:
                template=normal_vector(mean)
                pending={'_id':uid,'email':user['email'],'model_id':MODEL_ID,'embedding':template.tolist(),
                    'enrolled':True,'created_at':time.time(),'enrollment_session_id':session['session_id'],
                    'sample_count':1,'security_version':VERSION}
                result=db.verification_sessions.update_one({**self.active_guard(session),
                    'voice_challenge_id':challenge_id,'expires_at':{'$gt':time.time()},
                    'voice_status':{'$nin':['VERIFIED','FAILED_RECOVERY_USED']}},
                    {'$set':{'voice_pending_template':pending,'voice_status':'VERIFIED',
                             'recovery_required':False,'voice_metrics':{**metrics,'enrollment_sample':True},
                             'voice_security_version':VERSION},
                     '$unset':{'voice_enrollment_samples':''}})
                if result.modified_count!=1:raise HTTPException(409,'Verification session changed. Sign in again.')
                self.audit(session,'VOICE_SETUP_PENDING','One live voice sample passed command and replay checks; saving awaits separate MFA.')
                return {'success':True,'status':'ENROLLED','matched':False,
                        'message':'Voice sample accepted. Complete Authenticator to save your profile.'}
            metrics.update(speaker_matches(profile['embedding'],mean,windows,float(os.getenv('VOICE_SPEAKER_MIN_COSINE','.80'))))
            result=db.verification_sessions.update_one({**self.active_guard(session),'voice_challenge_id':challenge_id,
                'expires_at':{'$gt':time.time()},'voice_status':{'$nin':['VERIFIED','FAILED_RECOVERY_USED']}},
                {'$set':{'voice_status':'VERIFIED','recovery_required':False,'voice_metrics':metrics,'voice_security_version':VERSION}})
            if result.modified_count!=1:raise HTTPException(409,'Verification session changed. Sign in again.')
            self.audit(session,'VOICE_VERIFIED','Fresh phrase, speaker identity and replay countermeasure passed.')
            return {'success':True,'status':'VERIFIED','matched':True,'metrics':metrics,'confidence':metrics['speaker_score'],'message':'Live voice and enrolled speaker verified.'}
        except VoiceError as error:
            # Numerical diagnostics only; never retain raw audio, transcripts,
            # embeddings or verification tokens in failure records.
            allowed=('snr_db','speech_seconds','replay_logit','speaker_score','matching_window_ratio','required_speaker_score','recording_seconds','clean_seconds','ignored_transient_frames','speaker_window_count')
            diagnostics={key:value for key,value in {**metrics,**error.metrics}.items() if key in allowed}
            db.verification_sessions.update_one({'session_id':session['session_id'],'user_id':session['user_id']},
                {'$set':{'voice_last_error':error.code,'voice_last_failure_metrics':diagnostics,'voice_security_version':VERSION}})
            infrastructure=error.code in ('VOICE_ENGINE_UNAVAILABLE','INVALID_VOICE_PROFILE','VOICE_BUSY')
            attempts=session.get('voice_attempt_count',0)
            if error.retryable and not infrastructure:
                db.verification_sessions.update_one({'session_id':session['session_id']},
                    {'$inc':{'voice_quality_retry_count':1},'$set':{'voice_last_quality_error':error.code}})
            if not error.retryable and not infrastructure:
                attempts+=1
                db.verification_sessions.update_one({'session_id':session['session_id']},{'$set':{
                    'voice_attempt_count':attempts,'voice_status':'FAILED','recovery_required':attempts>=2,
                    'recovery_status':'REQUIRED' if attempts>=2 else 'NONE'}})
            self.audit(session,'VOICE_QUALITY_RETRY' if error.retryable else 'VOICE_VERIFICATION_FAILED',error.code,'MEDIUM')
            raise HTTPException(503 if infrastructure else 400,{'success':False,'code':error.code,'message':str(error),
                'recognized_command':error.metrics.get('recognized_command') if error.code=='PHRASE_MISMATCH' else None,
                'retryable':error.retryable,'attempts':attempts,'attempts_remaining':max(0,2-attempts),'recovery_required':attempts>=2})
        finally:
            if claimed is not None:
                db.verification_sessions.update_one({'session_id':session['session_id'],'user_id':session['user_id'],
                    'voice_challenge_id':data['challenge_id']},{'$unset':{'voice_processing_until':''}})

    def health(self):
        return {'voice_security_version':VERSION,'speaker_model':MODEL_ID,'speaker_loaded':self.engine.speaker is not None,
            'replay_loaded':self.engine.replay is not None,'speech_loaded':self.engine.whisper is not None,
            'status':'Operational' if all((self.engine.speaker,self.engine.replay,self.engine.whisper)) else 'Available / not probed',
            'noise_min_snr_db':12,'enrollment_samples':1,'requires_live_calibration':True}
