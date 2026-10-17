"""One-time, account-scoped biometric replacement. Existing profiles stay active
until live face, voice, final MFA and risk checks have completed.
"""
import hashlib
import json
import time
from bson import ObjectId
from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError
import pyotp

VERSION = '2026-10-08.staff-setup1'

def fingerprint(profile):
    return hashlib.sha256(json.dumps(profile, sort_keys=True, default=str).encode()).hexdigest()

class FaceSetup:
    def __init__(self, namespace):
        self.ns = namespace

    def context(self, data, authorization):
        payload = self.ns['decode_jwt_token']((authorization or '').removeprefix('Bearer ')) if (authorization or '').startswith('Bearer ') else None
        if not payload or payload.get('token_type') != 'VERIFICATION' or payload.get('session_id') != data.get('session_id'):
            raise HTTPException(401, 'Valid account verification token required.')
        session = self.ns['require_face_session'](data.get('session_id'))
        uid = str(session['user_id'])
        if str(payload.get('sub')) != uid:
            raise HTTPException(403, 'Account mismatch.')
        db = self.ns['db']
        user = db.users.find_one({'_id': ObjectId(uid) if ObjectId.is_valid(uid) else uid})
        if not user or user.get('email') != session.get('email'):
            raise HTTPException(403, 'Account unavailable.')
        return db, session, user, uid

    def status(self, data, authorization):
        db, session, user, uid = self.context(data, authorization)
        allowed = user.get('biometric_setup_allowed') is True and not user.get('biometric_setup_completed_at')
        return {'available': allowed, 'authorized': bool(allowed and session.get('face_setup_authorized')),
                'version': VERSION}

    def authorize(self, data, authorization):
        db, session, user, uid = self.context(data, authorization)
        if not user.get('biometric_setup_allowed') or user.get('biometric_setup_completed_at'):
            raise HTTPException(403, 'One-time setup is not enabled for this account.')
        if session.get('face_setup_authorized'):
            return {'success': True, 'message': 'Setup already authorized for this sign-in.'}
        if session.get('face_setup_attempts', 0) >= 5:
            raise HTTPException(429, 'Too many setup attempts. Sign in again.')
        db.verification_sessions.update_one({'session_id': session['session_id']}, {'$inc': {'face_setup_attempts': 1}})
        secret = user.get('mfa_secret') or user.get('protected_mfa_secret')
        if not secret:
            mfa = db.mfa_profiles.find_one({'$or': [{'user_id': uid}, {'email': user['email']}]}) or {}
            secret = mfa.get('secret')
        code = str(data.get('code', '')).strip()
        if not secret or len(code) != 6 or not code.isdigit():
            raise HTTPException(400, 'Enter this account’s current Google Authenticator code.')
        totp = pyotp.TOTP(secret)
        now = time.time()
        counter = int(now // totp.interval)
        matched = next((i for i in (counter, counter - 1, counter + 1) if i >= 0 and totp.at(i * totp.interval) == code), None)
        if matched is None:
            raise HTTPException(400, 'Invalid Google Authenticator code.')
        original = db.face_profiles.find_one(self.ns['face_profile_query'](session))
        if not original:
            raise HTTPException(409, 'Existing face profile unavailable. It has not been changed.')
        try:
            db.biometric_setup_totp_uses.insert_one({'_id': f'{uid}:{matched}', 'created_at': now})
        except DuplicateKeyError:
            raise HTTPException(409, 'This setup code was already used. Wait for the next Authenticator code.')
        claim = db.users.update_one({'_id': user['_id'], 'biometric_setup_allowed': True,
            '$or': [{'biometric_setup_session': session['session_id']},
                    {'biometric_setup_expires_at': {'$lte': now}}, {'biometric_setup_expires_at': {'$exists': False}}]},
            {'$set': {'biometric_setup_session': session['session_id'], 'biometric_setup_expires_at': session['expires_at']}})
        if claim.matched_count != 1:
            raise HTTPException(409, 'Setup is active in another sign-in. Finish it or wait for it to expire.')
        db.verification_sessions.update_one({'session_id': session['session_id']}, {'$set': {
            'face_setup_authorized': True, 'face_setup_original_fingerprint': fingerprint(original),
            'face_status': 'PENDING', 'liveness_status': 'PENDING', 'voice_status': 'PENDING', 'mfa_status': 'PENDING'},
            '$unset': {'face_pending_template': '', 'voice_pending_template': ''}})
        self.ns['FACE_MATCH_REFERENCES'].pop(session['session_id'], None)
        self.ns['LIVENESS_SESSIONS'].pop(session['session_id'], None)
        self.audit(session, 'BIOMETRIC_SETUP_AUTHORIZED', 'One-time setup authorized using account credentials and Google Authenticator; existing profiles preserved.')
        return {'success': True, 'message': 'Record your live face, then your voice. Saving requires final MFA.'}

    def stage(self, session, profile):
        if not session.get('face_setup_authorized'):
            raise HTTPException(403, 'Authorize one-time setup first.')
        if session.get('face_pending_template'):
            raise HTTPException(409, 'A face sample is already staged for this sign-in.')
        db = self.ns['db']
        user = db.users.find_one({'_id': ObjectId(session['user_id']) if ObjectId.is_valid(session['user_id']) else session['user_id']})
        if not user or not user.get('biometric_setup_allowed') or user.get('biometric_setup_session') != session['session_id']:
            raise HTTPException(403, 'One-time setup authorization is no longer active.')
        if str(profile.get('user_id')) != str(session['user_id']):
            raise HTTPException(403, 'Face setup identity mismatch.')
        self.ns['normalized_face_template'](profile)
        db.verification_sessions.update_one({'session_id': session['session_id']}, {'$set': {'face_pending_template': profile}})
        return {'success': True, 'status': 'ENROLLED', 'pending': True,
                'message': 'Live face captured. Complete live face, voice and MFA checks to save it.'}

    def commit(self, session, user):
        profile = session.get('face_pending_template')
        if not profile:
            return
        if (not session.get('face_setup_authorized') or str(profile.get('user_id')) != str(user['_id']) or
                any(session.get(k) != 'VERIFIED' for k in ('credential_status', 'face_status', 'liveness_status', 'voice_status', 'mfa_status')) or
                time.time() > session.get('expires_at', 0) or session.get('revoked') or
                session.get('final_decision') in ('FINALIZED', 'BLOCK') or
                session.get('risk_status') == 'BLOCK' or session.get('risk_decision') == 'BLOCK' or
                (session.get('risk_status') not in ('ALLOW', 'STEP_UP', 'VERIFIED') and session.get('risk_decision') not in ('ALLOW', 'STEP_UP'))):
            raise HTTPException(403, 'Complete live face, voice, MFA and access checks before saving setup.')
        self.ns['normalized_face_template'](profile)
        db = self.ns['db']
        current_user = db.users.find_one({'_id': user['_id']})
        if not current_user or not current_user.get('biometric_setup_allowed') or current_user.get('biometric_setup_session') != session['session_id']:
            raise HTTPException(409, 'Setup is no longer active.')
        original = db.face_profiles.find_one(self.ns['face_profile_query'](session))
        if not original or fingerprint(original) != session.get('face_setup_original_fingerprint'):
            raise HTTPException(409, 'Saved face changed during setup. Existing data preserved; sign in again.')
        query = {'_id': original['_id']}
        for key in ('protected_template', 'embedding', 'updated_at'):
            query[key] = original[key] if key in original else {'$exists': False}
        archived = {k: v for k, v in original.items() if k not in ('_id', 'setup_history')}
        archived['archived_at'] = time.time()
        updated = db.face_profiles.update_one(query, {'$set': {**profile, 'setup_session_id': session['session_id']}, '$push': {'setup_history': archived}})
        if updated.matched_count != 1:
            raise HTTPException(409, 'Saved face changed during setup. Existing data preserved.')
        db.users.update_one({'_id': user['_id'], 'biometric_setup_session': session['session_id']}, {'$set': {
            'biometric_setup_allowed': False, 'biometric_setup_completed_at': time.time(), 'face_enrolled': True},
            '$unset': {'biometric_setup_session': '', 'biometric_setup_expires_at': ''}})
        db.verification_sessions.update_one({'session_id': session['session_id']}, {'$unset': {'face_pending_template': ''}})
        self.audit(session, 'BIOMETRIC_SETUP_COMPLETED', 'Live face saved after live voice, MFA and access checks; previous face retained in profile history. One-time setup closed.')

    def audit(self, session, event, message):
        self.ns['log_audit_event'](event, str(session['user_id']), session['email'],
            session.get('organization_name', 'NovaCare'), message, risk='LOW', session_id=session['session_id'])
