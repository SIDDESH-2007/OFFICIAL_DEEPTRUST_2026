"""Fail-closed identity-bound, one-time mobile MFA pairing."""
import re
import pyotp
from fastapi import HTTPException

def authorize_pairing_identity(pairing, user):
    if (pairing.get('status') != 'CREDENTIALS_VERIFIED' or
        str(pairing.get('verified_admin_id') or '') != str(user.get('_id')) or
        str(pairing.get('verified_admin_email') or '').lower() != str(user.get('email') or '').lower()):
        raise HTTPException(403, 'Verify this admin account credentials before MFA')
    if user.get('role') not in {'DEEPTRUST_OWNER','DEEPTRUST_ADMIN'} or str(user.get('status','ACTIVE')).upper() != 'ACTIVE':
        raise HTTPException(403, 'Admin account is not authorised for mobile monitoring')

def verify_pairing_totp(secret, code):
    if not secret:
        raise HTTPException(403, 'Google Authenticator enrolment is required')
    code=str(code).strip()
    if not re.fullmatch(r'[0-9]{6}',code):
        raise HTTPException(400, 'Invalid Google Authenticator code')
    try:
        valid=pyotp.TOTP(secret).verify(code,valid_window=1)
    except Exception:
        raise HTTPException(503, 'Authenticator profile could not be verified')
    if not valid:
        raise HTTPException(400, 'Invalid Google Authenticator code')

def consume_pairing(collection, pairing, user, now):
    result=collection.update_one({'_id':pairing['_id'], 'status':'CREDENTIALS_VERIFIED',
        'verified_admin_id':str(user['_id']), 'expires_at':{'$gt':now}},
        {'$set':{'status':'CONSUMED','consumed_at':now,'verified_at':now}})
    if result.modified_count != 1:
        raise HTTPException(409, 'Pairing session expired or already used')
