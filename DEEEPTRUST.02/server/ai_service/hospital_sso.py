"""Staff identity checks and privacy-safe hospital login notifications."""
import time
from datetime import datetime, timezone
from fastapi import HTTPException

ROLE_ALIASES = {
    'HOSPITAL_ADMIN':'admin', 'ADMINISTRATOR':'admin',
    'DOCTOR':'doctor', 'PHYSICIAN':'doctor', 'CARDIOLOGIST':'doctor',
    'NURSE':'nurse', 'CHARGE_NURSE':'nurse',
    'RECEPTIONIST':'receptionist', 'FRONT_DESK':'receptionist',
    'LAB_TECHNICIAN':'lab_technician', 'LAB_TECH':'lab_technician', 'LAB_STAFF':'lab_technician',
    'PHARMACIST':'pharmacist',
}
def staff_role(role):
    return ROLE_ALIASES.get(str(role or '').strip().upper().replace(' ', '_'))

def check_staff_identity(user, organization_id, requested_role=None):
    role=staff_role(user.get('role'))
    if not role or user.get('organization_id')!=organization_id:
        raise HTTPException(403, 'This account is not an assigned staff member of this hospital. Contact your hospital administrator.')
    if requested_role and staff_role(requested_role)!=role and str(requested_role).lower()!=role:
        raise HTTPException(403, 'Your hospital role does not match the selected staff portal. Select your assigned role.')
    return role

def login_notification(identity, session, client_id, organization_name):
    now=time.time()
    role=staff_role(identity.get('role')) or identity.get('role','staff')
    score=session.get('risk_score')
    level=session.get('risk_level') or 'UNKNOWN'
    trust=session.get('device_trust') or 'UNKNOWN'
    email=identity.get('email','')
    timestamp=datetime.fromtimestamp(now,timezone.utc).isoformat()
    return {
        'notification_id':f"hospital_login_{client_id}_{session['session_id']}",
        'type':'HOSPITAL_STAFF_LOGIN', 'user_id':identity.get('user_id') or email,
        'email':email, 'full_name':identity.get('full_name',''), 'role':role,
        'organization_id':session.get('organization_id'), 'organization_name':organization_name,
        'auth_session_id':session['session_id'], 'client_id':client_id,
        'title':f'New login — {organization_name}',
        'message':f"{email} • {role.replace('_',' ').title()} • Device: {trust} • Risk: {score if score is not None else 'Not measured'}/100 ({level})",
        'risk_score':score, 'risk_level':level, 'device_trust':trust,
        'device':session.get('device'), 'ip_masked':session.get('ip_masked'),
        'read':False, 'created_at':now, 'timestamp':timestamp,
    }
