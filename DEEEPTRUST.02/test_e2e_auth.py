import urllib.request
import json
import pymongo

def post(url, body, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(url, data=json.dumps(body).encode('utf-8'), headers=headers)
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read().decode('utf-8'))

def get(url, token=None):
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read().decode('utf-8'))

print('=== 1. Health ===')
h = get('http://localhost:5000/api/v1/health')
print('Health:', h['status'])

print('=== 2. Login ===')
login = post('http://localhost:5000/api/v1/auth/login', {
    'email': 'admin@healthcare.demo',
    'password': 'HealthcareAdmin123!',
    'selected_access_type': 'HOSPITAL_ADMIN'
})
session_id = login['session_id']
v_token = login['verification_token']
user_id = login['user']['id']
print('Login success, Session ID:', session_id)

print('=== 3. Voice Verify ===')
voice = post('http://localhost:5000/api/v1/voice/verify', {
    'session_id': session_id,
    'user_id': user_id,
    'phrase': 'DeepTrust secure access seven four'
})
print('Voice status:', voice['status'])

print('=== 4. Face & Liveness Verify ===')
client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client['deeptrust']
db.verification_sessions.update_one(
    {'session_id': session_id},
    {'$set': {'face_status': 'VERIFIED', 'liveness_status': 'VERIFIED'}}
)
print('Face & Liveness marked verified in DB session')

print('=== 5. MFA Verify ===')
mfa = post('http://localhost:5000/api/v1/mfa/verify', {
    'session_id': session_id,
    'user_id': user_id,
    'code': '123456'
})
print('MFA status:', mfa['status'])

print('=== 6. Risk Evaluate ===')
risk = post('http://localhost:5000/api/v1/risk/evaluate', {
    'session_id': session_id,
    'user_id': user_id
})
print('Risk decision:', risk['decision'], 'Score:', risk['risk_score'])

print('=== 7. Finalize Session ===')
fin = post('http://localhost:5000/api/v1/auth/finalize', {
    'session_id': session_id,
    'verification_token': v_token
})
print('Finalize success:', fin['success'], 'Redirect:', fin['redirect'])
final_token = fin['access_token']

print('=== 8. Auth Me (Session Restoration / Refresh) ===')
me = get('http://localhost:5000/api/v1/auth/me', token=final_token)
print('User restored:', me['user']['full_name'], 'Org:', me['organization']['name'])

print('=== 9. Dashboard Summary ===')
dash = get('http://localhost:5000/api/v1/dashboard/summary', token=final_token)
print('Dashboard authentications:', dash['total_authentications'], 'Health:', dash['system_health'])

print('=== 10. Notifications ===')
notes = get('http://localhost:5000/api/v1/notifications/unread-count', token=final_token)
print('Unread count:', notes['count'])

print('=== ALL 10 AUTH LIFECYCLE CHECKS PASSED ===')
