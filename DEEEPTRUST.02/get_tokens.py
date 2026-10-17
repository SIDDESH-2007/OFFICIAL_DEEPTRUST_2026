import urllib.request
import json
import pymongo

def get_token(email, pwd, role):
    client = pymongo.MongoClient('mongodb://localhost:27017/')
    db = client['deeptrust']
    
    login_req = urllib.request.Request(
        'http://localhost:5000/api/v1/auth/login',
        data=json.dumps({'email': email, 'password': pwd, 'selected_access_type': role}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = urllib.request.urlopen(login_req)
    login_data = json.loads(res.read().decode('utf-8'))
    session_id = login_data['session_id']
    v_token = login_data['verification_token']
    
    db.verification_sessions.update_one(
        {'session_id': session_id},
        {'$set': {'face_status': 'VERIFIED', 'liveness_status': 'VERIFIED', 'voice_status': 'VERIFIED', 'mfa_status': 'VERIFIED', 'risk_status': 'VERIFIED', 'final_decision': 'ALLOW'}}
    )
    
    fin_req = urllib.request.Request(
        'http://localhost:5000/api/v1/auth/finalize',
        data=json.dumps({'session_id': session_id, 'verification_token': v_token}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    fin_res = urllib.request.urlopen(fin_req)
    fin_data = json.loads(fin_res.read().decode('utf-8'))
    return fin_data['access_token']

if __name__ == '__main__':
    c_tok = get_token('admin@healthcare.demo', 'HealthcareAdmin123!', 'HOSPITAL_ADMIN')
    o_tok = get_token('owner@deeptrust.demo', 'OwnerSecret123!', 'DEEPTRUST_OWNER')
    print('HEALTHCARE_TOKEN=' + c_tok)
    print('OWNER_TOKEN=' + o_tok)
    with open('tokens.json', 'w') as f:
        json.dump({'healthcare': c_tok, 'owner': o_tok}, f)
