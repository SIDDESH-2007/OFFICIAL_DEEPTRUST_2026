import requests
import time
import base64
import uuid

API_URL = "http://localhost:5000/api/v1"
AI_URL = "http://localhost:8000/api/v1"

def print_result(test_name, expected, actual_status, passed):
    print(f"{test_name}: {'PASS' if passed else 'FAIL'} (Expected: {expected}, Got: {actual_status})")

def run_tests():
    print("Running Backend Gating Bypass Tests...")
    
    # We will hit AI backend directly on 8000 or through 5000 gateway.
    
    # 1. Login to get a valid pre-auth session
    login_data = {
        "email": "admin@healthcare.demo",
        "password": "HealthcareAdmin123!",
        "selected_access_type": "HOSPITAL_ADMIN"
    }
    r = requests.post(f"{AI_URL}/auth/login", json=login_data)
    if r.status_code != 200:
        print("Failed to login for tests.")
        return
    
    session_id = r.json()["session_id"]
    token = r.json()["token"]
    user_id = r.json()["user"]["id"]
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # TEST A: No credentials -> call Face endpoint (we simulate by not providing session_id or invalid one)
    # Actually, we can use a fake session_id
    r_a = requests.post(f"{AI_URL}/face/match", json={"user_id": user_id, "image": "fake", "session_id": "vs_fake"})
    print_result("TEST A: Face Before Credentials", "403/401", r_a.status_code, r_a.status_code in [403, 401])
    
    # TEST B: Credentials only -> call Voice endpoint
    # Session currently only has credentials verified
    r_b = requests.post(f"{AI_URL}/voice/challenge", json={"session_id": session_id, "user_id": user_id})
    print_result("TEST B: Voice Before Face/Liveness", "403", r_b.status_code, r_b.status_code == 403)
    
    # TEST C: Credentials only -> call MFA endpoint
    r_c = requests.post(f"{AI_URL}/mfa/verify", json={"session_id": session_id, "user_id": user_id, "code": "123456"})
    print_result("TEST C: MFA Before Voice", "403", r_c.status_code, r_c.status_code == 403)
    
    # TEST E: All except MFA -> call /auth/finalize
    # Currently only credentials verified
    r_e = requests.post(f"{AI_URL}/auth/finalize", json={"session_id": session_id})
    print_result("TEST E: Finalize Before MFA", "403", r_e.status_code, r_e.status_code == 403)
    
    # TEST G: Valid PRE-AUTH token -> protected dashboard API
    r_g = requests.get(f"{API_URL}/auth/me", headers=headers)
    print_result("TEST G: Pre-Auth Token -> Protected API", "401/403", r_g.status_code, r_g.status_code in [401, 403])
    
    # TEST I: USER_A token + USER_B verification session
    # We pass user_id of somebody else
    r_i = requests.post(f"{AI_URL}/face/match", json={"user_id": "other_user_id", "image": "fake", "session_id": session_id})
    print_result("TEST I: Cross-User Verification Session", "403", r_i.status_code, r_i.status_code == 403)

    # Let's try to mock the DB to advance the session to test Expired and Completed Replay
    # But since it's an end-to-end black box test, we might just report what we can.
    
    print("Tests finished.")

if __name__ == "__main__":
    time.sleep(2) # wait for server
    run_tests()
