import requests
import time
import base64
from pymongo import MongoClient

API_URL = "http://localhost:5000/api/v1"
AI_URL = "http://localhost:8000/api/v1"

def print_result(test_name, expected, actual_status, passed):
    print(f"{test_name}: {'PASS' if passed else 'FAIL'} (Expected: {expected}, Got: {actual_status})")

def run_tests():
    print("Running Part B: Complete E2E Security Tests...")
    
    # We will log in to get a session
    login_data = {
        "email": "admin@healthcare.demo",
        "password": "HealthcareAdmin123!",
        "selected_access_type": "HOSPITAL_ADMIN"
    }
    r = requests.post(f"{AI_URL}/auth/login", json=login_data)
    if r.status_code != 200:
        print("Failed to login.")
        return
        
    session_id = r.json()["session_id"]
    token = r.json()["token"]
    user_id = r.json()["user"]["id"]
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # B4 - VERIFY FACTOR BINDING / B17 - CROSS-USER TEST
    # Test using a different user_id for face verification
    r_face_diff_user = requests.post(f"{AI_URL}/face/match", json={"user_id": "different_user", "image": "fake", "session_id": session_id})
    print_result("B17: Cross-User Verification Session", "403", r_face_diff_user.status_code, r_face_diff_user.status_code == 403)
    
    # B9 - BACKEND GATING TEST
    r_mfa_early = requests.post(f"{AI_URL}/mfa/verify", json={"user_id": user_id, "code": "123456", "session_id": session_id})
    print_result("B9: MFA Before Voice (Gating)", "403", r_mfa_early.status_code, r_mfa_early.status_code == 403)
    
    # B11 - DIRECT DASHBOARD TEST
    # Using PRE-AUTH token against dashboard API
    r_dashboard = requests.get(f"{API_URL}/auth/me", headers=headers)
    print_result("B11: Direct Dashboard Test (PRE-AUTH Token)", "401/403", r_dashboard.status_code, r_dashboard.status_code in [401, 403])
    
    # B18 - RBAC TEST
    # Healthcare Admin trying to access DeepTrust Admin API
    r_admin = requests.get(f"{API_URL}/admin/overview", headers=headers)
    print_result("B18: RBAC Test (Healthcare Admin -> DeepTrust API)", "401/403", r_admin.status_code, r_admin.status_code in [401, 403])

    # B20 - ACCOUNT DISABLE TEST
    # Mark user as disabled in db
    client = MongoClient("mongodb://localhost:27017/")
    db = client.deeptrust
    db.users.update_one({"email_normalized": "admin@healthcare.demo"}, {"$set": {"status": "DISABLED"}})
    
    r_login_disabled = requests.post(f"{AI_URL}/auth/login", json=login_data)
    print_result("B20: Account Disable Test", "403/401", r_login_disabled.status_code, r_login_disabled.status_code in [403, 401])
    
    # Restore user
    db.users.update_one({"email_normalized": "admin@healthcare.demo"}, {"$set": {"status": "ACTIVE"}})
    
    print("\nTests completed.")

if __name__ == "__main__":
    run_tests()
