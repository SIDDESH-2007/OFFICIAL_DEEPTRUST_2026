"""
test_p3_registration_suite.py
DeepTrust P3 — Real Database-Backed Create Account & Security Test Suite
"""

import time
import requests
import pyotp
import bcrypt
from pymongo import MongoClient

GATEWAY_URL = "http://127.0.0.1:5000"
AI_URL = "http://127.0.0.1:8000"

def run_p3_suite():
    print("=" * 70)
    print("       DEEPTRUST P3 — REGISTRATION & SECURITY SUITE")
    print("=" * 70)

    client = MongoClient("mongodb://localhost:27017/")
    db = client["deeptrust"]

    passed_tests = 0
    failed_tests = 0

    def assert_test(name, condition, error_msg):
        nonlocal passed_tests, failed_tests
        if condition:
            print(f"  [PASS] {name}")
            passed_tests += 1
        else:
            print(f"  [FAIL] {name}: {error_msg}")
            failed_tests += 1

    unique_ts = int(time.time() * 1000)
    test_email = f"p3_user_{unique_ts}@example.com"
    test_password = "P3SecurePassword123!"
    test_fullname = "Dr. DeepTrust P3 Tester"

    # -------------------------------------------------------------
    # 1. Valid Registration
    # -------------------------------------------------------------
    print("\n--- TEST 1: Valid Registration ---")
    reg_payload = {
        "full_name": test_fullname,
        "email": test_email,
        "password": test_password,
        "confirm_password": test_password
    }
    r = requests.post(f"{GATEWAY_URL}/api/v1/auth/register", json=reg_payload)
    d = r.json()
    assert_test("1. Valid Registration Response", r.status_code in [200, 201] and d.get("success") is True, f"Status: {r.status_code}, Body: {d}")

    # -------------------------------------------------------------
    # 2. Duplicate Normalized Email Prevention
    # -------------------------------------------------------------
    print("\n--- TEST 2: Duplicate Normalized Email ---")
    dup_payload = {
        "full_name": "Duplicate User",
        "email": f"  {test_email.upper()}  ",
        "password": test_password,
        "confirm_password": test_password
    }
    r = requests.post(f"{GATEWAY_URL}/api/v1/auth/register", json=dup_payload)
    assert_test("2. Duplicate Normalized Email Rejected", r.status_code in [400, 409], f"Status: {r.status_code}")

    # -------------------------------------------------------------
    # 3. Invalid Email Format
    # -------------------------------------------------------------
    print("\n--- TEST 3: Invalid Email Format ---")
    bad_email_payload = {
        "full_name": "Bad Email User",
        "email": "not-an-email-address",
        "password": test_password,
        "confirm_password": test_password
    }
    r = requests.post(f"{GATEWAY_URL}/api/v1/auth/register", json=bad_email_payload)
    assert_test("3. Invalid Email Rejected", r.status_code == 400, f"Status: {r.status_code}")

    # -------------------------------------------------------------
    # 4. Weak Password Rejection
    # -------------------------------------------------------------
    print("\n--- TEST 4: Weak Password Rejection ---")
    weak_pwd_payload = {
        "full_name": "Weak Pwd User",
        "email": f"weak_{unique_ts}@example.com",
        "password": "123",
        "confirm_password": "123"
    }
    r = requests.post(f"{GATEWAY_URL}/api/v1/auth/register", json=weak_pwd_payload)
    assert_test("4. Weak Password Rejected", r.status_code == 400, f"Status: {r.status_code}")

    # -------------------------------------------------------------
    # 5. Privileged Role Injection Protection (DEEPTRUST_OWNER / DEEPTRUST_ADMIN)
    # -------------------------------------------------------------
    print("\n--- TEST 5: Privileged Role Injection Protection ---")
    role_inj_payload = {
        "full_name": "Malicious Owner Attempt",
        "email": f"owner_inj_{unique_ts}@example.com",
        "password": test_password,
        "confirm_password": test_password,
        "role": "DEEPTRUST_OWNER"
    }
    r = requests.post(f"{GATEWAY_URL}/api/v1/auth/register", json=role_inj_payload)
    assert_test("5. Privileged Role Injection Denied", r.status_code == 403, f"Status: {r.status_code}")

    # Verify no owner record created in DB
    owner_doc = db.users.find_one({"email_normalized": f"owner_inj_{unique_ts}@example.com"})
    assert_test("5b. DB Owner Record Not Created", owner_doc is None or owner_doc.get("role") != "DEEPTRUST_OWNER", "Owner account was created!")

    # -------------------------------------------------------------
    # 6. status=ACTIVE Injection Protection
    # -------------------------------------------------------------
    print("\n--- TEST 6: status=ACTIVE Injection Protection ---")
    status_inj_payload = {
        "full_name": "Status Injection Attempt",
        "email": f"status_inj_{unique_ts}@example.com",
        "password": test_password,
        "confirm_password": test_password,
        "status": "ACTIVE"
    }
    r = requests.post(f"{GATEWAY_URL}/api/v1/auth/register", json=status_inj_payload)
    inj_user = db.users.find_one({"email_normalized": f"status_inj_{unique_ts}@example.com"})
    assert_test("6. ACTIVE Status Injection Blocked", inj_user is not None and inj_user.get("status") == "PENDING_EMAIL_VERIFICATION", f"User status: {inj_user.get('status') if inj_user else 'None'}")

    # -------------------------------------------------------------
    # 7. email_verified=true Injection Protection
    # -------------------------------------------------------------
    print("\n--- TEST 7: email_verified=true Injection Protection ---")
    verif_inj_payload = {
        "full_name": "Verif Injection Attempt",
        "email": f"verif_inj_{unique_ts}@example.com",
        "password": test_password,
        "confirm_password": test_password,
        "email_verified": True
    }
    r = requests.post(f"{GATEWAY_URL}/api/v1/auth/register", json=verif_inj_payload)
    verif_user = db.users.find_one({"email_normalized": f"verif_inj_{unique_ts}@example.com"})
    assert_test("7. email_verified Injection Blocked", verif_user is not None and verif_user.get("email_verified") is False, f"Email verified: {verif_user.get('email_verified') if verif_user else 'None'}")

    # -------------------------------------------------------------
    # 8. permissions Injection Protection
    # -------------------------------------------------------------
    print("\n--- TEST 8: permissions Injection Protection ---")
    perm_inj_payload = {
        "full_name": "Perm Injection Attempt",
        "email": f"perm_inj_{unique_ts}@example.com",
        "password": test_password,
        "confirm_password": test_password,
        "permissions": ["*"]
    }
    r = requests.post(f"{GATEWAY_URL}/api/v1/auth/register", json=perm_inj_payload)
    perm_user = db.users.find_one({"email_normalized": f"perm_inj_{unique_ts}@example.com"})
    assert_test("8. permissions Injection Ignored/Blocked", perm_user is not None and "permissions" not in perm_user, "Permissions array was attached!")

    # -------------------------------------------------------------
    # 9. Unknown Security Field Injection
    # -------------------------------------------------------------
    print("\n--- TEST 9: Unknown Security Field Injection ---")
    unknown_field_payload = {
        "full_name": "Unknown Field Attempt",
        "email": f"unknown_field_{unique_ts}@example.com",
        "password": test_password,
        "confirm_password": test_password,
        "is_admin": True,
        "super_bypass": True
    }
    r = requests.post(f"{GATEWAY_URL}/api/v1/auth/register", json=unknown_field_payload)
    unknown_user = db.users.find_one({"email_normalized": f"unknown_field_{unique_ts}@example.com"})
    assert_test("9. Unknown Security Field Ignored", unknown_user is not None and "is_admin" not in unknown_user and "super_bypass" not in unknown_user, "Unknown fields were set!")

    # -------------------------------------------------------------
    # 10. Database Persistence Verification
    # -------------------------------------------------------------
    print("\n--- TEST 10: Database Persistence Verification ---")
    user_record = db.users.find_one({"email_normalized": test_email.lower()})
    assert_test("10. MongoDB Account Document Persisted", user_record is not None, "Record not found in db.users!")

    # -------------------------------------------------------------
    # 11. Password Hash Verification (bcrypt, no plaintext)
    # -------------------------------------------------------------
    print("\n--- TEST 11: Password Hash Verification ---")
    stored_hash = user_record.get("password_hash", "") if user_record else ""
    is_bcrypt = stored_hash.startswith("$2a$") or stored_hash.startswith("$2b$")
    not_plaintext = stored_hash != test_password
    assert_test("11. Password Securely Hashed (bcrypt)", is_bcrypt and not_plaintext, f"Stored hash: {stored_hash}")

    # -------------------------------------------------------------
    # 12. Safe API Response Verification
    # -------------------------------------------------------------
    print("\n--- TEST 12: Safe API Response Verification ---")
    keys_in_res = list(d.keys())
    has_password = "password" in keys_in_res or "password_hash" in keys_in_res or "secret" in keys_in_res
    assert_test("12. Safe API Response (No Secrets/Passwords)", not has_password and d.get("success") is True, f"Response keys: {keys_in_res}")

    # -------------------------------------------------------------
    # 13. Initial Account Status Secure
    # -------------------------------------------------------------
    print("\n--- TEST 13: Initial Account Status Secure ---")
    status_val = user_record.get("status") if user_record else None
    email_verif = user_record.get("email_verified") if user_record else None
    assert_test("13. Initial Status PENDING_EMAIL_VERIFICATION", status_val == "PENDING_EMAIL_VERIFICATION" and email_verif is False, f"Status: {status_val}, Verified: {email_verif}")

    # -------------------------------------------------------------
    # 14. Pending User Login Denial
    # -------------------------------------------------------------
    print("\n--- TEST 14: Pending User Login Denial ---")
    login_res = requests.post(f"{GATEWAY_URL}/api/v1/auth/login", json={
        "email": test_email,
        "password": test_password,
        "selected_access_type": "HOSPITAL_ADMIN"
    })
    assert_test("14. Pending User Cannot Obtain Final Session", login_res.status_code == 403, f"Status: {login_res.status_code}, Body: {login_res.json()}")

    # -------------------------------------------------------------
    # 15. Admin Provisioning Endpoint Authorization
    # -------------------------------------------------------------
    print("\n--- TEST 15: Admin Provisioning Endpoint Authorization ---")
    admin_prov_res = requests.post(f"{GATEWAY_URL}/api/v1/admin/accounts", json={
        "email": f"unauth_prov_{unique_ts}@example.com",
        "password": test_password,
        "full_name": "Unauth Provision"
    })
    assert_test("15. Unauthenticated Admin Account Provisioning Denied", admin_prov_res.status_code in [401, 403], f"Status: {admin_prov_res.status_code}")

    # -------------------------------------------------------------
    # 16. Healthcare User Cannot Create DeepTrust Owner
    # -------------------------------------------------------------
    print("\n--- TEST 16: Healthcare User Cannot Create DeepTrust Owner ---")
    r = requests.post(f"{GATEWAY_URL}/api/v1/auth/register", json={
        "full_name": "Healthcare User Escalation",
        "email": f"hcu_esc_{unique_ts}@example.com",
        "password": test_password,
        "role": "DEEPTRUST_OWNER"
    })
    assert_test("16. Healthcare User Creating Owner Denied", r.status_code == 403, f"Status: {r.status_code}")

    # -------------------------------------------------------------
    # 17. Seed Script Not Required For Registration
    # -------------------------------------------------------------
    print("\n--- TEST 17: Seed Script Independence ---")
    seed_free_email = f"seed_free_{unique_ts}@example.com"
    r = requests.post(f"{GATEWAY_URL}/api/v1/auth/register", json={
        "full_name": "Seed Free Account",
        "email": seed_free_email,
        "password": test_password
    })
    seed_user = db.users.find_one({"email_normalized": seed_free_email})
    assert_test("17. Real Account Created Without Seed Script", r.status_code in [200, 201] and seed_user is not None, f"Status: {r.status_code}")

    # -------------------------------------------------------------
    # 18. Protected API Rejects Unauthenticated Access
    # -------------------------------------------------------------
    print("\n--- TEST 18: Protected API Rejects Unauthenticated Access ---")
    prot_res = requests.get(f"{GATEWAY_URL}/api/v1/admin/accounts")
    assert_test("18. Protected API Rejects Unauthenticated Access", prot_res.status_code in [401, 403], f"Status: {prot_res.status_code}")

    print("\n" + "=" * 70)
    print(f"P3 SUITE SUMMARY: PASSED {passed_tests} / TOTAL {passed_tests + failed_tests}")
    print("=" * 70)

    return passed_tests, failed_tests, (failed_tests == 0)

if __name__ == "__main__":
    run_p3_suite()
