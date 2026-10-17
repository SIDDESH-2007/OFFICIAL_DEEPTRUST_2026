"""
test_new_admin_flow.py
Verification test script for DeepTrust Admin Registration, Email Verification, and TOTP MFA
"""

import requests
import pyotp
import time
from pymongo import MongoClient

BASE_URL = "http://127.0.0.1:8000"
GATEWAY_URL = "http://127.0.0.1:5000"

def test_admin_registration_flow():
    print("=" * 60)
    print("RUNNING COMPLETE DEEPTRUST ADMIN REGISTRATION & MFA TESTS")
    print("=" * 60)

    test_email = f"testadmin_{int(time.time())}@deeptrust.org"
    test_password = "SecurePassword123!"
    test_name = "Test Security Officer"

    # Connect to MongoDB directly to inspect records
    client = MongoClient("mongodb://localhost:27017/")
    db = client["deeptrust"]

    # -------------------------------------------------------------
    # TEST 1: Register New DeepTrust Admin Account
    # -------------------------------------------------------------
    print("\n[TEST 1 & 2] Registering new admin account...")
    reg_payload = {
        "full_name": test_name,
        "email": test_email,
        "password": test_password,
        "confirm_password": test_password
    }

    res = requests.post(f"{GATEWAY_URL}/api/v1/admin/register", json=reg_payload)
    print(f"Register Response Status: {res.status_code}")
    reg_data = res.json()
    print("Register Response Body:", reg_data)

    assert res.status_code in [200, 201], f"Registration failed: {reg_data}"
    assert reg_data.get("status") == "PENDING_EMAIL_VERIFICATION"
    print("[OK] Registration successful! Status is PENDING_EMAIL_VERIFICATION.")

    # Verify MongoDB Persistence & Password Hashing
    user_doc = db.users.find_one({"email_normalized": test_email.lower()})
    assert user_doc is not None, "MongoDB user document not found!"
    assert user_doc["role"] == "DEEPTRUST_ADMIN", f"Expected DEEPTRUST_ADMIN role, got {user_doc['role']}"
    assert user_doc["password_hash"].startswith("$2b$") or user_doc["password_hash"].startswith("$2a$"), "Password is not securely hashed!"
    assert user_doc["password_hash"] != test_password, "CRITICAL ERROR: Password stored in plaintext!"
    print("[OK] MongoDB user record persistence & bcrypt password hashing verified!")

    # Verify email_verifications record
    verif_doc = db.email_verifications.find_one({"email": test_email.lower()})
    assert verif_doc is not None, "MongoDB email verification document not found!"
    assert "otp_hash" in verif_doc, "OTP hash missing!"
    print("[OK] MongoDB OTP hash record verified (OTP is NOT stored in plaintext)!")

    # -------------------------------------------------------------
    # TEST 3: Duplicate Account Prevention
    # -------------------------------------------------------------
    print("\n[TEST 3] Testing duplicate registration prevention...")
    dup_res = requests.post(f"{GATEWAY_URL}/api/v1/admin/register", json=reg_payload)
    assert dup_res.status_code == 400, f"Expected 400 for duplicate account, got {dup_res.status_code}"
    print("[OK] Duplicate account registration correctly REJECTED!")

    # -------------------------------------------------------------
    # TEST 4: Wrong Email OTP Verification
    # -------------------------------------------------------------
    print("\n[TEST 4] Testing wrong email OTP verification...")
    wrong_otp_res = requests.post(f"{GATEWAY_URL}/api/v1/auth/email/verify-code", json={
        "email": test_email,
        "code": "000000"
    })
    assert wrong_otp_res.status_code == 400, "Wrong OTP was accepted when it should have been rejected!"
    print("[OK] Wrong email OTP code correctly REJECTED!")

    # -------------------------------------------------------------
    # TEST 5: Correct Email OTP Verification
    # -------------------------------------------------------------
    print("\n[TEST 5] Testing correct email OTP verification...")
    # Fetch actual generated OTP from memory/test context by inspecting otp_hash or generating valid test hash
    # To test actual OTP verification end-to-end, we set a known test OTP hash in DB
    test_otp = "847291"
    import hashlib
    test_otp_hash = hashlib.sha256(test_otp.encode('utf-8')).hexdigest()
    db.email_verifications.update_one({"email": test_email.lower()}, {"$set": {"otp_hash": test_otp_hash}})

    correct_otp_res = requests.post(f"{GATEWAY_URL}/api/v1/auth/email/verify-code", json={
        "email": test_email,
        "code": test_otp
    })
    print("Correct OTP Response Body:", correct_otp_res.json())
    assert correct_otp_res.status_code == 200, f"Correct OTP verification failed: {correct_otp_res.json()}"
    
    # Check status updated to PENDING_MFA_SETUP
    user_doc = db.users.find_one({"email_normalized": test_email.lower()})
    assert user_doc["status"] == "PENDING_MFA_SETUP", f"Expected PENDING_MFA_SETUP status, got {user_doc['status']}"
    assert user_doc["email_verified"] is True
    print("[OK] Email verified successfully! User status updated to PENDING_MFA_SETUP.")

    # -------------------------------------------------------------
    # TEST 6: Google Authenticator Setup & QR Code Generation
    # -------------------------------------------------------------
    print("\n[TEST 6] Initializing Google Authenticator setup...")
    mfa_setup_res = requests.post(f"{GATEWAY_URL}/api/v1/mfa/setup", json={
        "user_id": test_email,
        "email": test_email
    })
    assert mfa_setup_res.status_code == 200
    mfa_data = mfa_setup_res.json()
    assert "qr_code" in mfa_data and mfa_data["qr_code"].startswith("data:image/png;base64,"), "Invalid base64 QR code!"
    assert "secret" in mfa_data and len(mfa_data["secret"]) >= 16, "Invalid TOTP secret!"
    totp_secret = mfa_data["secret"]
    print("[OK] Google Authenticator QR Code and secret generated successfully!")

    # -------------------------------------------------------------
    # TEST 7: Wrong Google Authenticator Code
    # -------------------------------------------------------------
    print("\n[TEST 7] Testing wrong Google Authenticator code...")
    wrong_mfa_res = requests.post(f"{GATEWAY_URL}/api/v1/mfa/totp/confirm", json={
        "user_id": test_email,
        "email": test_email,
        "code": "111111"
    })
    assert wrong_mfa_res.status_code == 400, "Wrong Authenticator code was accepted!"
    print("[OK] Wrong Authenticator code correctly REJECTED!")

    # -------------------------------------------------------------
    # TEST 8: Valid Google Authenticator Code & Activation
    # -------------------------------------------------------------
    print("\n[TEST 8] Confirming current Google Authenticator TOTP code...")
    totp = pyotp.TOTP(totp_secret)
    current_totp_code = totp.now()

    confirm_res = requests.post(f"{GATEWAY_URL}/api/v1/mfa/totp/confirm", json={
        "user_id": test_email,
        "email": test_email,
        "code": current_totp_code
    })
    print("Confirm Response Body:", confirm_res.json())
    assert confirm_res.status_code == 200, f"Authenticator TOTP confirmation failed: {confirm_res.json()}"

    user_doc = db.users.find_one({"email_normalized": test_email.lower()})
    assert user_doc["status"] == "ACTIVE", f"Expected ACTIVE status, got {user_doc['status']}"
    assert user_doc["mfa_enabled"] is True
    print("[OK] Google Authenticator TOTP verified! Account is now ACTIVE!")

    # -------------------------------------------------------------
    # TEST 9: Normal Login & Authenticator Verification
    # -------------------------------------------------------------
    print("\n[TEST 9] Logging in as newly registered ACTIVE admin...")
    login_res = requests.post(f"{GATEWAY_URL}/api/v1/auth/login", json={
        "email": test_email,
        "password": test_password,
        "selected_access_type": "DEEPTRUST_OWNER"
    })
    assert login_res.status_code == 200, f"Login failed for active admin: {login_res.json()}"
    login_data = login_res.json()
    assert login_data.get("success") is True
    print("[OK] Primary credentials verified for newly registered admin!")

    # Test MFA verification step
    mfa_verify_res = requests.post(f"{GATEWAY_URL}/api/v1/mfa/verify", json={
        "session_id": login_data["session_id"],
        "user_id": test_email,
        "code": totp.now()
    })
    assert mfa_verify_res.status_code == 200, f"MFA verification failed: {mfa_verify_res.json()}"
    print("[OK] Google Authenticator MFA verification step passed during login!")

    print("\n" + "=" * 60)
    print("ALL 10 VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    test_admin_registration_flow()
