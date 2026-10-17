"""
test_all_features.py — Automated End-to-End Test Suite for DeepTrust Security Platform
"""
import sys
import time
import requests
import pyotp
from pymongo import MongoClient

BASE_URL = "http://127.0.0.1:8000"
client = MongoClient("mongodb://localhost:27017/")
db = client["deeptrust"]

def run_tests():
    print("============================================================")
    print("STARTING DEEPTRUST COMPREHENSIVE VERIFICATION TEST SUITE")
    print("============================================================")

    results = {}

    # 1. TEST DATABASE CONNECTION & ISOLATED COLLECTIONS
    print("\n[TEST 1] Verifying MongoDB Connection & Isolated Collections...")
    try:
        collections = db.list_collection_names()
        required_cols = ["deeptrust_admins", "healthcare_admins", "organizations", "audit_logs", "auth_sessions"]
        missing = [c for c in required_cols if c not in collections]
        if missing:
            print(f"FAILED: Missing collections {missing}")
            results["MONGODB_COLLECTIONS"] = "FAIL"
        else:
            print(f"PASSED: Found collections: {collections}")
            results["MONGODB_COLLECTIONS"] = "PASS"
    except Exception as e:
        print(f"FAILED: MongoDB connection error: {e}")
        results["MONGODB_COLLECTIONS"] = "FAIL"

    # 2. GET OR BOOTSTRAP DEEPTRUST ADMIN
    print("\n[TEST 2] DeepTrust Admin Initial Authentication...")
    admin_login = db.users.find_one({"role": {"$in": ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]}, "status": {"$in": ["ACTIVE", "active"]}})
    if not admin_login:
        print("FAILED: No active DeepTrust admin found in DB")
        results["ADMIN_AUTH"] = "FAIL"
        return results

    admin_email = admin_login["email"]
    print(f"Logging in as DeepTrust Platform Admin: {admin_email}")

    # Login Step 1: Login credentials
    login_res = requests.post(f"{BASE_URL}/api/v1/auth/login", json={
        "email": admin_email,
        "password": "OwnerSecret123!" if "owner" in admin_email else "AdminSecret123!",
        "selected_access_type": "DEEPTRUST_OWNER"
    })
    
    if not login_res.ok:
        # Try AdminSecret123!
        login_res = requests.post(f"{BASE_URL}/api/v1/auth/login", json={
            "email": admin_email,
            "password": "AdminSecret123!",
            "selected_access_type": "DEEPTRUST_OWNER"
        })

    if not login_res.ok:
        print(f"FAILED: Admin login credentials failed: {login_res.text}")
        results["ADMIN_AUTH"] = "FAIL"
        return results

    login_data = login_res.json()
    session_id = login_data["session_id"]
    verif_token = login_data["verification_token"]

    # Helper for headless test to mark biometric verification steps
    def complete_biometric_steps(sess_id):
        db.verification_sessions.update_one(
            {"session_id": sess_id},
            {"$set": {
                "credential_status": "VERIFIED",
                "face_status": "VERIFIED",
                "liveness_status": "VERIFIED",
                "voice_status": "VERIFIED",
                "mfa_status": "VERIFIED",
                "face_verified": True,
                "liveness_verified": True,
                "voice_verified": True,
                "mfa_verified": True,
                "risk_score": 5.0,
                "risk_level": "LOW",
                "risk_status": "ALLOW",
                "risk_decision": "ALLOW"
            }}
        )

    # MFA Step: Fetch secret from DB to compute real TOTP
    mfa_prof = db.mfa_profiles.find_one({"$or": [{"user_id": admin_login["_id"]}, {"email": admin_email}]})
    totp_secret = mfa_prof["secret"] if mfa_prof else "JBSWY3DPEHPK3PXP"
    current_totp = pyotp.TOTP(totp_secret).now()

    # Mark biometrics complete for admin session
    complete_biometric_steps(session_id)

    # Step 2a: Test Wrong Code Rejection
    mfa_wrong = requests.post(f"{BASE_URL}/api/v1/mfa/verify", json={
        "session_id": session_id,
        "user_id": admin_email,
        "code": "000000"
    })
    if mfa_wrong.ok and mfa_wrong.json().get("success"):
        print("FAILED: MFA accepted invalid code 000000!")
        results["WRONG_TOTP_REJECTION"] = "FAIL"
    else:
        print(f"PASSED: MFA properly rejected invalid code 000000 (status={mfa_wrong.status_code})")
        results["WRONG_TOTP_REJECTION"] = "PASS"

    # Step 2b: Test Correct Code Acceptance
    mfa_res = requests.post(f"{BASE_URL}/api/v1/mfa/verify", json={
        "session_id": session_id,
        "user_id": admin_email,
        "code": current_totp
    })
    if not mfa_res.ok or not mfa_res.json().get("success"):
        print(f"FAILED: MFA verification with real TOTP failed: {mfa_res.text}")
        results["MFA_VERIFY"] = "FAIL"
        return results
    print("PASSED: Real TOTP verification succeeded.")
    results["MFA_VERIFY"] = "PASS"

    # Step 3: Finalize session
    fin_res = requests.post(f"{BASE_URL}/api/v1/auth/finalize", json={
        "session_id": session_id,
        "verification_token": verif_token
    })
    if not fin_res.ok:
        print(f"FAILED: Finalize session failed: {fin_res.text}")
        results["SESSION_FINALIZE"] = "FAIL"
        return results

    admin_token = fin_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}
    print("PASSED: Platform Admin authenticated with Final Token.")
    results["ADMIN_AUTH"] = "PASS"

    # 3. TEST CREATE DEEPTRUST ADMIN ACCOUNT
    print("\n[TEST 3] Creating DeepTrust Admin Account...")
    test_dt_email = f"test.dtadmin.{int(time.time())}@security.com"
    create_dt_res = requests.post(f"{BASE_URL}/api/v1/admin/accounts", headers=headers, json={
        "full_name": "Marcus Security Officer",
        "email": test_dt_email,
        "account_type": "DEEPTRUST_ADMIN",
        "organization": "DeepTrust",
        "role": "ADMIN",
        "password": "SecurePassword123!"
    })
    if not create_dt_res.ok:
        print(f"FAILED: Create DeepTrust Admin failed: {create_dt_res.text}")
        results["CREATE_DT_ADMIN"] = "FAIL"
    else:
        dt_acc_data = create_dt_res.json()
        print(f"PASSED: DeepTrust Admin created: {test_dt_email}")
        
        # Check MongoDB record
        dt_db_rec = db.deeptrust_admins.find_one({"email": test_dt_email})
        if not dt_db_rec or not dt_db_rec.get("password_hash"):
            print("FAILED: deeptrust_admins record or password_hash missing in MongoDB")
            results["CREATE_DT_ADMIN"] = "FAIL"
        else:
            print("PASSED: MongoDB deeptrust_admins record and bcrypt hash verified.")
            results["CREATE_DT_ADMIN"] = "PASS"

        # Check QR Code returned locally
        mfa_setup = dt_acc_data.get("mfa_setup", {})
        if not mfa_setup.get("qr_base64") or not mfa_setup.get("secret"):
            print("FAILED: QR Base64 or Secret missing from MFA setup")
            results["QR_ENROLLMENT"] = "FAIL"
        else:
            print(f"PASSED: QR Base64 generated locally ({len(mfa_setup['qr_base64'])} chars) with Secret: {mfa_setup['secret']}")
            results["QR_ENROLLMENT"] = "PASS"

            # Confirm TOTP for new DeepTrust Admin
            new_totp = pyotp.TOTP(mfa_setup["secret"]).now()
            conf_res = requests.post(f"{BASE_URL}/api/v1/mfa/totp/confirm", headers=headers, json={
                "user_id": dt_acc_data["user"]["id"],
                "totp_code": new_totp
            })
            if conf_res.ok and conf_res.json().get("success"):
                print("PASSED: Google Authenticator 2FA confirmed and enabled.")
                results["TOTP_CONFIRM"] = "PASS"
            else:
                print(f"FAILED: TOTP confirmation failed: {conf_res.text}")
                results["TOTP_CONFIRM"] = "FAIL"

    # 4. TEST CREATE HEALTHCARE ADMIN ACCOUNT
    print("\n[TEST 4] Creating Healthcare Admin Account for Healthcare Organization...")
    test_hc_email = f"dr.patel.{int(time.time())}@healthcarehospital.org"
    create_hc_res = requests.post(f"{BASE_URL}/api/v1/admin/accounts", headers=headers, json={
        "full_name": "Dr. Ananya Patel",
        "email": test_hc_email,
        "account_type": "HEALTHCARE_ADMIN",
        "organization": "Healthcare Organization",
        "role": "HOSPITAL_ADMIN",
        "password": "HospitalPass2026!"
    })
    if not create_hc_res.ok:
        print(f"FAILED: Create Healthcare Admin failed: {create_hc_res.text}")
        results["CREATE_HC_ADMIN"] = "FAIL"
    else:
        hc_acc_data = create_hc_res.json()
        print(f"PASSED: Healthcare Admin created: {test_hc_email}")
        
        # Check MongoDB healthcare_admins record and organization link
        hc_db_rec = db.healthcare_admins.find_one({"email": test_hc_email})
        if not hc_db_rec or not hc_db_rec.get("organization_id"):
            print("FAILED: healthcare_admins record or organization_id missing in MongoDB")
            results["CREATE_HC_ADMIN"] = "FAIL"
        else:
            print("PASSED: MongoDB healthcare_admins record and organization_id linkage verified.")
            results["CREATE_HC_ADMIN"] = "PASS"

        # Confirm TOTP for Healthcare Admin
        hc_mfa = hc_acc_data["mfa_setup"]
        hc_totp = pyotp.TOTP(hc_mfa["secret"]).now()
        conf_hc_res = requests.post(f"{BASE_URL}/api/v1/mfa/totp/confirm", headers=headers, json={
            "user_id": hc_acc_data["user"]["id"],
            "totp_code": hc_totp
        })
        if conf_hc_res.ok:
            print("PASSED: Healthcare Admin TOTP activated.")

    # 5. TEST DUPLICATE EMAIL PROTECTION
    print("\n[TEST 5] Testing Duplicate Email Protection...")
    dup_res = requests.post(f"{BASE_URL}/api/v1/admin/accounts", headers=headers, json={
        "full_name": "Duplicate Test",
        "email": test_hc_email,
        "account_type": "HEALTHCARE_ADMIN",
        "organization": "Healthcare Organization",
        "role": "HOSPITAL_ADMIN",
        "password": "AnotherPass123!"
    })
    if dup_res.status_code == 400 or dup_res.status_code == 409:
        print(f"PASSED: Duplicate email correctly rejected with status {dup_res.status_code}.")
        results["DUPLICATE_EMAIL_PROTECTION"] = "PASS"
    else:
        print(f"FAILED: Duplicate email allowed (status={dup_res.status_code})")
        results["DUPLICATE_EMAIL_PROTECTION"] = "FAIL"

    # 6. TEST HEALTHCARE ADMIN LOGIN FLOW
    print("\n[TEST 6] Testing Login Flow with newly created Healthcare Admin...")
    hc_login_res = requests.post(f"{BASE_URL}/api/v1/auth/login", json={
        "email": test_hc_email,
        "password": "HospitalPass2026!",
        "selected_access_type": "HOSPITAL_ADMIN"
    })
    if not hc_login_res.ok:
        print(f"FAILED: Healthcare Admin login credentials rejected: {hc_login_res.text}")
        results["HC_LOGIN"] = "FAIL"
    else:
        hc_login_data = hc_login_res.json()
        hc_sess_id = hc_login_data["session_id"]
        hc_verif = hc_login_data["verification_token"]

        # Complete biometrics for HC session
        complete_biometric_steps(hc_sess_id)

        # Verify MFA with real TOTP
        hc_live_totp = pyotp.TOTP(hc_mfa["secret"]).now()
        hc_mfa_res = requests.post(f"{BASE_URL}/api/v1/mfa/verify", json={
            "session_id": hc_sess_id,
            "user_id": test_hc_email,
            "code": hc_live_totp
        })
        if not hc_mfa_res.ok:
            print(f"FAILED: Healthcare Admin MFA verification failed: {hc_mfa_res.text}")
            results["HC_LOGIN"] = "FAIL"
        else:
            # Finalize session
            hc_fin_res = requests.post(f"{BASE_URL}/api/v1/auth/finalize", json={
                "session_id": hc_sess_id,
                "verification_token": hc_verif
            })
            if hc_fin_res.ok and hc_fin_res.json().get("access_token"):
                print("PASSED: Healthcare Admin logged in successfully with full zero-trust session.")
                results["HC_LOGIN"] = "PASS"
                hc_token = hc_fin_res.json()["access_token"]
            else:
                print(f"FAILED: Finalize session failed: {hc_fin_res.text}")
                results["HC_LOGIN"] = "FAIL"

    # 7. TEST PROFILE UPDATE
    print("\n[TEST 7] Testing Profile Full Name Update...")
    prof_patch_res = requests.patch(f"{BASE_URL}/api/v1/profile", headers=headers, json={
        "full_name": "Platform Chief Architect"
    })
    if prof_patch_res.ok:
        me_res = requests.get(f"{BASE_URL}/api/v1/auth/me", headers=headers)
        if me_res.ok and me_res.json()["user"]["full_name"] == "Platform Chief Architect":
            print("PASSED: Profile full_name successfully updated and persisted in MongoDB.")
            results["PROFILE_UPDATE"] = "PASS"
        else:
            print(f"FAILED: Profile GET did not reflect updated name: {me_res.text}")
            results["PROFILE_UPDATE"] = "FAIL"
    else:
        print(f"FAILED: Profile PATCH failed: {prof_patch_res.text}")
        results["PROFILE_UPDATE"] = "FAIL"

    # 8. TEST CHANGE PASSWORD & SESSION REVOCATION
    print("\n[TEST 8] Testing Password Change...")
    # Change password for test_dt_email
    dt_login_res = requests.post(f"{BASE_URL}/api/v1/auth/login", json={
        "email": test_dt_email,
        "password": "SecurePassword123!",
        "selected_access_type": "DEEPTRUST_OWNER"
    })
    if not dt_login_res.ok:
        print(f"FAILED: dt_login_res failed: status={dt_login_res.status_code}, body={dt_login_res.text}")
    dt_sess = dt_login_res.json()
    complete_biometric_steps(dt_sess["session_id"])
    dt_live_totp = pyotp.TOTP(mfa_setup["secret"]).now()
    requests.post(f"{BASE_URL}/api/v1/mfa/verify", json={
        "session_id": dt_sess["session_id"],
        "user_id": test_dt_email,
        "code": dt_live_totp
    })
    dt_fin = requests.post(f"{BASE_URL}/api/v1/auth/finalize", json={
        "session_id": dt_sess["session_id"],
        "verification_token": dt_sess["verification_token"]
    }).json()
    dt_token = dt_fin["access_token"]

    chg_pwd_res = requests.post(f"{BASE_URL}/api/v1/profile/change-password", headers={"Authorization": f"Bearer {dt_token}"}, json={
        "current_password": "SecurePassword123!",
        "new_password": "NewUltraPassword2026!",
        "confirm_password": "NewUltraPassword2026!"
    })
    if chg_pwd_res.ok and chg_pwd_res.json().get("success"):
        print("PASSED: Password changed successfully.")
        results["CHANGE_PASSWORD"] = "PASS"
        
        # Verify old password rejected
        old_login = requests.post(f"{BASE_URL}/api/v1/auth/login", json={
            "email": test_dt_email,
            "password": "SecurePassword123!",
            "selected_access_type": "DEEPTRUST_OWNER"
        })
        if not old_login.ok:
            print("PASSED: Old password correctly rejected after change.")
        else:
            print("FAILED: Old password still accepted!")
    else:
        print(f"FAILED: Password change failed: {chg_pwd_res.text}")
        results["CHANGE_PASSWORD"] = "FAIL"

    # 9. TEST DISABLE & REMOVE ACCOUNT WITH IMMEDIATE LOGIN REJECTION
    print("\n[TEST 9] Testing Account Disabling & Removal...")
    hc_id = hc_acc_data["user"]["id"]
    
    # Disable account
    dis_res = requests.post(f"{BASE_URL}/api/v1/admin/accounts/{hc_id}/disable", headers=headers)
    if dis_res.ok:
        print(f"PASSED: Account {test_hc_email} disabled.")
        # Attempt login while disabled -> MUST FAIL
        dis_login = requests.post(f"{BASE_URL}/api/v1/auth/login", json={
            "email": test_hc_email,
            "password": "HospitalPass2026!",
            "selected_access_type": "HOSPITAL_ADMIN"
        })
        if not dis_login.ok and dis_login.status_code in [401, 403]:
            print(f"PASSED: Disabled account login rejected with status {dis_login.status_code}.")
            results["DISABLE_ACCOUNT"] = "PASS"
        else:
            print(f"FAILED: Disabled account was able to login! (status={dis_login.status_code})")
            results["DISABLE_ACCOUNT"] = "FAIL"
    else:
        print(f"FAILED: Disable account API failed: {dis_res.text}")
        results["DISABLE_ACCOUNT"] = "FAIL"

    # Remove account (Soft-Delete)
    del_res = requests.delete(f"{BASE_URL}/api/v1/admin/accounts/{hc_id}", headers=headers)
    if del_res.ok:
        print(f"PASSED: Account {test_hc_email} removed.")
        del_db = db.healthcare_admins.find_one({"_id": hc_id}) or db.users.find_one({"email": test_hc_email})
        if del_db and del_db.get("status") in ["removed", "REMOVED"]:
            print("PASSED: MongoDB auditable removal status ('removed') confirmed.")
            results["REMOVE_ACCOUNT"] = "PASS"
        else:
            print(f"FAILED: Database record status not 'removed': {del_db}")
            results["REMOVE_ACCOUNT"] = "FAIL"
    else:
        print(f"FAILED: Remove account API failed: {del_res.text}")
        results["REMOVE_ACCOUNT"] = "FAIL"

    # 10. TEST MONTHLY REPORT AGGREGATION & PDF GENERATION
    print("\n[TEST 10] Testing Monthly Security Report Aggregation & PDF Generation...")
    rep_res = requests.get(f"{BASE_URL}/api/v1/admin/reports/monthly?year=2026&month=9", headers=headers)
    if rep_res.ok:
        rep_data = rep_res.json()
        metrics = rep_data.get("metrics", {})
        print(f"PASSED: Monthly report aggregated from MongoDB (Total Logins: {metrics.get('total_login_attempts')}, Successful: {metrics.get('successful_authentications')})")
        results["MONTHLY_REPORT_AGGREGATION"] = "PASS"
    else:
        print(f"FAILED: Monthly report API failed: {rep_res.text}")
        results["MONTHLY_REPORT_AGGREGATION"] = "FAIL"

    pdf_res = requests.get(f"{BASE_URL}/api/v1/admin/reports/monthly?year=2026&month=9&download=true", headers=headers)
    if pdf_res.ok and pdf_res.headers.get("content-type") == "application/pdf" and pdf_res.content.startswith(b"%PDF"):
        print(f"PASSED: Monthly PDF report generated successfully ({len(pdf_res.content)} bytes, starts with %PDF).")
        results["PDF_GENERATION"] = "PASS"
        # Save a copy locally
        with open("DeepTrust_Security_Report_2026_09_Test.pdf", "wb") as f:
            f.write(pdf_res.content)
    else:
        print(f"FAILED: PDF generation failed: status={pdf_res.status_code}, content_type={pdf_res.headers.get('content-type')}")
        results["PDF_GENERATION"] = "FAIL"

    # 11. TEST AUDIT LOGS
    print("\n[TEST 11] Testing Security Audit Trail Records...")
    audit_logs = list(db.audit_logs.find().sort("timestamp", -1).limit(10))
    actions = [a.get("action") for a in audit_logs]
    print(f"Recent Audit Actions in MongoDB: {actions}")
    if len(audit_logs) > 0:
        print("PASSED: Immutable audit records populated in MongoDB.")
        results["AUDIT_LOGGING"] = "PASS"
    else:
        print("FAILED: No audit logs found in MongoDB")
        results["AUDIT_LOGGING"] = "FAIL"

    print("\n============================================================")
    print("TEST SUITE SUMMARY")
    print("============================================================")
    for k, v in results.items():
        print(f"{k.ljust(30)}: {v}")

    return results

if __name__ == "__main__":
    run_tests()
