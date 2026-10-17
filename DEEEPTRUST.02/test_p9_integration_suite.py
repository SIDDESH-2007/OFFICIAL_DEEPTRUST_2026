"""
test_p9_integration_suite.py — Automated Test Suite for DeepTrust P9:
External Protected Application Integration, Access Request & Authorization Verification APIs,
Organization Isolation, Session Revocation, Fail-Closed Security & Replay Protections
"""

import sys
import time
import os
import jwt
import requests
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

BASE_URL = "http://127.0.0.1:8000"
GATEWAY_URL = "http://127.0.0.1:5000"
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["deeptrust"]

def log_test(name, result, message=""):
    status = "PASSED" if result else "FAILED"
    print(f"[{status}] {name}{': ' + message if message else ''}")
    return result

def run_p9_suite():
    print("============================================================")
    print("  DEEPTRUST P9 EXTERNAL APPLICATION INTEGRATION TEST SUITE  ")
    print("============================================================\n")

    results = {}
    admin_jwt = jwt.encode(
        {"sub": "admin", "email": "admin.p9@deeptrust.demo", "session_id": "p9_test_admin_sess", "token_type": "ACCESS", "role": "DEEPTRUST_ADMIN", "organization_id": "HEALTHCARE_ORG_1", "exp": int(time.time()) + 3600},
        os.getenv("JWT_SECRET", "super_secret_jwt_key_for_deeptrust_enterprise"),
        algorithm="HS256"
    )
    if isinstance(admin_jwt, bytes):
        admin_jwt = admin_jwt.decode('utf-8')
    headers = {"Authorization": f"Bearer {admin_jwt}"}

    # Ensure admin user and session exist in DB
    db.users.replace_one(
        {"email_normalized": "admin.p9@deeptrust.demo"},
        {
            "_id": "p9_test_admin_user",
            "email": "admin.p9@deeptrust.demo",
            "email_normalized": "admin.p9@deeptrust.demo",
            "role": "DEEPTRUST_ADMIN",
            "organization_id": "HEALTHCARE_ORG_1",
            "status": "ACTIVE"
        },
        upsert=True
    )
    db.auth_sessions.replace_one(
        {"session_id": "p9_test_admin_sess"},
        {
            "_id": "p9_test_admin_sess",
            "session_id": "p9_test_admin_sess",
            "user_id": "admin.p9@deeptrust.demo",
            "email": "admin.p9@deeptrust.demo",
            "role": "DEEPTRUST_ADMIN",
            "organization_id": "HEALTHCARE_ORG_1",
            "created_at": time.time(),
            "last_activity": time.time(),
            "status": "ACTIVE",
            "revoked": False
        },
        upsert=True
    )

    # 1. TEST INTEGRATION CREATION & CREDENTIAL PROTECTION
    print("--- STEP 1: Integration Management & Credential Protection ---")
    try:
        create_payload = {
            "application_name": f"P9 Test App {int(time.time())}",
            "organization_id": "HEALTHCARE_ORG_1",
            "redirect_uri": "http://localhost:5050/callback",
            "allowed_origins": ["http://localhost:5050"]
        }
        res_create = requests.post(f"{BASE_URL}/api/v1/integrations", json=create_payload, headers=headers)
        if res_create.ok and res_create.json().get("success"):
            data = res_create.json()
            test_int_id = data["integration_id"]
            client_id = data["client_id"]
            client_secret = data["client_secret"]
            log_test("Integration Creation", True, f"Created Integration ID: {test_int_id}")
            results["INTEGRATION_CREATION"] = "PASS"

            # Check Database Hashing (Secret must NOT be stored in plaintext)
            db_int = db.integrations.find_one({"integration_id": test_int_id})
            if db_int and "client_secret_hash" in db_int and "client_secret" not in db_int:
                log_test("Credential Non-Plaintext Protection", True, "Client secret stored safely as SHA-256 hash")
                results["CREDENTIAL_PROTECTION"] = "PASS"
            else:
                log_test("Credential Non-Plaintext Protection", False, "Plaintext secret leak in MongoDB!")
                results["CREDENTIAL_PROTECTION"] = "FAIL"

            # Test Integration Status Update (Disable / Enable)
            res_dis = requests.put(f"{BASE_URL}/api/v1/integrations/{test_int_id}/status", json={"status": "DISABLED"}, headers=headers)
            if res_dis.ok and res_dis.json().get("status") == "DISABLED":
                log_test("Integration Status Disable", True, "Integration status set to DISABLED")
                results["INTEGRATION_STATUS"] = "PASS"
                # Re-enable
                requests.put(f"{BASE_URL}/api/v1/integrations/{test_int_id}/status", json={"status": "ACTIVE"}, headers=headers)
            else:
                log_test("Integration Status Disable", False, res_dis.text)
                results["INTEGRATION_STATUS"] = "FAIL"

            # Test Secret Rotation
            res_rot = requests.post(f"{BASE_URL}/api/v1/integrations/{test_int_id}/rotate-secret", json={}, headers=headers)
            if res_rot.ok and res_rot.json().get("success") and "client_secret" in res_rot.json():
                new_secret = res_rot.json()["client_secret"]
                client_secret = new_secret  # Update active secret for subsequent tests
                log_test("Credential Secret Rotation", True, "Successfully rotated integration secret")
                results["SECRET_ROTATION"] = "PASS"
            else:
                log_test("Credential Secret Rotation", False, res_rot.text)
                results["SECRET_ROTATION"] = "FAIL"
        else:
            log_test("Integration Creation", False, res_create.text)
            results["INTEGRATION_CREATION"] = "FAIL"
    except Exception as e:
        log_test("Integration Management Exception", False, str(e))
        results["INTEGRATION_CREATION"] = "FAIL"

    # 2. TEST ACCESS REQUEST API & PRE-AUTH ISOLATION
    print("\n--- STEP 2: Access Request API & Token Isolation ---")
    try:
        # Create a test active user session
        user_sess_id = f"p9_user_sess_{int(time.time())}"
        test_user_email = "staff.p9@healthcare.demo"
        db.users.replace_one(
            {"email_normalized": test_user_email},
            {
                "user_id": "usr_p9_staff",
                "email": test_user_email,
                "email_normalized": test_user_email,
                "role": "HOSPITAL_STAFF",
                "organization_id": "HEALTHCARE_ORG_1",
                "status": "ACTIVE"
            },
            upsert=True
        )

        db.auth_sessions.replace_one(
            {"session_id": user_sess_id},
            {
                "_id": user_sess_id,
                "session_id": user_sess_id,
                "user_id": test_user_email,
                "email": test_user_email,
                "role": "HOSPITAL_STAFF",
                "organization_id": "HEALTHCARE_ORG_1",
                "created_at": time.time(),
                "last_activity": time.time(),
                "status": "ACTIVE",
                "revoked": False
            },
            upsert=True
        )

        # Test Pre-Auth Token Rejection (Token A cannot authorize external app)
        pre_auth_sess_id = f"pre_auth_{int(time.time())}"
        db.verification_sessions.insert_one({
            "session_id": pre_auth_sess_id,
            "user_id": test_user_email,
            "email": test_user_email,
            "final_decision": "PENDING",
            "created_at": time.time()
        })

        req_pre_auth = {
            "client_id": client_id,
            "client_secret": client_secret,
            "session_token": pre_auth_sess_id,
            "requested_resource": "medical-record-demo",
            "requested_action": "VIEW"
        }
        res_pre = requests.post(f"{BASE_URL}/api/v1/access/request", json=req_pre_auth)
        if res_pre.status_code == 403 and res_pre.json().get("reason_code") == "PRE_AUTH_NOT_PERMITTED":
            log_test("Pre-Auth Token Isolation", True, "Pre-authentication token correctly DENIED")
            results["PRE_AUTH_ISOLATION"] = "PASS"
        else:
            log_test("Pre-Auth Token Isolation", False, f"Response: {res_pre.status_code} {res_pre.text}")
            results["PRE_AUTH_ISOLATION"] = "FAIL"

        # Test Valid Session ALLOW Decision
        req_valid = {
            "client_id": client_id,
            "client_secret": client_secret,
            "session_token": user_sess_id,
            "requested_resource": "medical-record-demo",
            "requested_action": "VIEW"
        }
        res_valid = requests.post(f"{BASE_URL}/api/v1/access/request", json=req_valid)
        if res_valid.ok and res_valid.json().get("decision") == "ALLOW":
            authz_token = res_valid.json().get("authorization_token")
            log_test("Access Request ALLOW Decision", True, f"Issued Authorization Token: {authz_token[:10]}...")
            results["ACCESS_REQUEST_ALLOW"] = "PASS"
        else:
            log_test("Access Request ALLOW Decision", False, res_valid.text)
            results["ACCESS_REQUEST_ALLOW"] = "FAIL"

    except Exception as e:
        log_test("Access Request Exception", False, str(e))
        results["ACCESS_REQUEST_ALLOW"] = "FAIL"

    # 3. TEST AUTHORIZATION VERIFICATION & REPLAY DEFENSES
    print("\n--- STEP 3: Authorization Verification & Security Controls ---")
    try:
        # Verify Valid Token
        ver_req = {
            "client_id": client_id,
            "client_secret": client_secret,
            "authorization_token": authz_token,
            "requested_resource": "medical-record-demo",
            "requested_action": "VIEW"
        }
        res_ver = requests.post(f"{BASE_URL}/api/v1/access/verify", json=ver_req)
        if res_ver.ok and res_ver.json().get("decision") == "ALLOW":
            log_test("Authorization Verification", True, "Valid authorization token verified successfully")
            results["ACCESS_VERIFY_ALLOW"] = "PASS"
        else:
            log_test("Authorization Verification", False, res_ver.text)
            results["ACCESS_VERIFY_ALLOW"] = "FAIL"

        # Test Replay Rejection after Session Revocation
        db.auth_sessions.update_one({"session_id": user_sess_id}, {"$set": {"revoked": True, "status": "REVOKED"}})
        res_rev = requests.post(f"{BASE_URL}/api/v1/access/verify", json=ver_req)
        if res_rev.status_code == 403 and res_rev.json().get("reason_code") == "REVOKED_SESSION":
            log_test("Session Revocation Enforcement", True, "Access DENIED after active session revocation")
            results["REVOKED_SESSION_DENIAL"] = "PASS"
        else:
            log_test("Session Revocation Enforcement", False, res_rev.text)
            results["REVOKED_SESSION_DENIAL"] = "FAIL"

        # Test Disabled Integration Denial
        requests.put(f"{BASE_URL}/api/v1/integrations/{test_int_id}/status", json={"status": "DISABLED"}, headers=headers)
        res_dis_acc = requests.post(f"{BASE_URL}/api/v1/access/request", json=req_valid)
        if res_dis_acc.status_code == 403 and res_dis_acc.json().get("reason_code") == "DISABLED_INTEGRATION":
            log_test("Disabled Integration Denial", True, "Disabled integration correctly DENIED")
            results["DISABLED_INTEGRATION_DENIAL"] = "PASS"
        else:
            log_test("Disabled Integration Denial", False, res_dis_acc.text)
            results["DISABLED_INTEGRATION_DENIAL"] = "FAIL"

    except Exception as e:
        log_test("Authorization Verification Exception", False, str(e))
        results["ACCESS_VERIFY_ALLOW"] = "FAIL"

    # 4. TEST CROSS-ORGANIZATION & CROSS-INTEGRATION ISOLATION
    print("\n--- STEP 4: Cross-Organization & Cross-Integration Isolation ---")
    try:
        # Re-enable integration for isolation testing
        requests.put(f"{BASE_URL}/api/v1/integrations/{test_int_id}/status", json={"status": "ACTIVE"}, headers=headers)

        # Create Org B user
        user_b_sess_id = f"p9_user_b_sess_{int(time.time())}"
        test_user_b_email = "staff.orgb@healthcare.demo"
        db.users.replace_one(
            {"email_normalized": test_user_b_email},
            {
                "user_id": "usr_p9_staff_b",
                "email": test_user_b_email,
                "email_normalized": test_user_b_email,
                "role": "HOSPITAL_STAFF",
                "organization_id": "HEALTHCARE_ORG_2",  # Different organization
                "status": "ACTIVE"
            },
            upsert=True
        )

        db.auth_sessions.replace_one(
            {"session_id": user_b_sess_id},
            {
                "_id": user_b_sess_id,
                "session_id": user_b_sess_id,
                "user_id": test_user_b_email,
                "email": test_user_b_email,
                "role": "HOSPITAL_STAFF",
                "organization_id": "HEALTHCARE_ORG_2",
                "created_at": time.time(),
                "last_activity": time.time(),
                "status": "ACTIVE",
                "revoked": False
            },
            upsert=True
        )

        # Org B user attempting Org A integration
        req_cross_org = {
            "client_id": client_id,
            "client_secret": client_secret,
            "session_token": user_b_sess_id,
            "requested_resource": "medical-record-demo",
            "requested_action": "VIEW"
        }
        res_cross = requests.post(f"{BASE_URL}/api/v1/access/request", json=req_cross_org)
        if res_cross.status_code == 403 and res_cross.json().get("reason_code") == "CROSS_ORGANIZATION_DENIED":
            log_test("Cross-Organization Isolation Defense", True, "Org B user accessing Org A integration DENIED")
            results["CROSS_ORG_ISOLATION"] = "PASS"
        else:
            log_test("Cross-Organization Isolation Defense", False, res_cross.text)
            results["CROSS_ORG_ISOLATION"] = "FAIL"

    except Exception as e:
        log_test("Isolation Testing Exception", False, str(e))
        results["CROSS_ORG_ISOLATION"] = "FAIL"

    # Cleanup test integration
    try:
        requests.delete(f"{BASE_URL}/api/v1/integrations/{test_int_id}", headers=headers)
    except Exception:
        pass

    # REPORT SUMMARY
    print("\n============================================================")
    print("              P9 INTEGRATION SUITE SUMMARY REPORT           ")
    print("============================================================")
    for test_key, status in results.items():
        print(f"  {test_key:<30} : {status}")
    print("============================================================\n")

    all_passed = all(status == "PASS" for status in results.values())
    return all_passed

if __name__ == "__main__":
    success = run_p9_suite()
    sys.exit(0 if success else 1)
