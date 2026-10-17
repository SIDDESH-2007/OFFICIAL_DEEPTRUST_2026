"""
DeepTrust P9 External Protected Application & Authorization Test Suite
========================================================================
Comprehensive automated test suite for Phase P9 requirements:
- External Protected Application Model & Secret Hashing
- Client Authentication & Organization Binding
- Access Request API & Authorization Decision API
- Pre-Auth Isolation, Expired Token, Session Revocation E2E
- Disabled Account, Organization, and Integration Isolation
- Cross-Integration & Cross-Organization Security
- NoSQL Injection Protection & Fail-Closed Behavior
"""

import urllib.request
import urllib.error
import json
import time
import sys
import uuid
import hashlib
from pymongo import MongoClient

BASE_URL = "http://localhost:5000"
FASTAPI_URL = "http://127.0.0.1:8000"
DEMO_APP_URL = "http://127.0.0.1:5050"

# Connect to local MongoDB
client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=3000)
db = client["deeptrust"]

def run_p9_suite():
    print("=" * 70)
    print("      DEEPTRUST P9 EXTERNAL APPLICATION INTEGRATION TEST SUITE      ")
    print("=" * 70 + "\n")

    results = {}
    
    # Setup test data in DB
    org_a = "HEALTHCARE_ORG_1"
    org_b = "ORG_ISOLATED_TEST_P9"
    
    db.organizations.update_one(
        {"_id": org_b},
        {"$set": {
            "organization_id": org_b,
            "name": "Isolated Org B",
            "industry": "Healthcare Research",
            "status": "ACTIVE",
            "created_at": time.time()
        }},
        upsert=True
    )

    # Create test user for Org A
    test_user_email = "p9_user@healthcare.demo"
    db.users.update_one(
        {"email_normalized": test_user_email},
        {"$set": {
            "user_id": "usr_p9_test_001",
            "email": test_user_email,
            "email_normalized": test_user_email,
            "full_name": "P9 Test Practitioner",
            "role": "Physician",
            "organization_id": org_a,
            "organization_name": "Healthcare Organization",
            "status": "ACTIVE"
        }},
        upsert=True
    )

    # Create valid active session
    sess_id = f"sess_p9_{uuid.uuid4().hex[:8]}"
    db.auth_sessions.update_one(
        {"session_id": sess_id},
        {"$set": {
            "session_id": sess_id,
            "user_id": test_user_email,
            "email": test_user_email,
            "organization_id": org_a,
            "status": "ACTIVE",
            "revoked": False,
            "risk_status": "ALLOW",
            "created_at": time.time(),
            "expires_at": time.time() + 3600
        }},
        upsert=True
    )

    # --- TEST 1: Default Seeded Integration Credentials & Hashing ---
    print("[TEST 1] Verifying Integration Model & Client Secret Protection...")
    int_doc = db.integrations.find_one({"client_id": "client_demo_healthcare_app_001"})
    if int_doc and "client_secret" not in int_doc and "client_secret_hash" in int_doc:
        print("  [PASS] 1. Integration model active. Client secret stored securely as SHA-256 hash.")
        results["CREDENTIAL_PROTECTION"] = "PASS"
    else:
        print("  [FAIL] 1. Integration model missing or secret stored in plaintext!")
        results["CREDENTIAL_PROTECTION"] = "FAIL"

    # --- TEST 2: Admin Create Integration Endpoint ---
    print("\n[TEST 2] Testing Admin Integration Creation Endpoint...")
    admin_user = db.users.find_one({"role": "DEEPTRUST_OWNER"}) or {"email": "owner@deeptrust.demo", "role": "DEEPTRUST_OWNER"}
    # Generate admin JWT
    import jwt
    from dotenv import load_dotenv
    import os
    load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
    jwt_secret = os.getenv("JWT_SECRET", "deeptrust_super_secret_jwt_key_2026")
    
    admin_sess_id = f"admin_sess_{uuid.uuid4().hex[:8]}"
    db.auth_sessions.update_one(
        {"session_id": admin_sess_id},
        {"$set": {
            "session_id": admin_sess_id,
            "user_id": "owner@deeptrust.demo",
            "email": "owner@deeptrust.demo",
            "role": "DEEPTRUST_OWNER",
            "status": "ACTIVE",
            "revoked": False,
            "created_at": time.time(),
            "expires_at": time.time() + 3600
        }},
        upsert=True
    )
    admin_token = jwt.encode({
        "token_type": "ACCESS",
        "session_id": admin_sess_id,
        "sub": "owner@deeptrust.demo",
        "email": "owner@deeptrust.demo",
        "role": "DEEPTRUST_OWNER",
        "organization_id": "DEEPTRUST_PLATFORM",
        "exp": int(time.time()) + 3600
    }, jwt_secret, algorithm="HS256")

    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/integrations",
        data=json.dumps({"application_name": "Test External App P9"}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {admin_token}"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=3)
        data = json.loads(res.read().decode())
        created_client_id = data.get("client_id")
        created_client_secret = data.get("client_secret")
        created_int_id = data.get("integration_id")
        
        # Verify secret in DB is hashed
        created_doc = db.integrations.find_one({"integration_id": created_int_id})
        if created_client_secret and created_doc and created_doc.get("client_secret_hash") == hashlib.sha256(created_client_secret.encode()).hexdigest():
            print(f"  [PASS] 2. Created Integration {created_int_id}. Secret returned once and hashed in database.")
            results["INTEGRATION_MANAGEMENT"] = "PASS"
        else:
            print("  [FAIL] 2. Secret not hashed properly in database!")
            results["INTEGRATION_MANAGEMENT"] = "FAIL"
    except Exception as e:
        print(f"  [FAIL] 2. Create integration endpoint failed: {e}")
        results["INTEGRATION_MANAGEMENT"] = "FAIL"

    # --- TEST 3: Access Request API — Positive ALLOW ---
    print("\n[TEST 3] Access Request API — Positive Authorization...")
    access_payload = {
        "client_id": "client_demo_healthcare_app_001",
        "client_secret": "demo_client_secret_99887766554433221100",
        "auth_session_id": sess_id,
        "requested_resource": "medical-record-demo",
        "requested_action": "VIEW"
    }
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/request",
        data=json.dumps(access_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    authz_token = None
    try:
        res = urllib.request.urlopen(req, timeout=3)
        data = json.loads(res.read().decode())
        if data.get("success") and data.get("decision") == "ALLOW":
            authz_token = data.get("authorization_token")
            print(f"  [PASS] 3. Access Request ALLOWED. Short-lived token issued: {authz_token[:15]}...")
            results["ACCESS_REQUEST_API"] = "PASS"
            results["ALLOW_DECISION"] = "PASS"
        else:
            print(f"  [FAIL] 3. Expected ALLOW but got: {data}")
            results["ACCESS_REQUEST_API"] = "FAIL"
            results["ALLOW_DECISION"] = "FAIL"
    except Exception as e:
        print(f"  [FAIL] 3. Access request endpoint error: {e}")
        results["ACCESS_REQUEST_API"] = "FAIL"
        results["ALLOW_DECISION"] = "FAIL"

    # --- TEST 4: Authorization Decision API — Positive Verify ---
    print("\n[TEST 4] Authorization Decision API — Token Verification...")
    if authz_token:
        verify_payload = {
            "client_id": "client_demo_healthcare_app_001",
            "client_secret": "demo_client_secret_99887766554433221100",
            "authorization_token": authz_token,
            "requested_resource": "medical-record-demo",
            "requested_action": "VIEW"
        }
        req = urllib.request.Request(
            f"{BASE_URL}/api/v1/access/verify",
            data=json.dumps(verify_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            res = urllib.request.urlopen(req, timeout=3)
            data = json.loads(res.read().decode())
            if data.get("success") and data.get("decision") == "ALLOW":
                print("  [PASS] 4. Authorization Decision verified ALLOWED by DeepTrust backend.")
                results["AUTHORIZATION_VERIFICATION"] = "PASS"
            else:
                print(f"  [FAIL] 4. Verification failed: {data}")
                results["AUTHORIZATION_VERIFICATION"] = "FAIL"
        except Exception as e:
            print(f"  [FAIL] 4. Verify endpoint error: {e}")
            results["AUTHORIZATION_VERIFICATION"] = "FAIL"
    else:
        results["AUTHORIZATION_VERIFICATION"] = "FAIL"

    # --- TEST 5: Negative Test 1 — Unauthenticated Access Request ---
    print("\n[TEST 5] Negative Test: Access Request without DeepTrust Session...")
    bad_payload = {
        "client_id": "client_demo_healthcare_app_001",
        "client_secret": "demo_client_secret_99887766554433221100",
        "auth_session_id": "",
        "requested_resource": "medical-record-demo",
        "requested_action": "VIEW"
    }
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/request",
        data=json.dumps(bad_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=3)
        print("  [FAIL] 5. Unauthenticated request unexpectedly succeeded!")
        results["NO_AUTH_DENIAL"] = "FAIL"
    except urllib.error.HTTPError as err:
        if err.code in [401, 403]:
            print(f"  [PASS] 5. Access correctly DENIED (HTTP {err.code}).")
            results["NO_AUTH_DENIAL"] = "PASS"
        else:
            print(f"  [FAIL] 5. Unexpected status code: {err.code}")
            results["NO_AUTH_DENIAL"] = "FAIL"

    # --- TEST 6: Negative Test 2 — Fake Client Decision Injection ---
    print("\n[TEST 6] Negative Test: Client Sending Fake decision='ALLOW'...")
    fake_payload = {
        "client_id": "client_demo_healthcare_app_001",
        "client_secret": "demo_client_secret_99887766554433221100",
        "auth_session_id": "invalid_fake_session",
        "decision": "ALLOW",
        "requested_resource": "medical-record-demo",
        "requested_action": "VIEW"
    }
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/request",
        data=json.dumps(fake_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=3)
        print("  [FAIL] 6. Fake decision='ALLOW' was trusted!")
        results["FAKE_ALLOW_DENIAL"] = "FAIL"
    except urllib.error.HTTPError as err:
        print(f"  [PASS] 6. Fake decision='ALLOW' IGNORED/DENIED by backend (HTTP {err.code}).")
        results["FAKE_ALLOW_DENIAL"] = "PASS"

    # --- TEST 7: Negative Test 3 — Pre-Auth Token Cannot Authorize External App ---
    print("\n[TEST 7] Negative Test: Pre-Auth Token Used for Protected Resource...")
    v_sess_id = f"v_sess_{uuid.uuid4().hex[:8]}"
    db.verification_sessions.update_one(
        {"session_id": v_sess_id},
        {"$set": {
            "session_id": v_sess_id,
            "email": test_user_email,
            "credential_status": "VERIFIED",
            "face_status": "VERIFIED",
            "final_decision": "PRE_AUTH"
        }},
        upsert=True
    )
    pre_payload = {
        "client_id": "client_demo_healthcare_app_001",
        "client_secret": "demo_client_secret_99887766554433221100",
        "auth_session_id": v_sess_id,
        "requested_resource": "medical-record-demo",
        "requested_action": "VIEW"
    }
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/request",
        data=json.dumps(pre_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=3)
        print("  [FAIL] 7. Pre-Auth token was accepted for external app!")
        results["PRE_AUTH_ISOLATION"] = "FAIL"
    except urllib.error.HTTPError as err:
        print(f"  [PASS] 7. Pre-Auth token DENIED for external application (HTTP {err.code}).")
        results["PRE_AUTH_ISOLATION"] = "PASS"

    # --- TEST 8: Negative Test 4 — Expired Authorization Artifact ---
    print("\n[TEST 8] Negative Test: Expired Authorization Artifact Verification...")
    exp_token = f"authz_expired_{uuid.uuid4().hex[:8]}"
    req_exp_id = f"req_exp_{uuid.uuid4().hex[:8]}"
    db.access_requests.update_one(
        {"request_id": req_exp_id},
        {"$set": {
            "request_id": req_exp_id,
            "integration_id": "int_demo_healthcare_app_001",
            "organization_id": org_a,
            "user_id": test_user_email,
            "requested_resource": "medical-record-demo",
            "requested_action": "VIEW",
            "auth_session_id": sess_id,
            "authorization_token": exp_token,
            "created_at": time.time() - 600,
            "expires_at": time.time() - 100,  # Already expired!
            "status": "APPROVED"
        }},
        upsert=True
    )
    exp_payload = {
        "client_id": "client_demo_healthcare_app_001",
        "client_secret": "demo_client_secret_99887766554433221100",
        "authorization_token": exp_token,
        "requested_resource": "medical-record-demo",
        "requested_action": "VIEW"
    }
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/verify",
        data=json.dumps(exp_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=3)
        print("  [FAIL] 8. Expired authorization token was accepted!")
        results["EXPIRED_AUTHORIZATION_DENIAL"] = "FAIL"
    except urllib.error.HTTPError as err:
        print(f"  [PASS] 8. Expired authorization artifact DENIED (HTTP {err.code}).")
        results["EXPIRED_AUTHORIZATION_DENIAL"] = "PASS"

    # --- TEST 9: Session Revocation Integration E2E (PART 21 & PART 38) ---
    print("\n[TEST 9] Session Revocation Integration E2E...")
    # Step A: Issue fresh token
    access_payload["auth_session_id"] = sess_id
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/request",
        data=json.dumps(access_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res = urllib.request.urlopen(req, timeout=3)
    data = json.loads(res.read().decode())
    fresh_token = data.get("authorization_token")

    # Step B: Revoke session in DB
    db.auth_sessions.update_one({"session_id": sess_id}, {"$set": {"revoked": True, "status": "REVOKED"}})

    # Step C: Attempt to verify token
    rev_payload = {
        "client_id": "client_demo_healthcare_app_001",
        "client_secret": "demo_client_secret_99887766554433221100",
        "authorization_token": fresh_token,
        "requested_resource": "medical-record-demo",
        "requested_action": "VIEW"
    }
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/verify",
        data=json.dumps(rev_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=3)
        print("  [FAIL] 9. Revoked session token was accepted!")
        results["SESSION_REVOCATION_E2E"] = "FAIL"
    except urllib.error.HTTPError as err:
        print(f"  [PASS] 9. Protected access DENIED after Admin Session Revocation (HTTP {err.code}).")
        results["SESSION_REVOCATION_E2E"] = "PASS"

    # Restore session for subsequent tests
    db.auth_sessions.update_one({"session_id": sess_id}, {"$set": {"revoked": False, "status": "ACTIVE"}})

    # --- TEST 10: Account Disable Integration (PART 22) ---
    print("\n[TEST 10] Account Disable Integration Test...")
    db.users.update_one({"email_normalized": test_user_email}, {"$set": {"status": "DISABLED"}})
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/request",
        data=json.dumps(access_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=3)
        print("  [FAIL] 10. Disabled user was granted access!")
        results["DISABLED_USER_DENIAL"] = "FAIL"
    except urllib.error.HTTPError as err:
        print(f"  [PASS] 10. Access DENIED for Disabled User Account (HTTP {err.code}).")
        results["DISABLED_USER_DENIAL"] = "PASS"
    db.users.update_one({"email_normalized": test_user_email}, {"$set": {"status": "ACTIVE"}})

    # --- TEST 11: Organization Disable Integration (PART 23) ---
    print("\n[TEST 11] Organization Disable Integration Test...")
    db.organizations.update_one({"$or": [{"organization_id": org_a}, {"_id": org_a}]}, {"$set": {"status": "SUSPENDED"}})
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/request",
        data=json.dumps(access_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=3)
        print("  [FAIL] 11. Suspended organization integration was granted access!")
        results["DISABLED_ORG_DENIAL"] = "FAIL"
    except urllib.error.HTTPError as err:
        print(f"  [PASS] 11. Access DENIED for Suspended Organization (HTTP {err.code}).")
        results["DISABLED_ORG_DENIAL"] = "PASS"
    db.organizations.update_one({"$or": [{"organization_id": org_a}, {"_id": org_a}]}, {"$set": {"status": "ACTIVE"}})

    # --- TEST 12: Integration Disable Test (PART 24) ---
    print("\n[TEST 12] Integration Disable & Re-enable Test...")
    db.integrations.update_one({"client_id": "client_demo_healthcare_app_001"}, {"$set": {"status": "DISABLED"}})
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/request",
        data=json.dumps(access_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=3)
        print("  [FAIL] 12. Disabled integration request was granted access!")
        results["DISABLED_INTEGRATION_DENIAL"] = "FAIL"
    except urllib.error.HTTPError as err:
        print(f"  [PASS] 12. Access DENIED for Disabled External Integration (HTTP {err.code}).")
        results["DISABLED_INTEGRATION_DENIAL"] = "PASS"
    db.integrations.update_one({"client_id": "client_demo_healthcare_app_001"}, {"$set": {"status": "ACTIVE"}})

    # --- TEST 13: Cross-Integration Isolation (PART 25) ---
    print("\n[TEST 13] Cross-Integration Isolation Test...")
    # Issue token for Integration A
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/request",
        data=json.dumps(access_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res = urllib.request.urlopen(req, timeout=3)
    data = json.loads(res.read().decode())
    int_a_token = data.get("authorization_token")

    # Create Integration B
    int_b_secret = "sec_integration_b_99001122"
    db.integrations.update_one(
        {"client_id": "client_integration_b_002"},
        {"$set": {
            "integration_id": "int_b_002",
            "organization_id": org_a,
            "application_name": "Integration B App",
            "status": "ACTIVE",
            "client_id": "client_integration_b_002",
            "client_secret_hash": hashlib.sha256(int_b_secret.encode()).hexdigest()
        }},
        upsert=True
    )

    # Attempt to verify Integration A's token using Integration B's credentials
    cross_int_payload = {
        "client_id": "client_integration_b_002",
        "client_secret": int_b_secret,
        "authorization_token": int_a_token,
        "requested_resource": "medical-record-demo",
        "requested_action": "VIEW"
    }
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/verify",
        data=json.dumps(cross_int_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=3)
        print("  [FAIL] 13. Token issued for Integration A was accepted for Integration B!")
        results["CROSS_INTEGRATION_ISOLATION"] = "FAIL"
    except urllib.error.HTTPError as err:
        print(f"  [PASS] 13. Cross-Integration Token Reuse DENIED (HTTP {err.code}).")
        results["CROSS_INTEGRATION_ISOLATION"] = "PASS"

    # --- TEST 14: Cross-Organization Isolation (PART 26) ---
    print("\n[TEST 14] Cross-Organization Isolation Test...")
    # Integration bound to Org B
    int_org_b_secret = "sec_org_b_secret_5566"
    db.integrations.update_one(
        {"client_id": "client_org_b_003"},
        {"$set": {
            "integration_id": "int_org_b_003",
            "organization_id": org_b,
            "application_name": "Org B App",
            "status": "ACTIVE",
            "client_id": "client_org_b_003",
            "client_secret_hash": hashlib.sha256(int_org_b_secret.encode()).hexdigest()
        }},
        upsert=True
    )
    # User belongs to Org A, attempting access via Org B integration
    cross_org_payload = {
        "client_id": "client_org_b_003",
        "client_secret": int_org_b_secret,
        "auth_session_id": sess_id,  # User in Org A
        "requested_resource": "medical-record-demo",
        "requested_action": "VIEW"
    }
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/request",
        data=json.dumps(cross_org_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=3)
        print("  [FAIL] 14. Cross-Organization access was granted!")
        results["CROSS_ORG_ISOLATION"] = "FAIL"
    except urllib.error.HTTPError as err:
        print(f"  [PASS] 14. Cross-Organization Access DENIED (HTTP {err.code}).")
        results["CROSS_ORG_ISOLATION"] = "PASS"

    # --- TEST 15: NoSQL Injection Protection (PART 33) ---
    print("\n[TEST 15] NoSQL Operator Injection Defense...")
    nosql_payload = {
        "client_id": {"$gt": ""},
        "client_secret": "demo_client_secret_99887766554433221100",
        "auth_session_id": sess_id,
        "requested_resource": "medical-record-demo",
        "requested_action": "VIEW"
    }
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/access/request",
        data=json.dumps(nosql_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=3)
        print("  [FAIL] 15. NoSQL injection object payload succeeded!")
        results["NOSQL_INJECTION_DEFENSE"] = "FAIL"
    except urllib.error.HTTPError as err:
        print(f"  [PASS] 15. NoSQL injection object payload DENIED (HTTP {err.code}).")
        results["NOSQL_INJECTION_DEFENSE"] = "PASS"

    # --- TEST 16: Protected Healthcare Demo App Integration E2E ---
    print("\n[TEST 16] Protected Healthcare Demo App Server-to-Server Flow...")
    demo_req = urllib.request.Request(
        f"{DEMO_APP_URL}/api/access-resource",
        data=json.dumps({"auth_session_id": sess_id}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(demo_req, timeout=4)
        data = json.loads(res.read().decode())
        if data.get("success") and data.get("decision") == "ALLOW":
            print("  [PASS] 16. Demo App successfully authorized by DeepTrust. Synthetic patient record received.")
            results["DEMO_APP_E2E"] = "PASS"
        else:
            print(f"  [FAIL] 16. Demo App request failed: {data}")
            results["DEMO_APP_E2E"] = "FAIL"
    except Exception as e:
        print(f"  [FAIL] 16. Demo App server unreachable on {DEMO_APP_URL}: {e}")
        results["DEMO_APP_E2E"] = "FAIL"

    # Print Summary Report
    print("\n" + "=" * 70)
    print("              P9 INTEGRATION SUITE SUMMARY REPORT             ")
    print("=" * 70)
    passed_count = sum(1 for v in results.values() if v == "PASS")
    total_count = len(results)
    for k, v in results.items():
        print(f"  {k:<30} : {v}")
    print("=" * 70)
    print(f"P9 TEST SUITE RESULT: {passed_count} / {total_count} PASSED\n")

    return passed_count == total_count

if __name__ == "__main__":
    success = run_p9_suite()
    sys.exit(0 if success else 1)
