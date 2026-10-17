"""
test_p7_monitoring_suite.py — Comprehensive Automated Test Suite for DeepTrust P7:
Security Monitoring, Alerts, Active Session Revocation, Incidents, PDF Generation, Analytics, RBAC & Audit Trail
"""

import sys
import time
import os
import jwt
import requests
import pyotp
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

def run_p7_suite():
    print("============================================================")
    print("      DEEPTRUST P7 MONITORING & INCIDENT RESPONSE TEST SUITE ")
    print("============================================================\n")

    results = {}

    # 1. TEST CENTRAL EVENT PIPELINE & PERSISTENCE
    print("\n--- STEP 1: Central Security Event Pipeline ---")
    try:
        res = requests.get(f"{BASE_URL}/api/v1/security-events")
        if res.ok and res.json().get("success"):
            events = res.json().get("events", [])
            log_test("Central Security Event Endpoint", True, f"Found {len(events)} events in MongoDB")
            results["EVENT_PIPELINE"] = "PASS"
        else:
            log_test("Central Security Event Endpoint", False, res.text)
            results["EVENT_PIPELINE"] = "FAIL"
    except Exception as e:
        log_test("Central Security Event Endpoint", False, str(e))
        results["EVENT_PIPELINE"] = "FAIL"

    # 2. TEST DYNAMIC UNREAD ALERT COUNT & ALERTS API
    print("\n--- STEP 2: Real-time Alerts & Notification Count ---")
    try:
        res_unread = requests.get(f"{BASE_URL}/api/v1/alerts/unread-count")
        if res_unread.ok and "count" in res_unread.json():
            count = res_unread.json()["count"]
            log_test("Unread Alert Count Endpoint", True, f"Unread count = {count}")
            results["UNREAD_ALERT_COUNT"] = "PASS"
        else:
            log_test("Unread Alert Count Endpoint", False, res_unread.text)
            results["UNREAD_ALERT_COUNT"] = "FAIL"

        res_alerts = requests.get(f"{BASE_URL}/api/v1/alerts")
        if res_alerts.ok and "alerts" in res_alerts.json():
            alerts_list = res_alerts.json()["alerts"]
            log_test("Alerts List Endpoint", True, f"Retrieved {len(alerts_list)} alerts")
            results["ALERTS_LIST"] = "PASS"
        else:
            log_test("Alerts List Endpoint", False, res_alerts.text)
            results["ALERTS_LIST"] = "FAIL"
    except Exception as e:
        log_test("Alerts API", False, str(e))
        results["ALERTS_LIST"] = "FAIL"

    # 3. TEST ALERT ACKNOWLEDGE & RESOLVE WORKFLOW
    print("\n--- STEP 3: Alert Acknowledge & Resolve Workflow ---")
    try:
        # Create a test alert directly in MongoDB or publish event
        test_alert_id = f"alt_test_{int(time.time())}"
        test_event_id = f"evt_test_{int(time.time())}"
        db.alerts.insert_one({
            "alert_id": test_alert_id,
            "event_id": test_event_id,
            "user_id": "test.user@healthcare.demo",
            "organization_id": "HEALTHCARE_ORG_1",
            "severity": "HIGH",
            "title": "Automated Test Security Alert",
            "summary": "P7 Automated Verification Test Alert",
            "created_at": time.time(),
            "status": "OPEN"
        })

        # Test Acknowledge
        res_ack = requests.post(f"{BASE_URL}/api/v1/alerts/{test_alert_id}/acknowledge", json={"notes": "Acknowledged by P7 Test"})
        if res_ack.ok and res_ack.json().get("status") == "ACKNOWLEDGED":
            db_alert = db.alerts.find_one({"alert_id": test_alert_id})
            if db_alert and db_alert.get("status") == "ACKNOWLEDGED":
                log_test("Alert Acknowledge Workflow", True, "Status persisted in MongoDB as ACKNOWLEDGED")
                results["ALERT_ACKNOWLEDGE"] = "PASS"
            else:
                log_test("Alert Acknowledge Workflow", False, "Status not persisted in DB")
                results["ALERT_ACKNOWLEDGE"] = "FAIL"
        else:
            log_test("Alert Acknowledge Workflow", False, res_ack.text)
            results["ALERT_ACKNOWLEDGE"] = "FAIL"

        # Test Resolve
        res_res = requests.post(f"{BASE_URL}/api/v1/alerts/{test_alert_id}/resolve", json={"notes": "Resolved by P7 Test"})
        if res_res.ok and res_res.json().get("status") == "RESOLVED":
            db_alert_res = db.alerts.find_one({"alert_id": test_alert_id})
            if db_alert_res and db_alert_res.get("status") == "RESOLVED":
                log_test("Alert Resolve Workflow", True, "Status persisted in MongoDB as RESOLVED")
                results["ALERT_RESOLVE"] = "PASS"
            else:
                log_test("Alert Resolve Workflow", False, "Status not persisted in DB")
                results["ALERT_RESOLVE"] = "FAIL"
        else:
            log_test("Alert Resolve Workflow", False, res_res.text)
            results["ALERT_RESOLVE"] = "FAIL"
    except Exception as e:
        log_test("Alert Workflow Exception", False, str(e))
        results["ALERT_WORKFLOW"] = "FAIL"

    # 4. TEST SECURITY TIMELINE & NOT REACHED STAGES
    print("\n--- STEP 4: Security Timeline & Step Correlation ---")
    try:
        test_sess_id = f"vs_timeline_{int(time.time())}"
        db.verification_sessions.insert_one({
            "session_id": test_sess_id,
            "user_id": "test.timeline@healthcare.demo",
            "email": "test.timeline@healthcare.demo",
            "credential_status": "VERIFIED",
            "face_status": "FAILED",
            "liveness_status": "NOT_STARTED",
            "voice_status": "NOT_STARTED",
            "mfa_status": "NOT_STARTED",
            "created_at": time.time()
        })

        res_timeline = requests.get(f"{BASE_URL}/api/v1/security-events/timeline/{test_sess_id}")
        if res_timeline.ok and res_timeline.json().get("success"):
            tl = res_timeline.json()["timeline"]
            # Find face and liveness steps
            face_step = next((s for s in tl if s["name"] == "Face Verification"), None)
            liveness_step = next((s for s in tl if s["name"] == "Active Liveness"), None)
            
            if face_step and face_step["status"] == "FAIL" and liveness_step and liveness_step["status"] == "NOT REACHED":
                log_test("Security Timeline NOT REACHED Logic", True, "Early Face failure correctly marks subsequent Liveness stage as NOT REACHED")
                results["TIMELINE_NOT_REACHED"] = "PASS"
            else:
                log_test("Security Timeline NOT REACHED Logic", False, f"Face state={face_step}, Liveness state={liveness_step}")
                results["TIMELINE_NOT_REACHED"] = "FAIL"
        else:
            log_test("Security Timeline Endpoint", False, res_timeline.text)
            results["TIMELINE_NOT_REACHED"] = "FAIL"
    except Exception as e:
        log_test("Security Timeline Exception", False, str(e))
        results["TIMELINE_NOT_REACHED"] = "FAIL"

    # 5. TEST AUTHENTICATION INVESTIGATION VIEW
    print("\n--- STEP 5: Authentication Investigation Endpoint ---")
    try:
        res_inv = requests.get(f"{BASE_URL}/api/v1/security-events/investigate/{test_sess_id}")
        if res_inv.ok and "investigation" in res_inv.json():
            inv = res_inv.json()["investigation"]
            # Ensure no secrets in investigation payload
            secret_keys = ["password", "password_hash", "totp_secret", "otp", "recovery_code", "jwt_secret"]
            leaks = [k for k in secret_keys if k in inv or k in str(inv)]
            if not leaks:
                log_test("Authentication Investigation View", True, "Payload contains identity/risk context with zero secret leaks")
                results["INVESTIGATION_VIEW"] = "PASS"
            else:
                log_test("Authentication Investigation View", False, f"Secret leakage detected: {leaks}")
                results["INVESTIGATION_VIEW"] = "FAIL"
        else:
            log_test("Authentication Investigation View", False, res_inv.text)
            results["INVESTIGATION_VIEW"] = "FAIL"
    except Exception as e:
        log_test("Investigation Exception", False, str(e))
        results["INVESTIGATION_VIEW"] = "FAIL"

    # 6. TEST ACTIVE SESSION MONITOR & REVOCATION
    print("\n--- STEP 6: Active Session Monitor & Revocation ---")
    try:
        # Create active test session in DB
        test_auth_sess_id = f"sess_revoke_test_{int(time.time())}"
        test_jwt = "dummy_token_p7"
        db.auth_sessions.insert_one({
            "_id": test_auth_sess_id,
            "session_id": test_auth_sess_id,
            "user_id": "test.session@healthcare.demo",
            "email": "test.session@healthcare.demo",
            "role": "HOSPITAL_STAFF",
            "organization_id": "HEALTHCARE_ORG_1",
            "created_at": time.time() - 600,
            "last_activity": time.time() - 60,
            "status": "ACTIVE",
            "revoked": False
        })

        admin_jwt = jwt.encode({"sub": "admin", "session_id": test_auth_sess_id, "token_type": "ACCESS", "role": "DEEPTRUST_ADMIN", "organization_id": "HEALTHCARE_ORG_1", "exp": int(time.time()) + 3600}, os.getenv("JWT_SECRET", "super_secret_jwt_key_for_deeptrust_enterprise"), algorithm="HS256")
        if isinstance(admin_jwt, bytes):
            admin_jwt = admin_jwt.decode('utf-8')
        headers = {"Authorization": f"Bearer {admin_jwt}"}
        res_active = requests.get(f"{BASE_URL}/api/v1/admin/sessions/active", headers=headers)
        if res_active.ok and "active_sessions" in res_active.json():
            active_list = res_active.json()["active_sessions"]
            found = any(s["session_id"] == test_auth_sess_id for s in active_list)
            log_test("Active Sessions Listing", found, f"Active session present: {found}")
            results["ACTIVE_SESSIONS_LIST"] = "PASS" if found else "FAIL"
        else:
            log_test("Active Sessions Listing", False, res_active.text)
            results["ACTIVE_SESSIONS_LIST"] = "FAIL"

        # Revoke Session
        res_revoke = requests.post(f"{BASE_URL}/api/v1/admin/sessions/{test_auth_sess_id}/revoke")
        if res_revoke.ok and res_revoke.json().get("status") == "REVOKED":
            db_sess = db.auth_sessions.find_one({"session_id": test_auth_sess_id})
            if db_sess and (db_sess.get("revoked") == True or db_sess.get("status") == "REVOKED"):
                log_test("Session Revocation Persistence", True, "Session marked REVOKED in MongoDB")
                results["SESSION_REVOCATION"] = "PASS"
            else:
                log_test("Session Revocation Persistence", False, "Session status not updated in DB")
                results["SESSION_REVOCATION"] = "FAIL"
        else:
            log_test("Session Revocation Endpoint", False, res_revoke.text)
            results["SESSION_REVOCATION"] = "FAIL"
    except Exception as e:
        log_test("Active Session Monitor Exception", False, str(e))
        results["SESSION_REVOCATION"] = "FAIL"

    # 7. TEST INCIDENT CREATION & LIFECYCLE
    print("\n--- STEP 7: Incident Management Lifecycle ---")
    try:
        # Create Incident
        inc_req = {
            "title": "P7 Automated Verification Incident",
            "severity": "HIGH",
            "primary_event_id": test_event_id,
            "user_id": "test.incident@healthcare.demo",
            "organization_id": "HEALTHCARE_ORG_1",
            "notes": "Incident created for automated test verification"
        }
        res_inc_create = requests.post(f"{BASE_URL}/api/v1/incidents", json=inc_req)
        if res_inc_create.ok and res_inc_create.json().get("success"):
            inc = res_inc_create.json()["incident"]
            inc_id = inc["incident_id"]
            log_test("Incident Creation", True, f"Created incident ID {inc_id}")
            results["INCIDENT_CREATION"] = "PASS"

            # Update Incident Status to RESOLVED
            res_inc_status = requests.post(f"{BASE_URL}/api/v1/incidents/{inc_id}/status", json={"status": "RESOLVED", "resolution_summary": "Resolved during P7 automated test"})
            if res_inc_status.ok and res_inc_status.json().get("status") == "RESOLVED":
                db_inc = db.incidents.find_one({"incident_id": inc_id})
                if db_inc and db_inc.get("status") == "RESOLVED":
                    log_test("Incident Resolution Workflow", True, "Incident status persisted in MongoDB as RESOLVED")
                    results["INCIDENT_RESOLUTION"] = "PASS"
                else:
                    log_test("Incident Resolution Workflow", False, "Status not persisted in DB")
                    results["INCIDENT_RESOLUTION"] = "FAIL"
            else:
                log_test("Incident Resolution Endpoint", False, res_inc_status.text)
                results["INCIDENT_RESOLUTION"] = "FAIL"

            # 8. TEST INCIDENT PDF GENERATION & DOWNLOAD
            print("\n--- STEP 8: Incident Report PDF Generation ---")
            res_pdf = requests.get(f"{BASE_URL}/api/v1/incidents/{inc_id}/pdf")
            if res_pdf.ok and res_pdf.headers.get("content-type") == "application/pdf" and len(res_pdf.content) > 1000:
                log_test("Incident PDF Report Generation", True, f"Generated valid PDF ({len(res_pdf.content)} bytes) via ReportLab")
                results["INCIDENT_PDF"] = "PASS"
            else:
                log_test("Incident PDF Report Generation", False, f"Status={res_pdf.status_code}, type={res_pdf.headers.get('content-type')}")
                results["INCIDENT_PDF"] = "FAIL"
        else:
            log_test("Incident Creation Endpoint", False, res_inc_create.text)
            results["INCIDENT_CREATION"] = "FAIL"
    except Exception as e:
        log_test("Incident Management Exception", False, str(e))
        results["INCIDENT_MANAGEMENT"] = "FAIL"

    # 9. TEST SECURITY ANALYTICS AGGREGATION
    print("\n--- STEP 9: Security Analytics MongoDB Aggregation ---")
    try:
        res_analytics = requests.get(f"{BASE_URL}/api/v1/security/analytics?range=7d")
        if res_analytics.ok and "analytics" in res_analytics.json():
            a = res_analytics.json()["analytics"]
            log_test("Security Analytics Aggregation", True, f"Metrics: attempts={a.get('total_auth_attempts')}, active_sessions={a.get('active_sessions')}")
            results["ANALYTICS_AGGREGATION"] = "PASS"
        else:
            log_test("Security Analytics Aggregation", False, res_analytics.text)
            results["ANALYTICS_AGGREGATION"] = "FAIL"
    except Exception as e:
        log_test("Analytics Exception", False, str(e))
        results["ANALYTICS_AGGREGATION"] = "FAIL"

    # 10. TEST AUDIT TRAIL LOGS
    print("\n--- STEP 10: Audit Trail Logs ---")
    try:
        res_audit = requests.get(f"{BASE_URL}/api/v1/audit-logs")
        if res_audit.ok and ("audit_logs" in res_audit.json() or "logs" in res_audit.json()):
            log_test("Audit Trail Log Retrieval", True, "Successfully queried audit logs from MongoDB")
            results["AUDIT_TRAIL"] = "PASS"
        else:
            log_test("Audit Trail Log Retrieval", False, res_audit.text)
            results["AUDIT_TRAIL"] = "FAIL"
    except Exception as e:
        log_test("Audit Trail Exception", False, str(e))
        results["AUDIT_TRAIL"] = "FAIL"

    # 11. SUMMARY TABLE
    print("\n============================================================")
    print("              P7 MONITORING SUITE SUMMARY REPORT             ")
    print("============================================================")
    all_passed = True
    for k, v in results.items():
        print(f"  {k:<30}: {v}")
        if v != "PASS":
            all_passed = False
    print("============================================================\n")

    return all_passed

if __name__ == "__main__":
    success = run_p7_suite()
    sys.exit(0 if success else 1)
