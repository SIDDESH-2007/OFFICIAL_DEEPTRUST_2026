"""
seed_demo.py
Dedicated, idempotent demo scenario seed script for DeepTrust stall presentation.
Only seeds exactly TWO labelled demo records with is_demo: True.
"""

import time
from datetime import datetime, timezone
from pymongo import MongoClient

MONGODB_URI = "mongodb://localhost:27017/"
DATABASE_NAME = "deeptrust"

def seed_demo_scenarios():
    print(f"[DeepTrust Demo Seeder] Connecting to {MONGODB_URI} (db: {DATABASE_NAME})...")
    client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=3000)
    db = client[DATABASE_NAME]

    # Ensure demo user: Dr. Priya Raman
    db.users.update_one(
        {"email_normalized": "priya.raman@healthcare.demo"},
        {"$set": {
            "email": "priya.raman@healthcare.demo",
            "email_normalized": "priya.raman@healthcare.demo",
            "full_name": "Dr. Priya Raman",
            "role": "Doctor",
            "display_role": "Chief of Neurology",
            "department": "Neurology & Neurocritical Care",
            "organization_id": "HEALTHCARE_ORG_1",
            "organization_name": "Healthcare Organization",
            "status": "ACTIVE",
            "face_enrolled": True,
            "voice_enrolled": True,
            "mfa_enabled": True,
            "is_demo": True,
            "last_auth": time.time() - 900,
            "created_at": time.time() - 86400 * 10
        }},
        upsert=True
    )

    # 1. DEMO SCENARIO 1: Verified Multi-Factor Access
    demo_session_1 = "vs_demo_priya_raman_verified"
    db.verification_sessions.update_one(
        {"session_id": demo_session_1},
        {"$set": {
            "session_id": demo_session_1,
            "user_id": "priya.raman@healthcare.demo",
            "email": "priya.raman@healthcare.demo",
            "role": "Doctor",
            "organization_name": "Healthcare Organization",
            "credential_status": "VERIFIED",
            "face_status": "VERIFIED",
            "liveness_status": "VERIFIED",
            "voice_status": "VERIFIED",
            "mfa_status": "VERIFIED",
            "risk_status": "LOW",
            "final_decision": "ALLOWED",
            "is_demo": True,
            "created_at": time.time() - 900,
            "timestamp": datetime.fromtimestamp(time.time() - 900, timezone.utc).isoformat()
        }},
        upsert=True
    )

    db.audit_logs.update_one(
        {"event_id": "EVT-DEMO-001"},
        {"$set": {
            "event_id": "EVT-DEMO-001",
            "event_type": "ACCESS_ALLOWED",
            "user_id": "priya.raman@healthcare.demo",
            "email": "priya.raman@healthcare.demo",
            "organization_name": "Healthcare Organization",
            "action": "Multi-Factor Biometrics Verified (Face + Liveness + Voice + MFA)",
            "risk": "LOW",
            "is_demo": True,
            "details": {
                "face": "VERIFIED (Confidence 96.2%)",
                "liveness": "VERIFIED (Temporal Shift)",
                "voice": "VERIFIED (Energy Match 91.4%)",
                "mfa": "VERIFIED (TOTP RFC 6238)",
                "decision": "ALLOWED"
            },
            "timestamp": datetime.fromtimestamp(time.time() - 900, timezone.utc).isoformat(),
            "created_at": time.time() - 900
        }},
        upsert=True
    )

    # 2. DEMO SCENARIO 2: Blocked High-Risk Synthetic / Mismatch Attempt
    demo_session_2 = "vs_demo_unknown_blocked"
    db.verification_sessions.update_one(
        {"session_id": demo_session_2},
        {"$set": {
            "session_id": demo_session_2,
            "user_id": "unknown.attacker@external-node",
            "email": "unknown.attacker@external-node",
            "role": "Unknown",
            "organization_name": "Healthcare Organization",
            "credential_status": "FAILED",
            "face_status": "MISMATCH",
            "liveness_status": "FAILED",
            "voice_status": "FAILED",
            "mfa_status": "FAILED",
            "risk_status": "CRITICAL",
            "final_decision": "BLOCKED",
            "is_demo": True,
            "created_at": time.time() - 1800,
            "timestamp": datetime.fromtimestamp(time.time() - 1800, timezone.utc).isoformat()
        }},
        upsert=True
    )

    db.security_events.update_one(
        {"event_id": "SEC-DEMO-002"},
        {"$set": {
            "event_id": "SEC-DEMO-002",
            "event_type": "BLOCKED_ACCESS_ATTEMPT",
            "severity": "CRITICAL",
            "identity": "unknown.attacker@external-node",
            "organization_id": "HEALTHCARE_ORG_1",
            "organization_name": "Healthcare Organization",
            "description": "Zero-Trust policy issued instant BLOCK: Facial mismatch & active liveness injection failure.",
            "verification_chain": {
                "credentials": "FAILED",
                "face": "MISMATCH",
                "liveness": "FAILED",
                "voice": "UNREACHED",
                "mfa": "UNREACHED"
            },
            "risk_score": 98,
            "risk_level": "CRITICAL",
            "decision": "BLOCK",
            "reason_codes": ["FACE_MISMATCH", "LIVENESS_INJECTION_FAILED", "UNRECOGNIZED_SUBNET"],
            "status": "OPEN",
            "is_demo": True,
            "created_at": time.time() - 1800,
            "timestamp": datetime.fromtimestamp(time.time() - 1800, timezone.utc).isoformat()
        }},
        upsert=True
    )

    db.audit_logs.update_one(
        {"event_id": "EVT-DEMO-002"},
        {"$set": {
            "event_id": "EVT-DEMO-002",
            "event_type": "ACCESS_BLOCKED",
            "user_id": "unknown.attacker@external-node",
            "email": "unknown.attacker@external-node",
            "organization_name": "Healthcare Organization",
            "action": "Zero-Trust Policy Block: Biometric Face Mismatch & Liveness Failure",
            "risk": "CRITICAL",
            "is_demo": True,
            "details": {
                "risk_score": 98,
                "reason": "Biometric Spoof / Mismatch Detected",
                "decision": "BLOCKED"
            },
            "timestamp": datetime.fromtimestamp(time.time() - 1800, timezone.utc).isoformat(),
            "created_at": time.time() - 1800
        }},
        upsert=True
    )

    print("[DeepTrust Demo Seeder] Idempotent demo scenarios successfully seeded:")
    print("  1. Dr. Priya Raman (is_demo=True, decision=ALLOWED, risk=LOW)")
    print("  2. Unknown / Demo Attempt (is_demo=True, decision=BLOCKED, risk=CRITICAL)")

if __name__ == "__main__":
    seed_demo_scenarios()
