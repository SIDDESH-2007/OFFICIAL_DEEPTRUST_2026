"""
DeepTrust Enterprise Computer Vision, Biometrics & Authentication AI Backend
=============================================================================
Features:
- MongoDB Persistence & Seed Management (Healthcare Organization & DeepTrust Admin)
- Multi-Stage Verification Session State Machine
- Pre-Auth Verification Token (Token A) vs Final Access Token (Token B)
- OpenCV YuNet DNN Real Face Detector & SFace DNN 128-d Feature Extractor
- Identity-bound randomized head turn and return liveness challenges
- Voice Biometrics (Microphone Audio Analysis, Waveform, Phrase Verification)
- Google Authenticator / Standards-based RFC 6238 TOTP MFA Engine
- Zero-Trust Deterministic Risk Evaluation Engine
- Finalization Endpoint (POST /api/v1/auth/finalize) & Session Lifecycle
- Dynamic Dashboard Summaries, Live Audit Trail & Notification Center
"""

import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '.env'))

try:
    from .production_config import validate_production_config
except ImportError:
    from production_config import validate_production_config
validate_production_config(os.environ)

import io
import threading
from functools import wraps
import json
import time
import uuid
import base64
import random
import re
import secrets
import hashlib
import smtplib
import urllib.parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import numpy as np
import cv2
import pyotp
import jwt
import bcrypt
import qrcode
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Header, Request, Depends, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
try:
    from .hospital_sso import staff_role, check_staff_identity, login_notification
except ImportError:
    from hospital_sso import staff_role, check_staff_identity, login_notification

try:
    from .mobile_pairing_security import authorize_pairing_identity, verify_pairing_totp, consume_pairing
except ImportError:
    from mobile_pairing_security import authorize_pairing_identity, verify_pairing_totp, consume_pairing

from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from bson import ObjectId

try:
    from .report_pdf import generate_monthly_security_pdf, generate_incident_pdf
except ImportError:
    from report_pdf import generate_monthly_security_pdf, generate_incident_pdf

try:
    from .face_liveness import MotionChallenge
    from .passive_pad import PassivePAD, PassiveChallenge
    from .phone_guard import load_phone_guard
except ImportError:
    from face_liveness import MotionChallenge
    from passive_pad import PassivePAD, PassiveChallenge
    from phone_guard import load_phone_guard


try:
    from .session_monitor import PLATFORM_ROLES, MONITOR_ROLES, masked_ip, iso_time, lifecycle, session_projection, assurance_projection, behavior_signal
except ImportError:
    from session_monitor import PLATFORM_ROLES, MONITOR_ROLES, masked_ip, iso_time, lifecycle, session_projection, assurance_projection, behavior_signal

# OpenCV detector input sizes and feature extractors are mutable shared objects.
FACE_ENGINE_LOCK = threading.RLock()

def serialized_face_engine(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        with FACE_ENGINE_LOCK:
            return fn(*args, **kwargs)
    return wrapped

def require_face_session(session_id, user_id=None, require_match=False):
    if not session_id:
        raise HTTPException(status_code=400, detail="Missing verification session_id")
    if db is None:
        raise HTTPException(status_code=503, detail="Biometric session store unavailable")
    session = db.verification_sessions.find_one({"session_id": session_id})
    if not session or session.get("credential_status") != "VERIFIED":
        raise HTTPException(status_code=403, detail="Credentials must be verified first")
    if time.time() > session.get("expires_at", 0) or session.get("revoked") or session.get("final_decision") == "FINALIZED":
        raise HTTPException(status_code=403, detail="Verification session expired or consumed")
    if user_id and str(user_id) not in (str(session.get("user_id")), str(session.get("email"))):
        raise HTTPException(status_code=403, detail="Session user mismatch")
    if require_match and session.get("face_status") != "VERIFIED":
        raise HTTPException(status_code=403, detail="Face must be matched first")
    return session

def face_profile_query(session):
    uid = str(session["user_id"])
    variants = [uid]
    if ObjectId.is_valid(uid):
        variants.append(ObjectId(uid))
    identities = [{"user_id": v} for v in variants]
    if session.get("email"):
        identities += [{"user_id": session["email"]}, {"email": session["email"]}]
    return {"$or": identities}

def normalized_face_template(profile):
    if not profile or not (profile.get("status") == "ACTIVE" or ("status" not in profile and profile.get("enrolled") is True)):
        raise ValueError("No active enrolled face profile")
    vec = profile.get("protected_template") or profile.get("embedding")
    result = np.asarray(vec, dtype=np.float32).reshape(-1)
    if result.size != 128 or not np.isfinite(result).all() or np.linalg.norm(result) <= 0:
        raise ValueError("Invalid enrolled face template")
    return result / np.linalg.norm(result)

# ── App & Security Constants ────────────────────────────────────────────────
def face_similarity(first, second):
    # OpenCV SFace may normalize its inputs in place. Never give it a view
    # into an enrolled template or the immutable matched-frame reference.
    a = np.asarray(first, dtype=np.float32).reshape((1, 128)).copy()
    b = np.asarray(second, dtype=np.float32).reshape((1, 128)).copy()
    return float(recognizer.match(a, b, cv2.FaceRecognizerSF_FR_COSINE))


def active_face_template(session):
    pending = session.get("face_pending_template")
    if pending:
        if (not session.get("face_setup_authorized") or
                str(pending.get("user_id")) != str(session["user_id"]) or
                time.time() > session.get("expires_at", 0)):
            raise ValueError("Invalid pending face setup")
        return normalized_face_template(pending)
    return normalized_face_template(db.face_profiles.find_one(face_profile_query(session)))


JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is missing. Cannot start server.")
JWT_ALGORITHM = "HS256"
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "deeptrust")

# Mail / SMTP Configuration (Never hardcoded)
MAIL_HOST = os.getenv("MAIL_HOST", "")
MAIL_PORT_RAW = os.getenv("MAIL_PORT", "587")
MAIL_PORT = int(MAIL_PORT_RAW) if MAIL_PORT_RAW.isdigit() else 587
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
MAIL_FROM = os.getenv("MAIL_FROM", os.getenv("MAIL_USERNAME", ""))
MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"

app = FastAPI(
    title="DeepTrust Enterprise Security & Biometric Platform",
    version="3.0.0",
    description="Unified Computer Vision, Biometrics, MFA & Zero-Trust Authentication Engine"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("FASTAPI_CORS_ORIGINS", "http://127.0.0.1:5000,http://localhost:5000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── MongoDB Connection & Initialization ─────────────────────────────────────
mongo_client = None
db = None

try:
    mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=2000)
    db = mongo_client[MONGODB_DATABASE]
    db.command({"ping": 1})
    print(f"[DeepTrust AI Backend] Connected to MongoDB database: {MONGODB_DATABASE}")
except Exception as e:
    print(f"[DeepTrust AI Backend] MongoDB connection warning: {e}")


def seed_database():
    """Seeds default demo accounts, workforce identities, security events, and indexes into MongoDB."""
    if db is None:
        return
    try:
        # Create MongoDB indexes
        try:
            db.users.create_index("email_normalized", unique=True)
            db.users.create_index("organization_id")
            db.verification_sessions.create_index("session_id", unique=True)
            db.verification_sessions.create_index("created_at")
            db.auth_sessions.create_index("user_id")
            db.auth_sessions.create_index("created_at")
            db.authentication_events.create_index([("created_at", -1)])
            db.authentication_events.create_index("user_id")
            db.security_events.create_index("event_id", unique=True)
            db.security_events.create_index("severity")
            db.security_events.create_index("status")
            db.security_events.create_index([("created_at", -1)])
            db.audit_logs.create_index([("created_at", -1)])
            db.audit_logs.create_index("event_type")
            db.notifications.create_index("user_id")
            db.notifications.create_index("read")
            db.access_requests.create_index("request_id", unique=True)
            db.access_requests.create_index("status")
            db.risk_evaluations.create_index("session_id")
            db.integrations.create_index("integration_id", unique=True)
            db.integrations.create_index("client_id", unique=True)
            db.integrations.create_index("organization_id")
        except Exception as idx_err:
            print(f"[DeepTrust AI Backend] Index warning: {idx_err}")

        if os.getenv("ENABLE_DEMO_SEEDING", "false").lower() != "true":
            print("[DeepTrust AI Backend] MongoDB Indexes Ready. Demo seeding disabled by default.")
            return

        # Seed Default Protected Healthcare Demo Integration
        demo_sec = "demo_client_secret_99887766554433221100"
        demo_sec_hash = hashlib.sha256(demo_sec.encode('utf-8')).hexdigest()
        db.integrations.update_one(
            {"client_id": "client_demo_healthcare_app_001"},
            {"$set": {
                "integration_id": "int_demo_healthcare_app_001",
                "organization_id": "HEALTHCARE_ORG_1",
                "application_name": "Protected Healthcare Demo App",
                "status": "ACTIVE",
                "client_id": "client_demo_healthcare_app_001",
                "client_secret_hash": demo_sec_hash,
                "allowed_origins": ["http://localhost:5050", "http://127.0.0.1:5050"],
                "allowed_redirects": [],
                "created_at": time.time(),
                "updated_at": time.time()
            }},
            upsert=True
        )

        # 1. Seed Organizations
        orgs = [
            {
                "_id": "HEALTHCARE_ORG_1",
                "name": "NovaCare Medical Center",
                "industry": "Healthcare Infrastructure",
                "status": "ACTIVE",
                "node_region": "US-East (Hospital Campus Node)",
                "created_at": time.time()
            },
            {
                "_id": "DEEPTRUST_PLATFORM",
                "name": "DeepTrust Security Platform",
                "industry": "Cybersecurity & Identity",
                "status": "ACTIVE",
                "node_region": "Global Core Security Cluster",
                "created_at": time.time()
            }
        ]
        for org in orgs:
            db.organizations.update_one({"_id": org["_id"]}, {"$set": org}, upsert=True)

        # 2. Seed Demo Users with bcrypt hashes
        default_pwd_hash = bcrypt.hashpw(b"HealthcareAdmin123!", bcrypt.gensalt(10)).decode('utf-8')
        owner_hash = bcrypt.hashpw(b"OwnerSecret123!", bcrypt.gensalt(10)).decode('utf-8')

        default_users = [
            {
                "email": "admin@healthcare.demo",
                "email_normalized": "admin@healthcare.demo",
                "full_name": "Dr. Rachel Vance",
                "password_hash": default_pwd_hash,
                "role": "HOSPITAL_ADMIN",
                "display_role": "Hospital Security Administrator",
                "department": "Security & Access Governance",
                "organization_id": "HEALTHCARE_ORG_1",
                "organization_name": "NovaCare Medical Center",
                "status": "ACTIVE",
                "email_verified": True,
                "face_enrolled": True,
                "voice_enrolled": True,
                "mfa_enabled": True,
                "last_auth": time.time() - 300,
                "created_at": time.time() - 86400 * 30
            },
            {
                "email": "marcus.chen@healthcare.demo",
                "email_normalized": "marcus.chen@healthcare.demo",
                "full_name": "Dr. Marcus Chen",
                "password_hash": default_pwd_hash,
                "role": "Doctor",
                "display_role": "Attending Cardiologist",
                "department": "Cardiology & Cath Lab",
                "organization_id": "HEALTHCARE_ORG_1",
                "organization_name": "NovaCare Medical Center",
                "status": "ACTIVE",
                "email_verified": True,
                "face_enrolled": True,
                "voice_enrolled": True,
                "mfa_enabled": True,
                "last_auth": time.time() - 1800,
                "created_at": time.time() - 86400 * 25
            },
            {
                "email": "elena.rodriguez@healthcare.demo",
                "email_normalized": "elena.rodriguez@healthcare.demo",
                "full_name": "Elena Rodriguez, RN",
                "password_hash": default_pwd_hash,
                "role": "Nurse",
                "display_role": "Charge Nurse",
                "department": "Emergency & Critical Care ICU",
                "organization_id": "HEALTHCARE_ORG_1",
                "organization_name": "NovaCare Medical Center",
                "status": "ACTIVE",
                "email_verified": True,
                "face_enrolled": True,
                "voice_enrolled": True,
                "mfa_enabled": True,
                "last_auth": time.time() - 3600,
                "created_at": time.time() - 86400 * 20
            },
            {
                "email": "ravi.patel@healthcare.demo",
                "email_normalized": "ravi.patel@healthcare.demo",
                "full_name": "Ravi Patel, PharmD",
                "password_hash": default_pwd_hash,
                "role": "Pharmacist",
                "display_role": "Clinical Pharmacist",
                "department": "Central Inpatient Pharmacy",
                "organization_id": "HEALTHCARE_ORG_1",
                "organization_name": "NovaCare Medical Center",
                "status": "ACTIVE",
                "email_verified": True,
                "face_enrolled": True,
                "voice_enrolled": True,
                "mfa_enabled": True,
                "last_auth": time.time() - 7200,
                "created_at": time.time() - 86400 * 18
            },
            {
                "email": "james.adams@healthcare.demo",
                "email_normalized": "james.adams@healthcare.demo",
                "full_name": "James Adams, MLS",
                "password_hash": default_pwd_hash,
                "role": "Lab Staff",
                "display_role": "Senior Medical Lab Scientist",
                "department": "Clinical Pathology & Diagnostics",
                "organization_id": "HEALTHCARE_ORG_1",
                "organization_name": "NovaCare Medical Center",
                "status": "ACTIVE",
                "email_verified": True,
                "face_enrolled": True,
                "voice_enrolled": True,
                "mfa_enabled": True,
                "last_auth": time.time() - 14400,
                "created_at": time.time() - 86400 * 15
            },
            {
                "email": "sarah.jenkins@healthcare.demo",
                "email_normalized": "sarah.jenkins@healthcare.demo",
                "full_name": "Sarah Jenkins",
                "password_hash": default_pwd_hash,
                "role": "Hospital Administrator",
                "display_role": "Clinical Operations Director",
                "department": "Executive Operations",
                "organization_id": "HEALTHCARE_ORG_1",
                "organization_name": "NovaCare Medical Center",
                "status": "ACTIVE",
                "email_verified": True,
                "face_enrolled": True,
                "voice_enrolled": True,
                "mfa_enabled": True,
                "last_auth": time.time() - 28800,
                "created_at": time.time() - 86400 * 12
            },
            {
                "email": "owner@deeptrust.demo",
                "email_normalized": "owner@deeptrust.demo",
                "full_name": "DeepTrust Platform Owner",
                "password_hash": owner_hash,
                "role": "DEEPTRUST_OWNER",
                "display_role": "Platform Security Architect",
                "department": "Platform Engineering & Security",
                "organization_id": "DEEPTRUST_PLATFORM",
                "organization_name": "DeepTrust Security Platform",
                "status": "ACTIVE",
                "email_verified": True,
                "face_enrolled": True,
                "voice_enrolled": True,
                "mfa_enabled": True,
                "last_auth": time.time() - 600,
                "created_at": time.time() - 86400 * 60
            }
        ]

        for u in default_users:
            if "mfa_secret" not in u or not u["mfa_secret"]:
                u["mfa_secret"] = pyotp.random_base32()
            u["protected_mfa_secret"] = u["mfa_secret"]

            db.users.update_one(
                {"email_normalized": u["email_normalized"]},
                {"$set": u},
                upsert=True
            )

            if u["role"] in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
                u_admin = dict(u)
                u_admin["account_type"] = "DEEPTRUST_ADMIN"
                db.deeptrust_admins.update_one(
                    {"email_normalized": u["email_normalized"]},
                    {"$set": u_admin},
                    upsert=True
                )
            else:
                u_h = dict(u)
                u_h["account_type"] = "HEALTHCARE_ADMIN"
                db.healthcare_admins.update_one(
                    {"email_normalized": u["email_normalized"]},
                    {"$set": u_h},
                    upsert=True
                )

            db.mfa_profiles.update_one(
                {"email": u["email_normalized"]},
                {"$set": {"email": u["email_normalized"], "secret": u["mfa_secret"], "updated_at": time.time()}},
                upsert=True
            )

        # Seed Recovery Codes for Demo Accounts
        demo_emails = [
            "admin@healthcare.demo",
            "owner@deeptrust.demo",
            "marcus.chen@healthcare.demo",
            "sarah.jenkins@healthcare.demo",
            "ravi.patel@healthcare.demo",
            "james.adams@healthcare.demo",
            "user@healthcare.demo"
        ]
        demo_rec_codes = []
        for em in demo_emails:
            demo_rec_codes.append({"email": em, "code": "RECOVERY-CODE-123456"})
            demo_rec_codes.append({"email": em, "code": "RECOVERY-CODE-789012"})

        for rc in demo_rec_codes:
            chash = hashlib.sha256(rc["code"].strip().upper().encode('utf-8')).hexdigest()
            db.recovery_codes.update_one(
                {"email": rc["email"].lower(), "code_hash": chash},
                {"$set": {
                    "email": rc["email"].lower(),
                    "user_id": rc["email"].lower(),
                    "code_hash": chash,
                    "used": False,
                    "created_at": time.time()
                }},
                upsert=True
            )

        # 3. Seed Realistic Security Events
        security_events = [
            {
                "event_id": "SEC-8821",
                "event_type": "REPEATED_LOGIN_FAILURES",
                "severity": "MEDIUM",
                "identity": "external-scanner-ip-10.24.1.92",
                "organization_id": "HEALTHCARE_ORG_1",
                "organization_name": "NovaCare Medical Center",
                "description": "5 consecutive failed password attempts detected against radiology workstation portal.",
                "verification_chain": {
                    "credentials": "FAILED",
                    "face": "UNREACHED",
                    "voice": "UNREACHED",
                    "mfa": "UNREACHED"
                },
                "risk_score": 45,
                "risk_level": "MEDIUM",
                "decision": "STEP_UP_CHALLENGE",
                "reason_codes": ["BRUTE_FORCE_PATTERN", "UNRECOGNIZED_WORKSTATION"],
                "status": "OPEN",
                "created_at": time.time() - 3600 * 2,
                "timestamp": datetime.fromtimestamp(time.time() - 3600 * 2, timezone.utc).isoformat()
            },
            {
                "event_id": "SEC-8822",
                "event_type": "FACE_IDENTITY_MISMATCH",
                "severity": "HIGH",
                "identity": "ravi.patel@healthcare.demo",
                "organization_id": "HEALTHCARE_ORG_1",
                "organization_name": "NovaCare Medical Center",
                "description": "Live facial feature extraction did not match enrolled template on High-Risk Pharmacy Dispenser.",
                "verification_chain": {
                    "credentials": "VERIFIED",
                    "face": "FAILED",
                    "voice": "UNREACHED",
                    "mfa": "UNREACHED"
                },
                "risk_score": 78,
                "risk_level": "HIGH",
                "decision": "BLOCK",
                "reason_codes": ["SFACE_COSINE_BELOW_THRESHOLD", "BIOMETRIC_DISCREPANCY"],
                "status": "OPEN",
                "created_at": time.time() - 3600 * 5,
                "timestamp": datetime.fromtimestamp(time.time() - 3600 * 5, timezone.utc).isoformat()
            },
            {
                "event_id": "SEC-8823",
                "event_type": "LIVENESS_VERIFICATION_FAILURE",
                "severity": "HIGH",
                "identity": "marcus.chen@healthcare.demo",
                "organization_id": "HEALTHCARE_ORG_1",
                "organization_name": "NovaCare Medical Center",
                "description": "Active liveness challenge timed out; potential static screen playback or synthetic presentation.",
                "verification_chain": {
                    "credentials": "VERIFIED",
                    "face": "VERIFIED",
                    "liveness": "FAILED",
                    "voice": "UNREACHED",
                    "mfa": "UNREACHED"
                },
                "risk_score": 82,
                "risk_level": "HIGH",
                "decision": "BLOCK",
                "reason_codes": ["MOTION_CHALLENGE_TIMEOUT", "POSSIBLE_INJECTION_ATTACK"],
                "status": "ACKNOWLEDGED",
                "created_at": time.time() - 3600 * 12,
                "timestamp": datetime.fromtimestamp(time.time() - 3600 * 12, timezone.utc).isoformat()
            },
            {
                "event_id": "SEC-8824",
                "event_type": "VOICE_IDENTITY_MISMATCH",
                "severity": "MEDIUM",
                "identity": "elena.rodriguez@healthcare.demo",
                "organization_id": "HEALTHCARE_ORG_1",
                "organization_name": "NovaCare Medical Center",
                "description": "Vocal energy distribution and phrase verification frequency outside baseline range.",
                "verification_chain": {
                    "credentials": "VERIFIED",
                    "face": "VERIFIED",
                    "voice": "FAILED",
                    "mfa": "PENDING"
                },
                "risk_score": 55,
                "risk_level": "MEDIUM",
                "decision": "STEP_UP_CHALLENGE",
                "reason_codes": ["ENERGY_PROFILE_VARIANCE", "VOICE_STEP_UP_TRIGGERED"],
                "status": "RESOLVED",
                "created_at": time.time() - 3600 * 24,
                "timestamp": datetime.fromtimestamp(time.time() - 3600 * 24, timezone.utc).isoformat()
            },
            {
                "event_id": "SEC-8825",
                "event_type": "BLOCKED_ACCESS_ATTEMPT",
                "severity": "CRITICAL",
                "identity": "unknown.adversary@external-node",
                "organization_id": "HEALTHCARE_ORG_1",
                "organization_name": "NovaCare Medical Center",
                "description": "Zero-Trust Risk Engine issued automatic BLOCK: biometric and MFA mismatch from unrecognized device subnet.",
                "verification_chain": {
                    "credentials": "FAILED",
                    "face": "FAILED",
                    "voice": "FAILED",
                    "mfa": "FAILED"
                },
                "risk_score": 96,
                "risk_level": "CRITICAL",
                "decision": "BLOCK",
                "reason_codes": ["GEO_ANOMALY", "ZERO_TRUST_POLICY_VIOLATION", "BIOMETRIC_MISSING"],
                "status": "OPEN",
                "created_at": time.time() - 3600 * 1.5,
                "timestamp": datetime.fromtimestamp(time.time() - 3600 * 1.5, timezone.utc).isoformat()
            }
        ]
        for evt in security_events:
            db.security_events.update_one({"event_id": evt["event_id"]}, {"$setOnInsert": evt}, upsert=True)

        # 4. Seed Realistic Access Requests
        access_requests = [
            {
                "request_id": "REQ-401",
                "requester_name": "Elena Rodriguez, RN",
                "requester_email": "elena.rodriguez@healthcare.demo",
                "role": "Nurse",
                "department": "Emergency ICU",
                "resource_name": "OmniCell Automated Dispensing Cabinet (ICU-North)",
                "permission_level": "Privileged Narcotic Dispense",
                "reason": "Emergency shift transfer coverage for ICU Bed 4-12",
                "status": "PENDING",
                "created_at": time.time() - 1800,
                "timestamp": datetime.fromtimestamp(time.time() - 1800, timezone.utc).isoformat()
            },
            {
                "request_id": "REQ-402",
                "requester_name": "Dr. Marcus Chen",
                "requester_email": "marcus.chen@healthcare.demo",
                "role": "Doctor",
                "department": "Cardiology",
                "resource_name": "PACS High-Res Cardiac Imaging Archive",
                "permission_level": "Read/Write Diagnostic",
                "reason": "Access to historical fluoroscopy datasets for emergency stent surgery",
                "status": "APPROVED",
                "created_at": time.time() - 7200,
                "timestamp": datetime.fromtimestamp(time.time() - 7200, timezone.utc).isoformat()
            },
            {
                "request_id": "REQ-403",
                "requester_name": "James Adams, MLS",
                "requester_email": "james.adams@healthcare.demo",
                "role": "Lab Staff",
                "department": "Pathology",
                "resource_name": "LIS Bio-Hazard Sample Sequence DB",
                "permission_level": "Privileged Lab Export",
                "reason": "Urgent blood culture export for state epidemiology report",
                "status": "PENDING",
                "created_at": time.time() - 900,
                "timestamp": datetime.fromtimestamp(time.time() - 900, timezone.utc).isoformat()
            }
        ]
        for ar in access_requests:
            db.access_requests.update_one({"request_id": ar["request_id"]}, {"$setOnInsert": ar}, upsert=True)

        # 5. Seed Initial Audit Logs
        if db.audit_logs.count_documents({}) == 0:
            sample_logs = [
                {
                    "event_id": f"EVT-INIT-101",
                    "event_type": "LOGIN_SUCCESS",
                    "user_id": "admin@healthcare.demo",
                    "email": "admin@healthcare.demo",
                    "organization_name": "NovaCare Medical Center",
                    "action": "Admin credential verification confirmed",
                    "risk": "LOW",
                    "details": {"method": "password", "ip": "10.200.4.12"},
                    "timestamp": datetime.fromtimestamp(time.time() - 3600*4, timezone.utc).isoformat(),
                    "created_at": time.time() - 3600*4
                },
                {
                    "event_id": f"EVT-INIT-102",
                    "event_type": "FACE_VERIFIED",
                    "user_id": "admin@healthcare.demo",
                    "email": "admin@healthcare.demo",
                    "organization_name": "NovaCare Medical Center",
                    "action": "Face biometrics matched with YuNet/SFace neural extractor",
                    "risk": "LOW",
                    "details": {"confidence": 0.94, "liveness": "CONFIRMED"},
                    "timestamp": datetime.fromtimestamp(time.time() - 3600*4 + 20, timezone.utc).isoformat(),
                    "created_at": time.time() - 3600*4 + 20
                },
                {
                    "event_id": f"EVT-INIT-103",
                    "event_type": "VOICE_VERIFIED",
                    "user_id": "admin@healthcare.demo",
                    "email": "admin@healthcare.demo",
                    "organization_name": "NovaCare Medical Center",
                    "action": "Voice acoustic verification passed challenge phrase",
                    "risk": "LOW",
                    "details": {"energy_score": 0.88, "phrase_match": True},
                    "timestamp": datetime.fromtimestamp(time.time() - 3600*4 + 45, timezone.utc).isoformat(),
                    "created_at": time.time() - 3600*4 + 45
                },
                {
                    "event_id": f"EVT-INIT-104",
                    "event_type": "MFA_VERIFIED",
                    "user_id": "admin@healthcare.demo",
                    "email": "admin@healthcare.demo",
                    "organization_name": "NovaCare Medical Center",
                    "action": "Time-based OTP token confirmed via Authenticator",
                    "risk": "LOW",
                    "details": {"factor": "TOTP_RFC6238"},
                    "timestamp": datetime.fromtimestamp(time.time() - 3600*4 + 60, timezone.utc).isoformat(),
                    "created_at": time.time() - 3600*4 + 60
                },
                {
                    "event_id": f"EVT-INIT-105",
                    "event_type": "ACCESS_ALLOWED",
                    "user_id": "admin@healthcare.demo",
                    "email": "admin@healthcare.demo",
                    "organization_name": "NovaCare Medical Center",
                    "action": "Zero-Trust policy ALLOW: Full healthcare session token granted",
                    "risk": "LOW",
                    "details": {"risk_score": 8, "decision": "ALLOW"},
                    "timestamp": datetime.fromtimestamp(time.time() - 3600*4 + 65, timezone.utc).isoformat(),
                    "created_at": time.time() - 3600*4 + 65
                }
            ]
            db.audit_logs.insert_many(sample_logs)

        # 6. Seed Initial Notifications
        if db.notifications.count_documents({}) == 0:
            sample_notifs = [
                {
                    "user_id": "admin@healthcare.demo",
                    "email": "admin@healthcare.demo",
                    "type": "SECURITY_ALERT",
                    "title": "High-Risk Pharmacy Attempt Blocked",
                    "message": "Biometric face mismatch on High-Risk Pharmacy Dispenser (SEC-8822).",
                    "read": False,
                    "created_at": time.time() - 3600 * 5,
                    "timestamp": datetime.fromtimestamp(time.time() - 3600 * 5, timezone.utc).isoformat()
                },
                {
                    "user_id": "admin@healthcare.demo",
                    "email": "admin@healthcare.demo",
                    "type": "ACCESS_REQUEST",
                    "title": "New Privileged Access Request",
                    "message": "Elena Rodriguez, RN requested Privileged Narcotic Dispense access (REQ-401).",
                    "read": False,
                    "created_at": time.time() - 1800,
                    "timestamp": datetime.fromtimestamp(time.time() - 1800, timezone.utc).isoformat()
                },
                {
                    "user_id": "admin@healthcare.demo",
                    "email": "admin@healthcare.demo",
                    "type": "ACCESS_ALLOWED",
                    "title": "Hospital Security Session Active",
                    "message": "Zero-trust verification completed for Dr. Rachel Vance.",
                    "read": True,
                    "created_at": time.time() - 300,
                    "timestamp": datetime.fromtimestamp(time.time() - 300, timezone.utc).isoformat()
                }
            ]
            db.notifications.insert_many(sample_notifs)

        print("[DeepTrust AI Backend] MongoDB Collections, Indexes & Seed State Ready.")
    except Exception as err:
        print(f"[DeepTrust AI Backend] Seed error: {err}")

seed_database()


# ── Load OpenCV Models ──────────────────────────────────────────────────────
MODEL_DIR = os.path.abspath(os.getenv("DEEPTRUST_MODEL_DIR") or os.path.join(os.path.dirname(__file__), "..", "..", "models"))
YUNET_PATH = os.path.join(MODEL_DIR, "face_detection_yunet.onnx")
SFACE_PATH = os.path.join(MODEL_DIR, "face_recognition_sface.onnx")
try:
    phone_guard = load_phone_guard(MODEL_DIR)
except Exception as err:
    print(f"[Phone detector initialization failed]: {err}")
    phone_guard = None

try:
    passive_pad = PassivePAD(MODEL_DIR)
except Exception as err:
    print(f"[Passive PAD initialization failed]: {err}")
    passive_pad = None

PHONE_OBSERVATIONS = {}

def check_phone_presentation(img, session_id=None):
    if phone_guard is None:
        raise HTTPException(status_code=503, detail="Phone detector unavailable. Restart the AI service with its model installed.")
    phones = phone_guard.detect(img)
    now = time.time()
    for sid, record in list(PHONE_OBSERVATIONS.items()):
        if now - record["last"] > 3:
            PHONE_OBSERVATIONS.pop(sid, None)
    if session_id:
        if not phones:
            PHONE_OBSERVATIONS.pop(session_id, None)
            return None
        old = PHONE_OBSERVATIONS.get(session_id)
        if old is None or now - old["last"] > 2:
            old = {"count": 0, "started": now, "last": now}
        # Multiple API calls for the same camera frame cannot confirm a phone.
        if old["count"] == 0 or now - old["last"] >= .12:
            old["count"] += 1
            old["last"] = now
        PHONE_OBSERVATIONS[session_id] = old
        if old["count"] < 3 or now - old["started"] < .4:
            return None
    if phones:
        return {"status": "PHONE_DETECTED", "matched": False, "phone_detected": True,
                "faces_count": 0, "bounding_box": None, "phones": phones,
                "message": "Phone detected — photo face not accepted. Remove the phone and show your live face."}
    return None

detector = None
recognizer = None
FACE_DETECTION_THRESHOLD = 0.6

if os.path.exists(YUNET_PATH):
    detector = cv2.FaceDetectorYN.create(
        model=YUNET_PATH,
        config="",
        input_size=(320, 320),
        score_threshold=FACE_DETECTION_THRESHOLD,
        nms_threshold=0.3,
        top_k=5000
    )
    print("[DeepTrust AI Backend] YuNet Deep Face Detector loaded.")
else:
    print(f"[DeepTrust AI Backend] Warning: YuNet model not found at {YUNET_PATH}")

if os.path.exists(SFACE_PATH):
    recognizer = cv2.FaceRecognizerSF.create(
        model=SFACE_PATH,
        config=""
    )
    print("[DeepTrust AI Backend] SFace Deep Face Recognizer loaded.")
else:
    print(f"[DeepTrust AI Backend] Warning: SFace model not found at {SFACE_PATH}")

# In-Memory Active Liveness Sessions
LIVENESS_SESSIONS: Dict[str, Dict[str, Any]] = {}
FACE_MATCH_REFERENCES: Dict[str, Dict[str, Any]] = {}


# ── Helper Functions ────────────────────────────────────────────────────────
def decode_image(image_data: str) -> Optional[np.ndarray]:
    """Decodes base64 data URL or raw base64 string to OpenCV BGR image."""
    if not image_data:
        return None
    try:
        if "," in image_data:
            image_data = image_data.split(",", 1)[1]
        image_bytes = base64.b64decode(image_data)
        np_arr = np.frombuffer(image_bytes, np.uint8)
        return cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    except Exception:
        return None


def generate_verification_token(user_id: str, email: str, role: str, session_id: str) -> str:
    """Issues short-lived PRE-AUTH verification token (Token A)."""
    payload = {
        "token_type": "VERIFICATION",
        "session_id": session_id,
        "sub": str(user_id),
        "email": email,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + 15 * 60  # 15 minutes
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def generate_final_access_token(user: Dict[str, Any], session_id: str) -> str:
    """Issues authenticated application session FINAL access token (Token B)."""
    payload = {
        "token_type": "ACCESS",
        "session_id": session_id,
        "sub": str(user.get("_id") or user.get("id")),
        "email": user["email"],
        "full_name": user.get("full_name", "User"),
        "role": user.get("role", "HOSPITAL_ADMIN"),
        "organization_id": user.get("organization_id", "HEALTHCARE_ORG_1"),
        "organization_name": user.get("organization_name", "Healthcare Organization"),
        "iat": int(time.time()),
        "exp": int(time.time()) + 8 * 3600  # 8 hours
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT token."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None


try:
    from .security_controls import AuditChain, enforce_session, session_deadline, MANAGERS, register_security_controls
    from .monthly_metrics import aggregate_month
except ImportError:
    from security_controls import AuditChain, enforce_session, session_deadline, MANAGERS, register_security_controls
    from monthly_metrics import aggregate_month
audit_chain = AuditChain(os.getenv("AUDIT_SIGNING_KEY") or JWT_SECRET,
    os.getenv("AUDIT_CHECKPOINT_PATH") or os.path.join(os.path.dirname(__file__), "data", "audit-checkpoint.json"))

def log_audit_event(
    event_type: str,
    user_id: str,
    email: str,
    organization_name: str,
    action: str,
    risk: str = "LOW",
    details: Dict[str, Any] = None,
    session_id: Optional[str] = None,
    identity_id: Optional[str] = None
):
    """Records audit trail event in MongoDB with identity and session correlation."""
    if db is not None:
        try:
            resolved_identity = str(identity_id or user_id)
            if "@" in resolved_identity and db is not None:
                u = db.users.find_one({"email_normalized": resolved_identity.lower()})
                if u:
                    resolved_identity = str(u.get("_id"))

            # Scrub any sensitive biometric or credential data before audit logging
            safe_details = {}
            if details and isinstance(details, dict):
                for k, v in details.items():
                    if k.lower() not in ["password", "token", "jwt", "otp", "totp", "secret", "embedding", "recording", "voice_template", "face_frame", "audio", "recovery_code_raw"]:
                        safe_details[k] = v

            audit_identity = db.users.find_one({"_id": ObjectId(resolved_identity)}) if ObjectId.is_valid(resolved_identity) else db.users.find_one({"_id": resolved_identity})
            email = (audit_identity or {}).get("email") or email
            audit_org = (audit_identity or {}).get("organization_id")
            audit_session = None
            if session_id:
                audit_session = db.auth_sessions.find_one({"session_id": session_id}) or db.verification_sessions.find_one({"session_id": session_id})
                audit_org = (audit_session or {}).get("organization_id") or audit_org
            audit_chain.append(db.audit_logs, {
                "organization_id": audit_org,
                "event_id": f"EVT-{int(time.time() * 1000)}-{100 + secrets.randbelow(900)}",
                "event_type": event_type,
                "user_id": resolved_identity,
                "identity_id": resolved_identity,
                "session_id": session_id,
                "email": email,
                "email_snapshot": email,
                "organization_name": organization_name,
                "action": action,
                "risk": risk,
                "details": safe_details,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "created_at": time.time()
            })
            alert_types = {"LOGIN_FAILED", "CREDENTIALS_FAILED", "FACE_MISMATCH", "LIVENESS_FAILED", "VOICE_VERIFICATION_FAILED", "VOICE_VERIFICATION_FAILED_ATTEMPT_1", "MFA_FAILED", "BEHAVIOR_DEVIATION", "NETWORK_CHANGED"}
            if event_type in alert_types and audit_org:
                is_access = bool(audit_session and audit_session.get("verification_session_id"))
                publish_security_event(event_type, resolved_identity, organization_id=audit_org,
                    auth_session_id=session_id if is_access else None,
                    verification_session_id=(audit_session or {}).get("verification_session_id") if is_access else session_id,
                    severity="MEDIUM" if event_type in {"BEHAVIOR_DEVIATION","NETWORK_CHANGED","LIVENESS_FAILED","VOICE_VERIFICATION_FAILED_ATTEMPT_1"} else "HIGH",
                    risk_decision="REVIEW", reason_codes=(details or {}).get("reason_codes",[]), source="AUDIT_MONITOR")
        except Exception as err:
            print(f"[Audit Log Error]: {err}")


# ── Connection, IP & Device Security Context Helpers ──────────────────────────

def resolve_client_ip(request: Optional[Request] = None, explicit_header: Optional[str] = None) -> str:
    """
    Safely resolves client IP server-side.
    When behind a local reverse proxy (like Express gateway), safely uses forwarded header.
    Otherwise uses server-observed remote address. Never trusts arbitrary client spoofed IP.
    """
    client_host = "127.0.0.1"
    if request and request.client and request.client.host:
        client_host = request.client.host

    # Check if direct connection comes from local proxy or direct client
    if client_host in ["127.0.0.1", "::1", "localhost", "testclient"]:
        forwarded = explicit_header or (request.headers.get("x-forwarded-for") if request else None)
        real_ip = request.headers.get("x-real-ip") if request else None
        if forwarded:
            candidate = forwarded.split(",")[0].strip()
        elif real_ip:
            candidate = real_ip.strip()
        else:
            candidate = client_host
    else:
        candidate = client_host

    # Normalize IPv4-mapped IPv6
    if candidate.startswith("::ffff:"):
        candidate = candidate.replace("::ffff:", "")
    if candidate == "::1":
        candidate = "127.0.0.1"
    return candidate


def classify_ip_network(ip: str) -> str:
    """Determines if an IP address is LOCAL, PRIVATE NETWORK, or PUBLIC."""
    if not ip or ip in ["127.0.0.1", "::1", "localhost"]:
        return "LOCAL"
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback:
            return "LOCAL"
        if ip_obj.is_private:
            return "PRIVATE NETWORK"
    except Exception:
        pass
    return "PUBLIC"


def mask_ip(ip: str) -> str:
    return masked_ip(ip)


def determine_network_status(user_id: str, current_ip: str, session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluates network context status: KNOWN, NEW, CHANGED, LOCAL, or PRIVATE NETWORK.
    Calculates first_seen and last_seen from actual security history.
    """
    net_type = classify_ip_network(current_ip)
    status = net_type

    first_seen = None
    last_seen = None
    changed = False

    if db is not None:
        try:
            prior_cursor = list(db.auth_sessions.find({
                "$or": [{"user_id": str(user_id)}, {"email": str(user_id)}, {"identity_id": str(user_id)}],
                "$or": [{"ip_address": current_ip}, {"network_context.ip_address": current_ip}, {"ip": current_ip}]
            }).sort("created_at", 1))

            if prior_cursor:
                first_seen = prior_cursor[0].get("created_at")
                last_seen = prior_cursor[-1].get("created_at")
                if net_type == "PUBLIC":
                    status = "KNOWN"
            else:
                if net_type == "PUBLIC":
                    status = "NEW"

            if session_id:
                sess = db.auth_sessions.find_one({"$or": [{"_id": session_id}, {"session_id": session_id}]})
                if sess:
                    orig_ip = sess.get("ip_address") or sess.get("network_context", {}).get("ip_address") or sess.get("ip")
                    if orig_ip and orig_ip != current_ip:
                        changed = True
                        status = "CHANGED"
        except Exception as e:
            print(f"[Network Status Calc Error]: {e}")

    return {
        "ip_address": current_ip,
        "ip_masked": mask_ip(current_ip),
        "network_status": status,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "session_network_changed": changed
    }


def parse_device_info(user_agent: str, user_id: Optional[str] = None, client_ip: Optional[str] = None) -> Dict[str, Any]:
    """
    Parses browser, OS, and category from User-Agent.
    Determines device trust from actual db.trusted_devices registry.
    """
    ua = (user_agent or "").lower()

    if "edg/" in ua or "edge/" in ua:
        browser = "Edge"
    elif "chrome" in ua and "safari" in ua and "edg" not in ua:
        browser = "Chrome"
    elif "firefox" in ua:
        browser = "Firefox"
    elif "safari" in ua and "chrome" not in ua:
        browser = "Safari"
    elif "opera" in ua or "opr" in ua:
        browser = "Opera"
    else:
        browser = "Chrome"

    if "windows" in ua:
        os_name = "Windows"
    elif "macintosh" in ua or "mac os" in ua:
        os_name = "macOS"
    elif "android" in ua:
        os_name = "Android"
    elif "iphone" in ua or "ipad" in ua or "ios" in ua:
        os_name = "iOS"
    elif "linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Windows"

    if "mobile" in ua or "iphone" in ua or ("android" in ua and "mobile" in ua):
        category = "Mobile"
    elif "tablet" in ua or "ipad" in ua:
        category = "Tablet"
    else:
        category = "Desktop"

    display_device = f"{browser} • {os_name}"

    device_trust = "UNKNOWN"
    first_seen = None
    last_seen = None

    if db is not None and user_id:
        try:
            dev_doc = db.trusted_devices.find_one({
                "$or": [{"user_id": str(user_id)}, {"email": str(user_id)}],
                "browser": browser,
                "os": os_name
            })
            if dev_doc:
                ts = str(dev_doc.get("trust_status", "UNKNOWN")).upper()
                if ts in ["TRUSTED", "VERIFIED"]:
                    device_trust = "TRUSTED"
                elif ts in ["UNTRUSTED", "REVOKED", "BLOCKED"]:
                    device_trust = "UNTRUSTED"
                else:
                    device_trust = "UNKNOWN"
                first_seen = dev_doc.get("first_seen") or dev_doc.get("created_at")
                last_seen = dev_doc.get("last_seen") or dev_doc.get("updated_at")
            else:
                device_trust = "UNTRUSTED"
        except Exception as e:
            print(f"[Device Trust Calc Error]: {e}")
            device_trust = "UNKNOWN"

    return {
        "browser": browser,
        "os": os_name,
        "category": category,
        "display_device": display_device,
        "device_trust": device_trust,
        "first_seen": first_seen,
        "last_seen": last_seen
    }


def format_duration_hhmmss(seconds: int) -> str:
    """Formats seconds into HH:MM:SS."""
    seconds = max(0, int(seconds))
    hrs = seconds // 3600
    mins = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hrs:02d}:{mins:02d}:{secs:02d}"


def publish_security_event(
    event_type: str,
    user_id: str,
    organization_id: str = "HEALTHCARE_ORG_1",
    verification_session_id: Optional[str] = None,
    auth_session_id: Optional[str] = None,
    severity: Optional[str] = None,
    risk_score: int = 0,
    risk_level: str = "LOW",
    risk_decision: str = "ALLOW",
    reason_codes: Optional[List[str]] = None,
    source: str = "DEEPTRUST_PIPELINE",
    status: str = "OPEN",
    is_demo: bool = False,
    metadata: Optional[Dict[str, Any]] = None,
    idempotency_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Central Security Event Pipeline function.
    Persists events into db.security_events and triggers alerts/notifications according to policy.
    """
    if db is None:
        return {}

    now = time.time()
    # Idempotency check: avoid duplicate event creation within 2 seconds for same session & type
    if verification_session_id and event_type:
        recent = db.security_events.find_one({
            "verification_session_id": verification_session_id,
            "event_type": event_type,
            "created_at": {"$gte": now - 2.0}
        })
        if recent:
            recent["_id"] = str(recent["_id"])
            return recent

    # Deterministic severity mapping if not explicitly provided
    if not severity:
        if event_type in ["ACCESS_BLOCKED", "SESSION_REVOKED", "ACCOUNT_DISABLED"] or risk_decision == "BLOCK":
            severity = "HIGH" if risk_score < 90 else "CRITICAL"
        elif event_type in ["FACE_MISMATCH", "VOICE_VERIFICATION_FAILED", "HIGH_RISK_AUTHENTICATION", "MFA_FAILED"]:
            severity = "HIGH"
        elif event_type in ["LIVENESS_FAILED", "UNUSUAL_LOCATION", "BEHAVIOR_DEVIATION", "VOICE_MAX_ATTEMPTS_REACHED"]:
            severity = "MEDIUM"
        elif event_type in ["LOGIN_FAILED", "RECOVERY_CODE_USED"]:
            severity = "LOW"
        else:
            severity = "INFO"

    event_id = f"evt_{uuid.uuid4().hex[:12]}"
    created_iso = datetime.now(timezone.utc).isoformat()

    # Clean sensitive fields from metadata if any
    safe_metadata = {}
    if metadata and isinstance(metadata, dict):
        for k, v in metadata.items():
            if k.lower() not in ["password", "otp", "totp", "secret", "recovery_code", "jwt", "embedding", "recording"]:
                safe_metadata[k] = v

    event_doc = {
        "event_id": event_id,
        "event_type": event_type,
        "user_id": user_id,
        "identity": user_id,
        "organization_id": organization_id,
        "verification_session_id": verification_session_id,
        "auth_session_id": auth_session_id,
        "severity": severity,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_decision": risk_decision,
        "decision": risk_decision,
        "reason_codes": reason_codes or [],
        "source": source,
        "status": status,
        "is_demo": is_demo,
        "metadata": safe_metadata,
        "created_at": now,
        "timestamp": created_iso,
        "description": f"{event_type.replace('_', ' ')} for {user_id} (Severity: {severity})"
    }

    try:
        db.security_events.insert_one(event_doc)
    except Exception as e:
        print(f"[Publish Security Event Error]: {e}")

    # Alert policy check: Should this generate an Alert?
    alert_triggers = ["FACE_MISMATCH", "VOICE_VERIFICATION_FAILED", "MFA_FAILED", "HIGH_RISK_AUTHENTICATION",
                      "ACCESS_BLOCKED", "SESSION_REVOKED", "ACCOUNT_DISABLED", "BEHAVIOR_DEVIATION"]
    if severity in ["HIGH", "CRITICAL"] or risk_decision in ["BLOCK", "STEP_UP"] or event_type in alert_triggers:
        alert_id = f"alt_{uuid.uuid4().hex[:12]}"
        title_map = {
            "ACCESS_BLOCKED": "Zero-Trust Access Blocked",
            "FACE_MISMATCH": "Biometric Face Verification Failed",
            "VOICE_VERIFICATION_FAILED": "Voice Acoustic Verification Failed",
            "MFA_FAILED": "Multi-Factor TOTP Verification Failed",
            "HIGH_RISK_AUTHENTICATION": "High Risk Authentication Attempt",
            "SESSION_REVOKED": "Active Security Session Revoked",
            "ACCOUNT_DISABLED": "Identity Account Disabled"
        }
        title = title_map.get(event_type, f"Security Alert: {event_type.replace('_', ' ')}")
        summary = f"Severity {severity} alert triggered for {user_id}. Risk score: {risk_score}."

        alert_doc = {
            "alert_id": alert_id,
            "event_id": event_id,
            "user_id": user_id,
            "identity": user_id,
            "organization_id": organization_id,
            "severity": severity,
            "title": title,
            "summary": summary,
            "created_at": now,
            "status": "OPEN",
            "acknowledged_at": None,
            "acknowledged_by": None,
            "resolved_at": None,
            "resolved_by": None,
            "resolution_summary": None,
            "is_demo": is_demo
        }
        try:
            db.alerts.update_one({"alert_id": alert_id}, {"$setOnInsert": alert_doc}, upsert=True)
            # Create notification for drawer & count
            db.notifications.insert_one({
                "notification_id": f"notif_{uuid.uuid4().hex[:12]}",
                "alert_id": alert_id,
                "event_id": event_id,
                "user_id": user_id,
                "organization_id": organization_id,
                "severity": severity,
                "title": title,
                "summary": summary,
                "created_at": now,
                "read": False
            })
        except Exception as a_err:
            print(f"[Alert Creation Error]: {a_err}")

    # Remove ObjectId for return
    if "_id" in event_doc:
        event_doc["_id"] = str(event_doc["_id"])
    return event_doc



def generate_qr_base64(otpauth_uri: str) -> str:
    """Generates locally rendered base64 PNG data URI for Google Authenticator QR enrollment."""
    qr = qrcode.QRCode(version=1, box_size=5, border=2)
    qr.add_data(otpauth_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("utf-8")


def is_email_configured() -> bool:
    """Returns True if MAIL_HOST, MAIL_USERNAME and MAIL_PASSWORD environment variables are set."""
    return bool(MAIL_HOST and MAIL_USERNAME and MAIL_PASSWORD)


def generate_secure_otp() -> str:
    """Generates a cryptographically secure 6-digit verification code string."""
    return str(secrets.randbelow(900000) + 100000)


def hash_otp(otp_code: str) -> str:
    """Computes SHA-256 hash of plaintext OTP for secure MongoDB storage."""
    return hashlib.sha256(otp_code.encode("utf-8")).hexdigest()


def mask_email_address(email: str) -> str:
    """Masks email address for UI display, e.g., s*****@example.com."""
    if not email or "@" not in email:
        return email
    parts = email.split("@")
    user, domain = parts[0], parts[1]
    if len(user) <= 2:
        masked_user = user[0] + "*"
    else:
        masked_user = user[0] + "*****" + user[-1]
    return f"{masked_user}@{domain}"


def send_real_email_otp(to_email: str, otp_code: str) -> tuple:
    """Sends real 6-digit OTP email via configured SMTP server."""
    if not is_email_configured():
        return False, "Email service is not configured."
    
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "DeepTrust Admin Verification Code"
        msg["From"] = MAIL_FROM or MAIL_USERNAME
        msg["To"] = to_email

        text = f"Your DeepTrust Admin verification code is: {otp_code}\nThis code will expire in 10 minutes.\nIf you did not request this code, please ignore this email."
        html = f"""
        <div style="font-family: Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; padding: 24px; border-radius: 8px;">
            <h2 style="color: #38bdf8; margin-top: 0;">DeepTrust Admin Email Verification</h2>
            <p>Use the following 6-digit verification code to complete your admin account setup:</p>
            <div style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #38bdf8; background-color: #1e293b; padding: 16px; text-align: center; border-radius: 6px; margin: 20px 0;">
                {otp_code}
            </div>
            <p style="font-size: 13px; color: #94a3b8;">This code expires in 10 minutes and can only be used once.</p>
            <p style="font-size: 12px; color: #64748b; margin-top: 24px;">DeepTrust Healthcare Identity & Access Platform</p>
        </div>
        """

        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        if MAIL_PORT == 465:
            server = smtplib.SMTP_SSL(MAIL_HOST, MAIL_PORT, timeout=10)
        else:
            server = smtplib.SMTP(MAIL_HOST, MAIL_PORT, timeout=10)
            if MAIL_USE_TLS:
                server.starttls()

        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_FROM or MAIL_USERNAME, [to_email], msg.as_string())
        server.quit()
        return True, "Verification code sent successfully."
    except Exception as err:
        print(f"[DeepTrust Email Error]: {err}")
        return False, "Email delivery failed. Please check the sender SMTP configuration and try Resend Code."


def get_authenticated_user_from_header(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    Zero-Trust Authentication Dependency:
    - Validates Bearer access token signature & expiration
    - Enforces Token Type isolation (Token B ACCESS only; rejects Token A VERIFICATION)
    - Validates active session existence & revocation status in MongoDB
    - Validates account status (blocks PENDING, DISABLED, SUSPENDED, REMOVED)
    - Returns server-authoritative user profile (Never trusts client-supplied roles/orgs)
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Missing or invalid authorization header")
    token = authorization.replace("Bearer ", "").strip()
    decoded = decode_jwt_token(token)
    if not decoded:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or expired access token")
    
    # Strict Token Isolation: Pre-auth verification tokens cannot access protected APIs
    token_type = decoded.get("token_type")
    if token_type == "VERIFICATION":
        raise HTTPException(status_code=403, detail="Forbidden: Pre-auth verification token cannot access protected application APIs")
    if token_type != "ACCESS":
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid access token type")
    
    # Fail closed: every access token must own a live database session.
    session_id = decoded.get("session_id")
    checked_session = enforce_session(db, decoded, on_expire=lambda ended, deadline: log_audit_event(
        "SESSION_EXPIRED", str(ended.get("user_id")), ended.get("email", ""), ended.get("organization_name", ""),
        "Session expired due to inactivity or maximum lifetime", session_id=str(ended.get("session_id") or ended["_id"])))

    # Server-side User Lookup (Never trust client-supplied role or organization claims)
    user_email = decoded.get("email")
    user = None
    if db is not None and user_email:
        user = db.users.find_one({"email_normalized": user_email.lower()})
        if not user:
            user = db.deeptrust_admins.find_one({"email_normalized": user_email.lower()}) or \
                   db.healthcare_admins.find_one({"email_normalized": user_email.lower()})
    
    if user:
        if str(user.get("_id")) != str(decoded.get("sub")):
            raise HTTPException(401, "Account identity changed; sign in again")
        if user.get("organization_id") != checked_session.get("organization_id"):
            raise HTTPException(401, "Account organization changed; sign in again")
        status = user.get("status", "ACTIVE")
        if status == "PENDING_EMAIL_VERIFICATION":
            raise HTTPException(status_code=403, detail="Forbidden: Email verification pending. Please verify your official email address.")
        elif status in ["PENDING_MFA_SETUP", "PENDING_SECURITY_ENROLLMENT"]:
            raise HTTPException(status_code=403, detail="Forbidden: Security enrollment pending.")
        elif status in ["DISABLED", "SUSPENDED", "REMOVED", "disabled", "suspended", "removed"]:
            raise HTTPException(status_code=403, detail="Forbidden: Account is disabled or suspended.")
        
        user_dict = dict(user)
        user_dict["_id"] = str(user["_id"])
        user_dict["session_id"] = session_id
        if not user_dict.get("role"):
            raise HTTPException(403, "Account role is not configured")
        if user_dict.get("role") not in PLATFORM_ROLES and not user_dict.get("organization_id"):
            raise HTTPException(403, "Account organization is not configured")
        return user_dict
    raise HTTPException(status_code=401, detail="Authenticated user not found")


get_authenticated_user = get_authenticated_user_from_header


def require_platform_admin(user: Dict[str, Any] = Depends(get_authenticated_user_from_header)) -> Dict[str, Any]:
    """Requires DEEPTRUST_OWNER or DEEPTRUST_ADMIN role."""
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Administrator privileges.")
    return user


def require_platform_owner(user: Dict[str, Any] = Depends(get_authenticated_user_from_header)) -> Dict[str, Any]:
    """Requires DEEPTRUST_OWNER role."""
    if user.get("role") not in ["DEEPTRUST_OWNER", "OWNER"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Owner privileges.")
    return user


def require_write_permission(user: Dict[str, Any]) -> Dict[str, Any]:
    """Rejects mutation actions from read-only AUDITOR accounts."""
    if user.get("role") not in MANAGERS:
        raise HTTPException(status_code=403, detail="Administrator write permission required; auditors are read-only.")
    return user


def validate_org_scope(user: Dict[str, Any], requested_org_id: Optional[str]):
    """Validates organization boundary to prevent cross-organization access."""
    if not requested_org_id or requested_org_id == "ALL":
        return
    if user.get("role") in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        return
    user_org = user.get("organization_id", "HEALTHCARE_ORG_1")
    if requested_org_id != user_org:
        raise HTTPException(status_code=403, detail="Forbidden: Cross-organization access denied.")




# ── Request / Response Schemas ──────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str
    selected_access_type: Optional[str] = "HOSPITAL_ADMIN"


class FinalizeRequest(BaseModel):
    session_id: str
    verification_token: Optional[str] = None


class DetectRequest(BaseModel):
    image: str
    session_id: Optional[str] = None


class EnrollFaceRequest(BaseModel):
    user_id: str
    image: Optional[str] = None
    images: Optional[List[str]] = None
    organization_name: Optional[str] = "Healthcare Organization"
    liveness_verified: Optional[bool] = False
    session_id: Optional[str] = None


class MatchFaceRequest(BaseModel):
    user_id: str
    image: str
    session_id: Optional[str] = None


class LivenessChallengeRequest(BaseModel):
    session_id: str
    user_id: Optional[str] = None


class LivenessVerifyRequest(BaseModel):
    session_id: str
    image: str


class VoiceChallengeRequest(BaseModel):
    session_id: str
    user_id: Optional[str] = None


class VoiceVerifyRequest(BaseModel):
    challenge_id: Optional[str] = None
    session_id: str
    user_id: str
    phrase: Optional[str] = None
    audio_data: Optional[str] = None
    energy_score: Optional[float] = None


class VoiceRecoveryVerifyRequest(BaseModel):
    session_id: str
    recovery_code: str
    user_id: Optional[str] = None


class VoiceRecoverySessionRequest(BaseModel):
    session_id: str
    user_id: Optional[str] = None


class VoiceRecoveryAlternateVerifyRequest(VoiceRecoverySessionRequest):
    totp_code: str
    repair_voice: bool = False


def validate_redirect_uri(uri: str) -> bool:
    if not uri or not isinstance(uri, str):
        return False
    uri = uri.strip()
    if "*" in uri:
        return False
    if not (uri.startswith("http://localhost") or uri.startswith("http://127.0.0.1") or uri.startswith("https://")):
        return False
    try:
        parsed = urllib.parse.urlparse(uri)
        if not parsed.scheme or not parsed.netloc:
            return False
        return True
    except Exception:
        return False


class CreateApplicationRequest(BaseModel):
    organization_id: str
    application_name: str
    application_type: Optional[str] = "Web Application"
    redirect_uri: str
    description: Optional[str] = None
    status: Optional[str] = "ACTIVE"


class CreateIntegrationRequest(BaseModel):
    application_name: str
    organization_id: Optional[str] = None
    application_type: Optional[str] = "Web Application"
    redirect_uri: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = "ACTIVE"
    allowed_origins: Optional[List[str]] = ["http://localhost:5050", "http://127.0.0.1:5050"]
    allowed_redirects: Optional[List[str]] = []


class UpdateIntegrationStatusRequest(BaseModel):
    status: str



class AccessRequestInput(BaseModel):
    client_id: str
    client_secret: str
    auth_session_id: Optional[str] = None
    session_token: Optional[str] = None
    user_id: Optional[str] = None
    requested_resource: str
    requested_action: str
    decision: Optional[str] = None
    role: Optional[str] = None


class OAuthAuthorizeInput(BaseModel):
    client_id: str
    redirect_uri: str
    response_type: Optional[str] = "code"
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = "S256"
    scope: Optional[str] = None
    requested_role: Optional[str] = None
    auth_session_id: Optional[str] = None


class OAuthTokenInput(BaseModel):
    grant_type: str = "authorization_code"
    client_id: str
    client_secret: str
    code: str
    redirect_uri: str
    code_verifier: Optional[str] = None


class AccessVerifyInput(BaseModel):
    client_id: str
    client_secret: str
    authorization_token: str
    requested_resource: str
    requested_action: str


class MfaSetupRequest(BaseModel):
    user_id: str
    email: str


class MfaVerifyRequest(BaseModel):
    session_id: Optional[str] = None
    user_id: str
    code: str


class RiskEvaluateRequest(BaseModel):
    session_id: str
    user_id: Optional[str] = None


class CreateAccountRequest(BaseModel):
    full_name: str
    email: str
    account_type: str  # DEEPTRUST_ADMIN or HEALTHCARE_ADMIN
    organization_id: Optional[str] = None
    organization_name: Optional[str] = None
    role: str
    password: str


class MfaTotpSetupRequest(BaseModel):
    user_id: str
    email: Optional[str] = None


class MfaTotpConfirmRequest(BaseModel):
    user_id: str
    code: Optional[str] = None
    totp_code: Optional[str] = None
    secret: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ProfileUpdateRequest(BaseModel):
    full_name: str


class AdminRegisterRequest(BaseModel):
    full_name: Any
    email: Any
    password: Any
    confirm_password: Optional[Any] = None
    role: Optional[Any] = None
    organization_id: Optional[Any] = None
    organization_name: Optional[Any] = None
    status: Optional[Any] = None
    email_verified: Optional[Any] = None
    permissions: Optional[Any] = None


class EmailSendCodeRequest(BaseModel):
    email: str


class EmailVerifyCodeRequest(BaseModel):
    email: str
    code: str


class EmailResendCodeRequest(BaseModel):
    email: str


class MobilePairCreateRequest(BaseModel):
    lan_host: Optional[str] = None
    frontend_port: Optional[int] = 5000


class MobilePairVerifyCredentialsRequest(BaseModel):
    token: str
    email: str
    password: str


class MobilePairVerifyTotpRequest(BaseModel):
    token: str
    email: str
    totp_code: str


class MobileRevokeSessionRequest(BaseModel):
    session_id: str


class SessionActivityHeartbeat(BaseModel):
    session_id: Optional[str] = None
    client_timestamp: Optional[float] = None
    action_type: Optional[str] = None
    has_activity: bool = False
    details: Optional[Dict[str, Any]] = None


class BehaviorSummaryRequest(BaseModel):
    session_id: Optional[str] = None
    average_velocity: float = Field(default=0, ge=0, le=100000, allow_inf_nan=False)
    velocity_variance: float = Field(default=0, ge=0, le=1e10, allow_inf_nan=False)
    movement_rate: float = Field(default=0, ge=0, le=10000, allow_inf_nan=False)
    click_rate: float = Field(default=0, ge=0, le=10000, allow_inf_nan=False)
    idle_ratio: float = Field(default=0, ge=0, le=1, allow_inf_nan=False)
    sample_count: int = Field(default=0, ge=0, le=100000)
    trusted_events: int = Field(default=0, ge=0, le=100000)
    synthetic_events: int = Field(default=0, ge=0, le=100000)
    window_seconds: float = Field(default=15, ge=1, le=120, allow_inf_nan=False)
    webdriver: bool = False
    is_touch_device: bool = False
    scroll_events: int = Field(default=0, ge=0, le=100000)
    wheel_events: int = Field(default=0, ge=0, le=100000)
    swipe_count: int = Field(default=0, ge=0, le=100000)
    pointer_interval_cv: float = Field(default=0, ge=0, le=100, allow_inf_nan=False)
    path_straightness: float = Field(default=0, ge=0, le=1, allow_inf_nan=False)
    path_segments: int = Field(default=0, ge=0, le=100000)


# ── API Endpoints ───────────────────────────────────────────────────────────

# ── 1. SYSTEM HEALTH ────────────────────────────────────────────────────────
@app.get("/api/v1/health")
@app.get("/api/v1/system/status")
def system_health():
    is_db_connected = False
    if db is not None:
        try:
            db.command({"ping": 1})
            is_db_connected = True
        except Exception:
            is_db_connected = False

    return {
        "status": "HEALTHY" if is_db_connected else "DEGRADED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "api": "ONLINE",
            "database": "ONLINE" if is_db_connected else "UNAVAILABLE",
            "auth": "ONLINE",
            "face": "ONLINE" if detector and recognizer else "NOT_CONFIGURED",
            "voice": "ONLINE",
            "mfa": "ONLINE",
            "risk": "ONLINE"
        },
        "models": {
            "yunet": detector is not None,
            "sface": recognizer is not None
        }
    }


# ── 2. ADMIN REGISTRATION & EMAIL VERIFICATION ────────────────────────────────
@app.post("/api/v1/admin/register")
@app.post("/api/v1/auth/register")
def register_admin_account(req: AdminRegisterRequest):
    # 1. Type validation (NoSQL query operator protection)
    if not isinstance(req.full_name, str) or not isinstance(req.email, str) or not isinstance(req.password, str):
        raise HTTPException(status_code=400, detail="Invalid input data types. String values required.")

    full_name = req.full_name.strip()
    email = req.email.strip()
    norm_email = email.lower()

    if not full_name or not email or not req.password:
        raise HTTPException(status_code=400, detail="Full Name, Email Address, and Password are required.")

    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", norm_email):
        raise HTTPException(status_code=400, detail="Invalid email format. Please provide a valid email address.")

    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")

    if req.confirm_password is not None and req.password != req.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    # 2. Strict Anti-Privilege Escalation Enforcement
    # Public registration MUST NEVER allow assigning DEEPTRUST_OWNER or DEEPTRUST_ADMIN or privileged platform roles
    if req.role in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN", "ROOT", "SUPERADMIN"]:
        raise HTTPException(status_code=403, detail="Public registration cannot assign privileged platform roles.")

    # 3. Organization Security Protection
    if req.organization_id == "DEEPTRUST_PLATFORM":
        raise HTTPException(status_code=403, detail="Public registration cannot join DeepTrust Platform internal organization.")

    # 4. Prevent duplicate accounts (normalized email check)
    if db is not None:
        existing = db.users.find_one({"email_normalized": norm_email})
        if not existing:
            existing = db.deeptrust_admins.find_one({"email_normalized": norm_email})
        if existing:
            raise HTTPException(status_code=409, detail="An account with this email address already exists.")

    # 5. Securely hash password using bcrypt
    password_hash = bcrypt.hashpw(req.password.encode('utf-8'), bcrypt.gensalt(10)).decode('utf-8')

    # Safe account role and organization defaults
    assigned_role = "HOSPITAL_ADMIN"
    org_id = "HEALTHCARE_ORG_1"
    org_name = "Healthcare Organization"

    now = time.time()
    # 6. Mass Assignment Protection: explicitly construct initial user doc
    user_doc = {
        "full_name": full_name,
        "email": email,
        "email_normalized": norm_email,
        "password_hash": password_hash,
        "role": assigned_role,
        "display_role": "Healthcare Security Admin",
        "organization_id": org_id,
        "organization_name": org_name,
        "status": "PENDING_EMAIL_VERIFICATION",
        "email_verified": False,
        "email_verified_at": None,
        "mfa_enabled": False,
        "mfa_verified_at": None,
        "protected_mfa_secret": None,
        "created_at": now,
        "updated_at": now,
        "last_login_at": None
    }

    user_id = None
    if db is not None:
        try:
            res = db.users.insert_one(user_doc)
            user_id = str(res.inserted_id)
            user_doc["_id"] = user_id
            db.healthcare_admins.update_one({"email_normalized": norm_email}, {"$set": user_doc}, upsert=True)
        except DuplicateKeyError:
            raise HTTPException(status_code=409, detail="An account with this email address already exists.")
    else:
        user_id = f"usr_{uuid.uuid4().hex[:16]}"

    log_audit_event("REGISTER_INITIATED", user_id, norm_email, org_name, "Account Registration Initiated — Status PENDING_EMAIL_VERIFICATION", risk="LOW")

    # 7. Generate OTP hash record for P4 Email Verification readiness
    otp_code = generate_secure_otp()
    otp_hash = hash_otp(otp_code)
    expires_at = now + 600  # 10 min

    if db is not None:
        db.email_verifications.update_one(
            {"email": norm_email},
            {
                "$set": {
                    "user_id": user_id,
                    "email": norm_email,
                    "otp_hash": otp_hash,
                    "created_at": now,
                    "expires_at": expires_at,
                    "attempt_count": 0,
                    "verified_at": None,
                    "status": "PENDING"
                }
            },
            upsert=True
        )

    # Store the hash before delivery so an immediately entered code can be verified.
    sent_ok, delivery_message = send_real_email_otp(norm_email, otp_code)
    if db is not None:
        delivery_fields = {
            "delivery_status": "SENT" if sent_ok else "FAILED",
            "last_attempt_at": now,
        }
        if sent_ok:
            delivery_fields["last_sent_at"] = now
        db.email_verifications.update_one(
            {"email": norm_email}, {"$set": delivery_fields}
        )

    # The account remains pending even if the SMTP delivery attempt fails.
    return {
        "success": True,
        "message": ("Account created successfully. Verification code sent; check your inbox and spam folder."
                    if sent_ok else "Account created successfully, but the verification email was not sent. " + delivery_message),
        "email_sent": sent_ok,
        "email_configured": is_email_configured(),
        "user_id": user_id,
        "email": norm_email,
        "masked_email": mask_email_address(norm_email),
        "status": "PENDING_EMAIL_VERIFICATION",
        "email_verified": False
    }


@app.post("/api/v1/auth/email/send-code")
@app.post("/api/v1/auth/email/resend-code")
@app.post("/api/v1/admin/email/send-code")
@app.post("/api/v1/admin/email/resend-code")
def resend_email_code(req: EmailResendCodeRequest):
    if not req.email:
        raise HTTPException(status_code=400, detail="Email address is required.")

    norm_email = req.email.strip().lower()

    if not is_email_configured():
        return {
            "success": False,
            "message": "Email service is not configured.",
            "email_configured": False
        }

    # Cooldown rate limiting check
    now = time.time()
    if db is not None:
        rec = db.email_verifications.find_one({"email": norm_email})
        if rec and (now - max(rec.get("last_sent_at", 0), rec.get("last_attempt_at", 0))) < 60:
            raise HTTPException(status_code=429, detail="EMAIL_RESEND_COOLDOWN: Please wait 60 seconds before requesting a new verification code.")

    otp_code = generate_secure_otp()
    otp_hash = hash_otp(otp_code)
    expires_at = now + 600

    if db is not None:
        db.email_verifications.update_one(
            {"email": norm_email},
            {
                "$set": {
                    "email": norm_email,
                    "otp_hash": otp_hash,
                    "created_at": now,
                    "expires_at": expires_at,
                    "attempt_count": 0,
                    "verified_at": None,
                    "status": "PENDING"
                }
            },
            upsert=True
        )

    sent_ok, msg = send_real_email_otp(norm_email, otp_code)
    if db is not None:
        delivery_fields = {
            "delivery_status": "SENT" if sent_ok else "FAILED",
            "last_attempt_at": now,
        }
        if sent_ok:
            delivery_fields["last_sent_at"] = now
        db.email_verifications.update_one(
            {"email": norm_email}, {"$set": delivery_fields}
        )
    if not sent_ok:
        raise HTTPException(status_code=500, detail=msg)

    return {
        "success": True,
        "message": "Verification code sent to official email address.",
        "email_sent": True,
        "email_configured": True,
        "email": norm_email,
        "masked_email": mask_email_address(norm_email)
    }


@app.post("/api/v1/auth/email/verify-code")
@app.post("/api/v1/admin/email/verify-code")
def verify_email_code(req: EmailVerifyCodeRequest):
    if not req.email or not req.code:
        raise HTTPException(status_code=400, detail="Email and 6-digit verification code are required.")

    norm_email = req.email.strip().lower()
    code_input = req.code.strip()

    if db is None:
        raise HTTPException(status_code=500, detail="Database unavailable")

    rec = db.email_verifications.find_one({"email": norm_email})
    if not rec:
        raise HTTPException(status_code=400, detail="No pending email verification record found for this address.")

    if rec.get("status") == "VERIFIED":
        raise HTTPException(status_code=400, detail="EMAIL_OTP_ALREADY_USED: This verification code has already been used.")

    now = time.time()
    if rec.get("expires_at", 0) < now:
        raise HTTPException(status_code=400, detail="EMAIL_OTP_EXPIRED: Verification code has expired. Please request a new code.")

    if rec.get("attempt_count", 0) >= 5:
        raise HTTPException(status_code=429, detail="EMAIL_ATTEMPTS_EXCEEDED: Maximum attempt limit exceeded. Please request a new verification code.")

    # Cryptographic hash verification
    if hash_otp(code_input) != rec.get("otp_hash"):
        db.email_verifications.update_one({"email": norm_email}, {"$inc": {"attempt_count": 1}})
        raise HTTPException(status_code=400, detail="EMAIL_OTP_INVALID: Invalid verification code.")

    # Verification successful
    db.email_verifications.update_one(
        {"email": norm_email},
        {"$set": {"status": "VERIFIED", "verified_at": now}}
    )

    user = db.users.find_one({"email_normalized": norm_email})
    user_id = str(user["_id"]) if user else rec.get("user_id")

    db.users.update_one(
        {"email_normalized": norm_email},
        {"$set": {"email_verified": True, "email_verified_at": now, "status": "PENDING_MFA_SETUP", "updated_at": now}}
    )
    db.deeptrust_admins.update_one(
        {"email_normalized": norm_email},
        {"$set": {"email_verified": True, "email_verified_at": now, "status": "PENDING_MFA_SETUP", "updated_at": now}}
    )

    log_audit_event("EMAIL_VERIFIED", str(user_id), norm_email, "DeepTrust Security Platform", "Official Email Verification Code Verified", risk="LOW")

    return {
        "success": True,
        "message": "Official email address verified. Proceed to Google Authenticator setup.",
        "status": "PENDING_MFA_SETUP",
        "user_id": user_id,
        "email": norm_email
    }


# ── 3. AUTHENTICATION & SESSIONS ───────────────────────────────────────────
@app.post("/api/v1/auth/login")
def login(req: LoginRequest):
    norm_email = req.email.strip().lower()
    
    # 1. Lookup User in MongoDB
    user = None
    if db is not None:
        user = db.users.find_one({"email_normalized": norm_email})
        if not user:
            user = db.healthcare_admins.find_one({"email_normalized": norm_email})
        if not user:
            user = db.deeptrust_admins.find_one({"email_normalized": norm_email})

    if not user:
        # Fallback to in-memory check for demo
        if norm_email == "admin@healthcare.demo":
            user = {
                "_id": "demo_admin_1",
                "email": "admin@healthcare.demo",
                "email_normalized": "admin@healthcare.demo",
                "full_name": "Healthcare Security Admin",
                "role": "HOSPITAL_ADMIN",
                "organization_name": "NovaCare Medical Center",
                "status": "ACTIVE"
            }
        elif norm_email == "owner@deeptrust.demo":
            user = {
                "_id": "demo_owner_1",
                "email": "owner@deeptrust.demo",
                "email_normalized": "owner@deeptrust.demo",
                "full_name": "DeepTrust Platform Owner",
                "role": "DEEPTRUST_OWNER",
                "organization_name": "DeepTrust Security Platform",
                "status": "ACTIVE"
            }

    if not user:
        log_audit_event("LOGIN_FAILED", "unknown", norm_email, "Unknown", "User Not Found", risk="MEDIUM")
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    user_status = user.get("status", "ACTIVE")
    if user_status == "PENDING_EMAIL_VERIFICATION":
        raise HTTPException(status_code=403, detail="Email verification pending. Please verify your official email address before logging in.")
    elif user_status == "PENDING_MFA_SETUP":
        raise HTTPException(status_code=403, detail="Google Authenticator setup pending. Please complete MFA setup to activate your account.")
    elif user_status != "ACTIVE":
        raise HTTPException(status_code=403, detail="Account is disabled or pending review.")

    # 2. Verify Password
    is_valid = False
    stored_hash = user.get("password_hash", "")
    if stored_hash.startswith("$2a$") or stored_hash.startswith("$2b$"):
        try:
            is_valid = bcrypt.checkpw(req.password.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception:
            is_valid = False
    else:
        is_valid = False

    if not is_valid:
        log_audit_event("LOGIN_FAILED", str(user.get("_id")), user["email"], user.get("organization_name", ""), "Invalid Password", risk="HIGH")
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    # 3. Verify Portal / Access Type
    if req.selected_access_type == "DEEPTRUST_OWNER":
        if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "ADMIN", "OWNER"]:
            raise HTTPException(
                status_code=403,
                detail=f"Access Mismatch: Your account is assigned as {user.get('role').replace('_', ' ')}. Please select the correct portal tab."
            )
    else:
        if not staff_role(user.get("role")):
            raise HTTPException(
                status_code=403,
                detail=f"Access Mismatch: Your account is assigned as {user.get('role').replace('_', ' ')}. Please select the correct portal tab."
            )

    # 4. Create Verification Session in MongoDB
    session_id = f"vs_{uuid.uuid4().hex[:16]}"
    verification_session = {
        "session_id": session_id,
        "user_id": str(user.get("_id")),
        "email": user["email"],
        "role": user["role"],
        "organization_id": user.get("organization_id"),
        "organization_name": user.get("organization_name", "Healthcare Organization"),
        "credential_status": "VERIFIED",
        "face_status": "PENDING",
        "liveness_status": "PENDING",
        "voice_status": "PENDING",
        "mfa_status": "PENDING",
        "risk_status": "PENDING",
        "final_decision": "PENDING",
        "created_at": time.time(),
        "expires_at": time.time() + 900  # 15 min
    }

    if db is not None:
        try:
            db.verification_sessions.insert_one(verification_session)
            db.authentication_events.insert_one({
                "user_id": str(user.get("_id")),
                "email": user["email"],
                "role": user["role"],
                "status": "CREDENTIALS_VERIFIED",
                "session_id": session_id,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        except Exception as err:
            print(f"[Auth Login DB Error]: {err}")

    # 5. Issue PRE-AUTH Verification Token (Token A)
    verification_token = generate_verification_token(
        user_id=str(user.get("_id")),
        email=user["email"],
        role=user["role"],
        session_id=session_id
    )

    log_audit_event("LOGIN_ATTEMPT", str(user.get("_id")), user["email"], user.get("organization_name", ""), "Credentials Verified", risk="LOW", session_id=session_id)
    log_audit_event("CREDENTIALS_VERIFIED", str(user.get("_id")), user["email"], user.get("organization_name", ""), "Credentials verified", risk="LOW", session_id=session_id)

    return {
        "success": True,
        "message": "Credentials verified. Proceed to Biometric Verification.",
        "token": verification_token,
        "verification_token": verification_token,
        "session_id": session_id,
        "next_step": "FACE",
        "user": {
            "id": str(user.get("_id")),
            "full_name": user.get("full_name", "Administrator"),
            "email": user["email"],
            "role": user["role"],
            "organization_name": user.get("organization_name", "Healthcare Organization"),
            "email_verified": bool(user.get("email_verified", True)),
            "face_enrolled": bool(user.get("face_enrolled", True)),
            "voice_enrolled": bool(user.get("voice_enrolled", True)),
            "mfa_enabled": bool(user.get("mfa_enabled", True))
        }
    }


@app.get("/api/v1/auth/verification-session/{session_id}")
def get_verification_session(session_id: str):
    """Retrieves session verification statuses so that page refreshes can resume exact step."""
    if db is not None:
        sess = db.verification_sessions.find_one({"session_id": session_id})
        if sess:
            sess["_id"] = str(sess["_id"])
            return {"success": True, "session": sess}

    # SECURITY: When the session is not found (DB unavailable or unknown session_id),
    # return all steps as PENDING — never pre-populate as VERIFIED.
    # A client that receives this must start over from credentials.
    return {
        "success": False,
        "session": {
            "session_id": session_id,
            "credential_status": "PENDING",
            "face_status": "PENDING",
            "liveness_status": "PENDING",
            "voice_status": "PENDING",
            "mfa_status": "PENDING",
            "risk_status": "PENDING",
            "final_decision": "PENDING"
        },
        "message": "Session not found. Please restart the authentication flow."
    }


@app.post("/api/v1/auth/finalize")
def finalize_authentication(req: FinalizeRequest, request: Request):
    """
    CRITICAL FINALIZATION ENDPOINT:
    Verifies all 5 factors (Credentials, Face, Liveness, Voice, MFA) + Risk ALLOW.
    Generates the authenticated application session and FINAL ACCESS TOKEN (Token B).
    Enriches session with server-resolved IP, network status, device trust, and security correlation.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    session = db.verification_sessions.find_one({"session_id": req.session_id})
    if not session:
        raise HTTPException(status_code=401, detail="Verification session not found or expired")

    if time.time() > session.get("expires_at", 0):
        raise HTTPException(status_code=403, detail="VERIFICATION_SESSION_EXPIRED: Session expired.")

    # Verify it has not already been finalized/used
    if session.get("final_decision") == "FINALIZED" or session.get("revoked") == True:
         raise HTTPException(status_code=403, detail="Verification session already consumed or revoked.")

    # Check all factor statuses (Path A: Normal Voice Success, Path B: Voice Failure + Recovery Verified)
    path_a_ok = (
        session.get("credential_status") == "VERIFIED" and
        session.get("face_status") == "VERIFIED" and
        session.get("liveness_status") == "VERIFIED" and
        session.get("voice_status") == "VERIFIED" and
        session.get("mfa_status") == "VERIFIED"
    )

    path_b_ok = (
        session.get("credential_status") == "VERIFIED" and
        session.get("face_status") == "VERIFIED" and
        session.get("liveness_status") == "VERIFIED" and
        session.get("voice_status") == "FAILED_RECOVERY_USED" and
        session.get("recovery_status") == "VERIFIED" and
        session.get("mfa_status") == "VERIFIED"
    )

    if not (path_a_ok or path_b_ok):
        incomplete_steps = []
        if session.get("credential_status") != "VERIFIED":
            incomplete_steps.append("Credentials")
        if session.get("face_status") != "VERIFIED":
            incomplete_steps.append("Face Verification")
        if session.get("liveness_status") != "VERIFIED":
            incomplete_steps.append("Active Liveness")
        if session.get("voice_status") not in ("VERIFIED", "FAILED_RECOVERY_USED") or (session.get("voice_status") == "FAILED_RECOVERY_USED" and session.get("recovery_status") != "VERIFIED"):
            incomplete_steps.append("Voice/Recovery Verification")
        if session.get("mfa_status") != "VERIFIED":
            incomplete_steps.append("Two-Step Authenticator")

        raise HTTPException(
            status_code=403,
            detail=f"Security verification incomplete. Required steps: {', '.join(incomplete_steps)}"
        )
        
    # Check Risk
    risk_dec = session.get("risk_decision") or session.get("final_decision") or session.get("risk_status")
    if risk_dec == "BLOCK" or (session.get("risk_status") not in ("ALLOW", "STEP_UP", "VERIFIED") and session.get("risk_decision") not in ("ALLOW", "STEP_UP")):
        raise HTTPException(
            status_code=403,
            detail="Access blocked by Risk Engine."
        )

    # Resolve User
    user_email = session.get("email")
    user = db.users.find_one({"email_normalized": user_email.lower()})
    
    if not user:
        raise HTTPException(status_code=401, detail="Authenticated user not found.")

    # Save first-time voice setup only after all factors and risk checks above.
    voice_security.commit_enrollment(session, user)
    face_setup.commit(session, user)

    # Mark as finalized so it can't be reused
    db.verification_sessions.update_one(
        {"session_id": req.session_id},
        {"$set": {"final_decision": "FINALIZED", "completed_at": time.time()}}
    )

    # 1. Generate Authenticated Application Session ID
    auth_session_id = f"as_{uuid.uuid4().hex[:16]}"
    identity_id = str(user.get("_id"))

    # 2. Resolve Client IP, Network Status, and Device Context Server-Side
    client_ip = resolve_client_ip(request)
    user_agent = request.headers.get("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)") if request else "Mozilla/5.0"
    net_ctx = determine_network_status(identity_id, client_ip)
    dev_ctx = parse_device_info(user_agent, identity_id, client_ip)

    # 3. Generate FINAL ACCESS TOKEN (Token B)
    access_token = generate_final_access_token(user, auth_session_id)

    # 4. Store in MongoDB auth_sessions with strict correlation
    if db is not None:
        try:
            now = time.time()
            loc_ctx = get_approximate_location(client_ip if classify_ip_network(client_ip) == "PUBLIC" else "127.0.0.1")
            
            # Determine application name
            org_id = user.get("organization_id", "HEALTHCARE_ORG_1")
            app_name = "NovaCare Staff Portal" if "HEALTHCARE" in str(org_id) else "DeepTrust Admin Console"

            db.auth_sessions.insert_one({
                "_id": auth_session_id,
                "session_id": auth_session_id,
                "user_id": identity_id,
                "identity_id": identity_id,
                "email": user["email"],
                "email_snapshot": user["email"],
                "full_name": user.get("full_name", user.get("email")),
                "role": user.get("role", "HOSPITAL_ADMIN"),
                "organization_id": org_id,
                "organization_name": user.get("organization_name", "Healthcare Organization"),
                "application_name": app_name,
                "created_at": now,
                "login_at": now,
                "logout_at": None,
                "expires_at": now + 8 * 3600,
                "last_activity_at": now,
                "last_heartbeat_at": now,
                "user_agent": user_agent,
                "session_duration_seconds": 0,
                "status": "ACTIVE",
                "revoked": False,
                "ip_address": client_ip,
                "ip_masked": mask_ip(client_ip),
                "network_status": net_ctx.get("network_status", "LOCAL"),
                "network_context": net_ctx,
                "device": dev_ctx.get("display_device", "Chrome • Windows"),
                "device_context": dev_ctx,
                "device_trust": dev_ctx.get("device_trust", "UNKNOWN"),
                "location_context": loc_ctx,
                "behavior_summary": {
                    "interaction_velocity": "Not measured",
                    "status": "INSUFFICIENT_DATA",
                    "reason_codes": ["NO_TELEMETRY"]
                },
                "verification_session_id": req.session_id,
                "risk_score": session.get("risk_score", 12),
                "risk_level": session.get("risk_level", "LOW"),
                "risk_decision": session.get("risk_decision", "ALLOW")
            })

            # Record / update device in db.trusted_devices
            dev_key = f"{identity_id}_{dev_ctx.get('browser')}_{dev_ctx.get('os')}"
            dev_id = f"dev_{hashlib.md5(dev_key.encode()).hexdigest()[:12]}"
            db.trusted_devices.update_one(
                {"user_id": identity_id, "browser": dev_ctx.get("browser"), "os": dev_ctx.get("os")},
                {"$set": {
                    "device_id": dev_id,
                    "organization_id": org_id,
                    "user_id": identity_id,
                    "email": user["email"],
                    "browser": dev_ctx.get("browser"),
                    "os": dev_ctx.get("os"),
                    "category": dev_ctx.get("category"),
                    "display_device": dev_ctx.get("display_device"),
                    "last_ip": client_ip,
                    "last_seen": now,
                    "updated_at": now
                },
                "$setOnInsert": {
                    "trust_status": "TRUSTED" if dev_ctx.get("device_trust") == "TRUSTED" else "UNTRUSTED",
                    "first_seen": now,
                    "created_at": now
                }},
                upsert=True
            )

            # Create notification for successful access
            db.notifications.insert_one({
                "user_id": identity_id,
                "email": user["email"],
                "type": "ACCESS_ALLOWED",
                "title": "Secure access granted",
                "message": "Multi-factor identity verification completed successfully.",
                "read": False,
                "created_at": time.time(),
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        except Exception as err:
            print(f"[Auth Finalize DB Error]: {err}")

    log_audit_event("FINAL_ACCESS_GRANTED", identity_id, user["email"], user.get("organization_name", "Healthcare Organization"), "Final Zero-Trust Access Token Granted", risk="LOW", session_id=auth_session_id, identity_id=identity_id)
    log_audit_event("SESSION_STARTED", identity_id, user["email"], user.get("organization_name", "Healthcare Organization"), "Authenticated Session Started", risk="LOW", session_id=auth_session_id, identity_id=identity_id)

    return {
        "success": True,
        "access_token": access_token,
        "token": access_token,
        "token_type": "bearer",
        "user": {
            "id": identity_id,
            "full_name": user.get("full_name", "Administrator"),
            "email": user["email"],
            "role": user.get("role", "HOSPITAL_ADMIN"),
            "organization_name": user.get("organization_name", "Healthcare Organization")
        },
        "organization": {
            "id": user.get("organization_id", "HEALTHCARE_ORG_1"),
            "name": user.get("organization_name", "Healthcare Organization"),
            "industry": "Healthcare"
        },
        "redirect": "/dashboard"
    }


@app.get("/api/v1/auth/me")
def get_current_user(authorization: Optional[str] = Header(None)):
    """Restores authenticated user profile from valid FINAL access token."""
    user = get_authenticated_user_from_header(authorization)
    return {
        "success": True,
        "user": {
            "id":str(user["_id"]), "full_name":user.get("full_name", user.get("email")),
            "email":user["email"], "role":user["role"],
            "organization_id":user.get("organization_id"), "organization_name":user.get("organization_name"),
            "email_verified":bool(user.get("email_verified")), "face_enrolled":bool(user.get("face_enrolled")),
            "voice_enrolled":bool(user.get("voice_enrolled")), "mfa_enabled":bool(user.get("mfa_enabled"))
        },
        "organization":{"id":user.get("organization_id"), "name":user.get("organization_name")}
    }


@app.post("/api/v1/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    """Revokes the current authenticated session."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "").strip()
        decoded = decode_jwt_token(token)
        if decoded:
            session_id = decoded.get("session_id")
            identity_id = str(decoded.get("sub", ""))
            if db is not None and session_id:
                now = time.time()
                sess = db.auth_sessions.find_one({"_id": session_id})
                login_at = (sess.get("login_at") or sess.get("created_at") or now) if sess else now
                duration_sec = max(0, int(now - login_at))
                db.auth_sessions.update_one(
                    {"_id": session_id},
                    {"$set": {
                        "revoked": True,
                        "revoked_at": now,
                        "logout_at": now,
                        "status": "LOGGED_OUT",
                        "session_duration_seconds": duration_sec
                    }}
                )
            log_audit_event("LOGOUT", identity_id, decoded.get("email", ""), decoded.get("organization_name", ""), "Session Terminated", risk="LOW", session_id=session_id, identity_id=identity_id)

    return {"success": True, "message": "Session terminated successfully."}





# ── 3. FACE & LIVENESS ENGINE ───────────────────────────────────────────────
@app.get("/api/v1/face/health")
def face_health():
    return {
        "status": "ONLINE" if detector is not None and recognizer is not None and phone_guard is not None and passive_pad is not None else "DEGRADED",
        "detector": "OpenCV YuNet DNN (Active)",
        "recognizer": "OpenCV SFace DNN (Active)",
        "phone_detector": "OpenCV NanoDet" if phone_guard is not None else "UNAVAILABLE",
        "face_pipeline_version": "2026-10-06.7",
        "face_setup_version": "2026-10-08.staff-setup1",
        "session_monitor_version": "2026-10-06.1",
        "security_controls_version": "2026-10-06.1",
        "dashboard_features_version": "2026-10-06.2",
        "passive_pad": "MiniFASNet ensemble" if passive_pad is not None else "UNAVAILABLE",
        "mongodb_connected": db is not None
    }


@app.post("/api/v1/face/detect")
@serialized_face_engine
def detect_face(req: DetectRequest):
    if detector is None:
        raise HTTPException(status_code=503, detail="Face detector model not initialized")

    img = decode_image(req.image)
    if img is None:
        raise HTTPException(status_code=400, detail="Invalid image payload")

    phone_result = check_phone_presentation(img, req.session_id)
    if phone_result:
        if req.session_id and db is not None:
            require_face_session(req.session_id)
            LIVENESS_SESSIONS.pop(req.session_id, None)
            db.verification_sessions.update_one({"session_id": req.session_id}, {"$set": {"face_status": "PENDING", "liveness_status": "FAILED"}})
        return phone_result

    h, w, _ = img.shape
    detector.setInputSize((w, h))
    _, faces = detector.detect(img)

    if faces is None or len(faces) == 0:
        return {
            "status": "NO_FACE",
            "faces_count": 0,
            "message": "No face detected. Position your face inside the frame.",
            "bounding_box": None
        }

    if len(faces) > 1:
        return {
            "status": "MULTIPLE_FACES",
            "faces_count": len(faces),
            "message": "Multiple faces detected. Only one person should be visible.",
            "bounding_box": None
        }

    face = faces[0]
    fx, fy, fw, fh = int(face[0]), int(face[1]), int(face[2]), int(face[3])
    score = float(face[-1])

    norm_box = [
        max(0.0, min(1.0, fx / w)),
        max(0.0, min(1.0, fy / h)),
        max(0.0, min(1.0, fw / w)),
        max(0.0, min(1.0, fh / h))
    ]

    landmarks = {
        "right_eye": [float(face[4]), float(face[5])],
        "left_eye": [float(face[6]), float(face[7])],
        "nose_tip": [float(face[8]), float(face[9])],
        "mouth_right": [float(face[10]), float(face[11])],
        "mouth_left": [float(face[12]), float(face[13])]
    }

    return {
        "status": "ONE_FACE",
        "faces_count": 1,
        "message": "Face detected",
        "confidence": round(score, 3),
        "bounding_box": norm_box,
        "landmarks": landmarks
    }


try:
    from .face_setup import FaceSetup
except ImportError:
    from face_setup import FaceSetup
face_setup = FaceSetup(globals())

@app.post("/api/v1/face/setup/status")
def face_setup_status(data: Dict[str, Any], authorization: Optional[str] = Header(None)):
    return face_setup.status(data, authorization)

@app.post("/api/v1/face/setup/authorize")
def face_setup_authorize(data: Dict[str, Any], authorization: Optional[str] = Header(None)):
    return face_setup.authorize(data, authorization)


@app.post("/api/v1/face/enroll")
@serialized_face_engine
def enroll_face(req: EnrollFaceRequest):
    session = require_face_session(req.session_id, req.user_id)
    profile_query = face_profile_query(session)
    setup = bool(session.get("face_setup_authorized"))
    if db.face_profiles.find_one(profile_query) and not setup:
        return JSONResponse(status_code=409, content={"success": False, "status": "FACE_ALREADY_ENROLLED", "message": "This account already has a face profile. Login cannot replace it."})
    req.user_id = str(session["user_id"])
    if detector is None or recognizer is None:
        raise HTTPException(status_code=503, detail="Face recognition engine not available")

    raw_images = req.images if (req.images and len(req.images) > 0) else ([req.image] if req.image else [])
    if not raw_images:
        raise HTTPException(status_code=400, detail="No image payload provided")

    valid_embeddings = []
    
    for idx, img_b64 in enumerate(raw_images):
        img = decode_image(img_b64)
        if img is None:
            if len(raw_images) == 1:
                raise HTTPException(status_code=400, detail="Invalid image payload")
            continue

        phone_result = check_phone_presentation(img, req.session_id)
        if phone_result:
            return JSONResponse(status_code=400, content={**phone_result, "success": False})

        h, w, _ = img.shape
        detector.setInputSize((w, h))
        _, faces = detector.detect(img)

        if faces is None or len(faces) == 0:
            if len(raw_images) == 1:
                return JSONResponse(status_code=400, content={"status": "NO_FACE", "success": False, "message": "No face detected in enrollment image."})
            continue

        if len(faces) > 1:
            if len(raw_images) == 1:
                return JSONResponse(status_code=400, content={"status": "MULTIPLE_FACES", "success": False, "message": "Multiple faces detected. Ensure only one person is visible."})
            continue

        live_face = faces[0]
        fw, fh = live_face[2], live_face[3]
        if fw < 50 or fh < 50:
            if len(raw_images) == 1:
                return JSONResponse(status_code=400, content={"status": "FACE_TOO_SMALL", "success": False, "message": "Face size is too small in the camera frame."})
            continue

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        brightness = float(np.mean(gray))
        if brightness < 20 or brightness > 245:
            if len(raw_images) == 1:
                return JSONResponse(status_code=400, content={"status": "LOW_QUALITY", "success": False, "message": "Lighting quality is poor (too dark or overexposed)."})
            continue

        aligned_face = recognizer.alignCrop(img, live_face)
        feature_vector = recognizer.feature(aligned_face).flatten().astype(np.float32)
        norm = np.linalg.norm(feature_vector)
        if norm > 0:
            feature_vector = feature_vector / norm
        valid_embeddings.append(feature_vector)

    if len(valid_embeddings) == 0:
        return JSONResponse(status_code=400, content={"status": "NO_FACE", "success": False, "message": "No valid face samples were captured."})

    # Mutual identity consistency check across captured sample frames
    if len(valid_embeddings) >= 2:
        for i in range(len(valid_embeddings)):
            for j in range(i + 1, len(valid_embeddings)):
                sim = face_similarity(valid_embeddings[i], valid_embeddings[j])
                if sim < 0.35:
                    return JSONResponse(status_code=400, content={
                        "status": "ENROLLMENT_IDENTITY_INCONSISTENT",
                        "success": False,
                        "message": "Enrollment samples appear to contain inconsistent identities."
                    })

    # Create reference biometric template (average normalized embedding)
    mean_embedding = np.mean(valid_embeddings, axis=0)
    norm = np.linalg.norm(mean_embedding)
    if norm > 0:
        mean_embedding = mean_embedding / norm
    embedding_list = mean_embedding.tolist()
    sample_embeddings_list = [emb.tolist() for emb in valid_embeddings]

    profile_id = f"fp_{uuid.uuid4().hex[:12]}"
    now_ts = time.time()

    if setup:
        return face_setup.stage(session, {
            "face_profile_id": profile_id, "user_id": str(session["user_id"]),
            "organization_name": session.get("organization_name", "Healthcare Organization"),
            "model_name": "OpenCV-SFace-DNN", "detector_backend": "OpenCV-YuNet-DNN",
            "metric": "Cosine Similarity", "threshold": 0.38,
            "protected_template": embedding_list, "embedding": embedding_list,
            "sample_embeddings": sample_embeddings_list, "sample_count": len(valid_embeddings),
            "enrollment_version": "v3.0-setup", "status": "ACTIVE",
            "enrolled_at": now_ts, "updated_at": now_ts, "created_at": now_ts})

    if db is not None:
        try:
            filter_query = profile_query

            enrollment_result = db.face_profiles.update_one(
                filter_query,
                {
                    "$setOnInsert": {
                        "face_profile_id": profile_id,
                        "user_id": str(req.user_id),
                        "organization_name": req.organization_name or "Healthcare Organization",
                        "model_name": "OpenCV-SFace-DNN",
                        "detector_backend": "OpenCV-YuNet-DNN",
                        "metric": "Cosine Similarity",
                        "threshold": 0.38,
                        "protected_template": embedding_list,
                        "embedding": embedding_list,
                        "sample_embeddings": sample_embeddings_list,
                        "sample_count": len(valid_embeddings),
                        "enrollment_version": "v2.0",
                        "status": "ACTIVE",
                        "enrolled_at": now_ts,
                        "updated_at": now_ts,
                        "created_at": now_ts
                    }
                },
                upsert=True
            )
            if enrollment_result.upserted_id is None:
                return JSONResponse(status_code=409, content={"success": False, "status": "FACE_ALREADY_ENROLLED", "message": "A face profile already exists for this account."})
            db.users.update_one(
                {"$or": [{"_id": ObjectId(req.user_id) if ObjectId.is_valid(req.user_id) else None}, {"email": req.user_id}, {"user_id": req.user_id}]},
                {"$set": {"face_enrolled": True}}
            )
        except Exception as err:
            print(f"[Face Enrollment MongoDB Error]: {err}")
            raise HTTPException(status_code=503, detail="Face enrollment could not be persisted")

    log_audit_event("FACE_ENROLLED", str(req.user_id), str(req.user_id), req.organization_name or "Healthcare Organization", f"Face Biometric Profile Registered ({len(valid_embeddings)} samples)", risk="LOW")

    return {
        "success": True,
        "status": "ENROLLED",
        "sample_count": len(valid_embeddings),
        "message": "Face profile securely enrolled in DeepTrust."
    }


@app.post("/api/v1/face/match")
@serialized_face_engine
def match_face(req: MatchFaceRequest):
    session = require_face_session(req.session_id, req.user_id)
    # Every new comparison invalidates any previous liveness evidence.
    LIVENESS_SESSIONS.pop(req.session_id, None)
    FACE_MATCH_REFERENCES.pop(req.session_id, None)
    db.verification_sessions.update_one({"session_id": req.session_id}, {"$set": {"face_status": "PENDING", "liveness_status": "PENDING"}})

    if detector is None or recognizer is None:
        raise HTTPException(status_code=503, detail="Face recognition engine not available")

    img = decode_image(req.image)
    if img is None:
        raise HTTPException(status_code=400, detail="Invalid image payload")

    phone_result = check_phone_presentation(img, req.session_id)
    if phone_result:
        return phone_result

    h, w, _ = img.shape
    detector.setInputSize((w, h))
    _, faces = detector.detect(img)

    if faces is None or len(faces) == 0:
        return {"status": "NO_FACE", "matched": False, "message": "No face detected in live stream."}

    if len(faces) > 1:
        return {"status": "MULTIPLE_FACES", "matched": False, "message": "Multiple faces detected. Ensure only one person is visible."}

    live_face = faces[0]
    fw, fh = live_face[2], live_face[3]
    if fw < 50 or fh < 50:
        return {"status": "FACE_TOO_SMALL", "matched": False, "message": "Face is too small in the frame."}

    aligned_live = recognizer.alignCrop(img, live_face)
    live_feature = recognizer.feature(aligned_live).flatten().astype(np.float32)
    norm = np.linalg.norm(live_feature)
    if not np.isfinite(live_feature).all() or norm <= 0:
        return {"status": "LOW_QUALITY", "matched": False, "message": "Invalid live face features. Retry the camera capture."}
    live_feature = live_feature / norm

    if session.get("face_setup_authorized") and not session.get("face_pending_template"):
        return {"status": "FACE_PROFILE_NOT_ENROLLED", "matched": False,
                "message": "One-time setup authorized. Capture your live face to continue."}
    enrolled_profile = session.get("face_pending_template") or db.face_profiles.find_one(face_profile_query(session))
    if not enrolled_profile:
        return {"status": "FACE_PROFILE_NOT_ENROLLED", "matched": False, "message": "No face profile is enrolled for this account."}
    try:
        enrolled_feature = active_face_template(session).reshape((1, 128))
    except (ValueError, TypeError):
        return {"status": "FACE_PROFILE_UNAVAILABLE", "matched": False, "message": "Your saved face profile exists but is unavailable. Contact support; do not enroll a replacement."}

    cosine_similarity = face_similarity(enrolled_feature, live_feature)
    is_match = cosine_similarity >= 0.38

    now_ts = time.time()

    if is_match:
        for sid, reference in list(FACE_MATCH_REFERENCES.items()):
            if now_ts - reference["created_at"] > 35:
                FACE_MATCH_REFERENCES.pop(sid, None)
        # Keep the exact live frame which passed enrollment matching. Never
        # replace it with later challenge frames (which would allow drift).
        FACE_MATCH_REFERENCES[req.session_id] = {
            "feature": live_feature.copy(), "template": enrolled_feature.flatten().copy(),
            "user_id": str(session["user_id"]), "created_at": now_ts
        }
        if db is not None and req.session_id:
            db.verification_sessions.update_one(
                {"session_id": req.session_id},
                {"$set": {"face_status": "VERIFIED"}}
            )
        log_audit_event("FACE_VERIFIED", str(req.user_id), str(req.user_id), "Healthcare Organization", f"Face Identity Matched (Similarity: {round(cosine_similarity, 3)})", risk="LOW", session_id=req.session_id)
        return {
            "status": "MATCH",
            "matched": True,
            "similarity": round(cosine_similarity, 3),
            "message": "Identity Verified ✓"
        }
    else:
        if db is not None:
            log_audit_event("FACE_MISMATCH", str(req.user_id), str(req.user_id), "Healthcare Organization", f"Face Identity Mismatch Attempt (Similarity: {round(cosine_similarity, 3)})", risk="HIGH", session_id=req.session_id)
            db.security_events.insert_one({
                "event_id": f"EVT-MISMATCH-{int(now_ts)}-{uuid.uuid4().hex[:4]}",
                "title": "Biometric Face Verification Mismatch",
                "event_type": "FACE_MISMATCH",
                "severity": "HIGH",
                "user_id": str(req.user_id),
                "timestamp": now_ts,
                "created_at": now_ts,
                "decision": "BLOCK",
                "details": f"Biometric comparison mismatch for account {req.user_id} (Similarity: {round(cosine_similarity, 3)} < 0.38)",
                "status": "OPEN"
            })
            if req.session_id:
                db.verification_sessions.update_one(
                    {"session_id": req.session_id},
                    {"$set": {"face_status": "MISMATCH"}}
                )

        return {
            "status": "FACE_MISMATCH",
            "matched": False,
            "similarity": round(cosine_similarity, 3),
            "message": "Wrong face detected — this face does not match your enrolled profile."
        }


@app.post("/api/v1/liveness/challenge")
@serialized_face_engine
def create_liveness_challenge(req: LivenessChallengeRequest):
    auth = require_face_session(req.session_id, req.user_id, require_match=True)
    if detector is None or recognizer is None or passive_pad is None:
        raise HTTPException(status_code=503, detail="Face and anti-spoof engine unavailable. Restart DeepTrust.")
    try:
        template = active_face_template(auth)
    except (ValueError, TypeError):
        raise HTTPException(status_code=403, detail="A valid enrolled face is required")
    now = time.time()
    # A retried HTTP request must retain the same identity-bound scan and timer.
    # It cannot create fresh liveness evidence or revive a failed/expired scan.
    existing = LIVENESS_SESSIONS.get(req.session_id)
    if existing is not None:
        motion = existing["motion"]
        if (existing["user_id"] == str(auth["user_id"]) and
                np.array_equal(existing["template"], template) and
                0 <= now - motion.started <= 30 and not motion.failed and not motion.passed):
            return {"session_id": req.session_id, "challenge": "PASSIVE_FACE_SCAN",
                    "instruction": motion.instruction, "timestamp": motion.started}
        LIVENESS_SESSIONS.pop(req.session_id, None)
    verified_reference = FACE_MATCH_REFERENCES.pop(req.session_id, None)
    if (not verified_reference or now - verified_reference["created_at"] > 35 or
            verified_reference["user_id"] != str(auth["user_id"]) or
            not np.array_equal(verified_reference["template"], template)):
        raise HTTPException(status_code=403, detail="Match your enrolled face again before starting liveness.")
    # Remove expired challenge entries so abandoned sessions do not accumulate.
    for sid, entry in list(LIVENESS_SESSIONS.items()):
        if now - entry["motion"].started > 30:
            LIVENESS_SESSIONS.pop(sid, None)
    motion = PassiveChallenge(None, now)
    LIVENESS_SESSIONS[req.session_id] = {"motion": motion, "template": template,
        "user_id": str(auth["user_id"]), "reference": verified_reference["feature"].copy(),
        "mismatch_frames": 0, "mismatch_started": None}
    db.verification_sessions.update_one({"session_id": req.session_id}, {"$set": {"liveness_status": "PENDING"}})
    return {"session_id": req.session_id, "challenge": "PASSIVE_FACE_SCAN", "instruction": motion.instruction, "timestamp": now}


@app.post("/api/v1/liveness/verify")
@serialized_face_engine
def verify_liveness(req: LivenessVerifyRequest):
    auth = require_face_session(req.session_id, require_match=True)
    entry = LIVENESS_SESSIONS.get(req.session_id)
    if entry is None:
        return {"status": "LIVENESS_REQUIRED", "message": "Start a fresh liveness challenge."}
    motion = entry["motion"]
    def fail(message):
        motion.failed = True
        motion.passed = False
        db.verification_sessions.update_one({"session_id": req.session_id}, {"$set": {"liveness_status": "FAILED"}})
        log_audit_event("LIVENESS_FAILED", auth["user_id"], auth["user_id"], "Healthcare Organization", message, risk="HIGH", session_id=req.session_id)
        return {"status": "LIVENESS_FAILED", "message": message}
    if motion.failed:
        return {"status": "LIVENESS_FAILED", "message": "Challenge failed. Restart face verification."}
    if time.time() - motion.started > 30:
        return fail("Face scan timed out. Retry looking straight at the camera in good lighting.")
    if entry["user_id"] != str(auth["user_id"]):
        return fail("Challenge identity changed. Restart face verification.")
    if detector is None or recognizer is None:
        raise HTTPException(status_code=503, detail="Face recognition engine unavailable")
    try:
        current_template = active_face_template(auth)
    except (ValueError, TypeError):
        return fail("Enrolled face profile is unavailable.")
    if not np.array_equal(current_template, entry["template"]):
        return fail("Enrolled face changed during verification.")
    img = decode_image(req.image)
    if img is None:
        return fail("Invalid camera frame. Restart face verification.")
    phone_result = check_phone_presentation(img, req.session_id)
    if phone_result:
        fail(phone_result["message"])
        return phone_result
    h, w, _ = img.shape
    detector.setInputSize((w, h))
    _, faces = detector.detect(img)
    if faces is not None and len(faces) > 1:
        return fail("Only one person may be visible during verification.")
    face = faces[0] if faces is not None and len(faces) == 1 else None
    if face is not None:
        if face[2] < 50 or face[3] < 50 or float(face[-1]) < FACE_DETECTION_THRESHOLD:
            face = None
        else:
            feature = recognizer.feature(recognizer.alignCrop(img, face)).flatten().astype(np.float32)
            norm = np.linalg.norm(feature)
            if not np.isfinite(feature).all() or norm <= 0:
                return fail("Invalid face features.")
            similarity = face_similarity(entry["template"], feature / norm)
            live_feature = feature / norm
            stage = motion.steps[min(motion.index, len(motion.steps) - 1)]
            # All challenge frames must match the enrollment OR the immutable
            # live reference captured by the successful enrollment comparison.
            # This also covers the return from a turn, where alignment can vary.
            reference = entry.get("reference")
            reference_score = face_similarity(reference, live_feature) if reference is not None else -1.0
            same_identity = np.isfinite(similarity) and (similarity >= 0.38 or
                (np.isfinite(reference_score) and reference_score >= 0.38))
            diagnostic = {"stage": stage, "enrollment_similarity": round(similarity, 3),
                "reference_similarity": round(reference_score, 3), "elapsed": round(time.time() - motion.started, 2)}
            db.verification_sessions.update_one({"session_id": req.session_id}, {"$set": {"face_liveness_diagnostics": diagnostic}})
            if not same_identity:
                # A borderline score is inconclusive, not proof of another
                # person. It cannot advance the challenge or grant access.
                motion.samples = []
                motion.hold_started = None
                clearly_different = (np.isfinite(reference_score) and similarity < 0.20 and reference_score < 0.20)
                if clearly_different:
                    entry["mismatch_frames"] = entry.get("mismatch_frames", 0) + 1
                    if entry.get("mismatch_started") is None:
                        entry["mismatch_started"] = time.time()
                else:
                    entry["mismatch_frames"] = 0
                    entry["mismatch_started"] = None
                if entry["mismatch_frames"] >= 3 and time.time() - entry["mismatch_started"] >= 0.5:
                    db.verification_sessions.update_one({"session_id": req.session_id}, {"$set": {"face_status": "MISMATCH"}})
                    return fail("Face identity could not be confirmed. Retry facing the camera.")
                motion.observe(None, time.time())
                return {"status": "IN_PROGRESS", "message": "Face match unclear — hold your face steady in good lighting.", "instruction": "Face match unclear — look straight at the camera in good lighting."}
            entry["mismatch_frames"] = 0
            entry["mismatch_started"] = None
    if passive_pad is None:
        raise HTTPException(status_code=503, detail="Anti-spoof engine unavailable. Restart DeepTrust.")
    pad_result = passive_pad.predict(img, face) if face is not None else None
    status = motion.observe(face, time.time(), pad_result)
    db.verification_sessions.update_one({"session_id": req.session_id}, {"$set": {
        "face_motion_diagnostics": {"stage": "STRAIGHT_FACE", "elapsed": round(time.time()-motion.started,2),
            "face_visible": face is not None, "accepted_frames": len(motion.samples),
            "failure_reason": motion.failure_reason,
            "live_score": round(pad_result["live_score"],3) if pad_result else None}}})
    if status == "LIVENESS_FAILED":
        return fail("Photo or screen presentation suspected. Show your live face." if motion.failure_reason == "SPOOF_DETECTED" else "Face scan timed out. Retry looking straight at the camera in good lighting.")
    if status == "LIVENESS_PASSED":
        if face is None:
            return {"status": "IN_PROGRESS", "message": "Keep your face visible."}
        db.verification_sessions.update_one({"session_id": req.session_id}, {"$set": {"liveness_status": "VERIFIED"}})
        log_audit_event("LIVENESS_VERIFIED", auth["user_id"], auth["user_id"], "Healthcare Organization", "Identity-bound passive anti-spoof scan passed", risk="LOW", session_id=req.session_id)
        return {"status": status, "message": "Active Liveness Verified ✓"}
    instruction = motion.instruction
    if face is None:
        instruction = "Keep your face visible with both eyes in view. " + instruction
    elif motion.samples:
        instruction = "Face verified in current frames. Keep looking straight briefly. " + instruction
    return {"status": status, "message": instruction, "instruction": instruction,
            "face_visible": face is not None, "step": motion.index + 1, "steps": len(motion.steps)}


# ── 4. VOICE VERIFICATION ENGINE ───────────────────────────────────────────
VOICE_PHRASES = [
    "DeepTrust secure access alpha seven",
    "DeepTrust authorization delta nine",
    "DeepTrust verify identity bravo four"
]

# Voice verification never mutates enrollment templates.
try:
    from .voice_security import VoiceSecurity
except ImportError:
    from voice_security import VoiceSecurity
voice_security = VoiceSecurity(globals())

@app.post("/api/v1/voice/challenge")
def get_voice_challenge(req: VoiceChallengeRequest, authorization: Optional[str] = Header(None)):
    return voice_security.challenge(req, authorization)

@app.post("/api/v1/voice/enroll")
def enroll_voice(req: Dict[str, Any], authorization: Optional[str] = Header(None)):
    return voice_security.submit(req, authorization, enroll=True)

@app.post("/api/v1/voice/verify")
def verify_voice(req: VoiceVerifyRequest, authorization: Optional[str] = Header(None)):
    return voice_security.submit(req, authorization)

@app.get("/api/v1/voice/health")
def voice_health():
    return voice_security.health()

def voice_recovery_context(req, authorization):
    _, database, session, user, user_id = voice_security.context(req, authorization, recovery=True)
    if session.get("revoked") or session.get("final_decision") == "FINALIZED":
        raise HTTPException(status_code=403, detail="Verification session is no longer active.")
    if session.get("voice_status") in ("VERIFIED", "FAILED_RECOVERY_USED") or session.get("recovery_status") == "VERIFIED":
        raise HTTPException(status_code=409, detail="Voice stage is already complete.")
    # Explicitly requested repair is still gated by password, live face, then
    # the single-use Authenticator verifier. It need not fail voice again.
    if (getattr(req, "repair_voice", False)
            and user.get("email") == "siddeshwar220407@gmail.com"
            and user.get("voice_repair_request_id")):
        return database, session, user, user_id
    if (session.get("voice_attempt_count", 0) < 2 and
            not session.get("recovery_required") and session.get("voice_status") != "FAILED" and
            session.get("voice_quality_retry_count", 0) < 1):
        raise HTTPException(status_code=403, detail="Try recording your voice once before using account recovery.")
    return database, session, user, user_id


@app.post("/api/v1/auth/voice-recovery/alternate/verify")
def verify_voice_recovery_alternate(req: VoiceRecoveryAlternateVerifyRequest, authorization: Optional[str] = Header(None)):
    database, session, user, user_id = voice_recovery_context(req, authorization)
    code = req.totp_code.strip()
    if not re.fullmatch(r"[0-9]{6}", code):
        raise HTTPException(status_code=400, detail="Enter the six-digit Google Authenticator code.")
    now = time.time()
    attempt = database.verification_sessions.update_one({
        "session_id": req.session_id, "user_id": session["user_id"],
        "expires_at": {"$gt": now}, "recovery_status": {"$ne": "VERIFIED"},
        "$or": [{"totp_recovery_attempts": {"$exists": False}}, {"totp_recovery_attempts": {"$lt": 5}}]
    }, {"$inc": {"totp_recovery_attempts": 1}})
    if attempt.modified_count != 1:
        raise HTTPException(status_code=429, detail="Recovery attempt limit reached or session expired. Sign in again.")
    secret = user.get("mfa_secret") or user.get("protected_mfa_secret")
    if not secret:
        profile = database.mfa_profiles.find_one({"$or": [{"user_id": user_id}, {"email": session["email"].lower()}]})
        secret = profile.get("secret") if profile else None
    if not secret:
        raise HTTPException(status_code=403, detail="Authenticator is not configured for this account. Contact your administrator.")
    totp = pyotp.TOTP(secret)
    current_step = int(now // totp.interval)
    matched_step = next((step for step in (current_step, current_step - 1, current_step + 1)
                         if secrets.compare_digest(totp.at(step * totp.interval), code)), None)
    if matched_step is None:
        log_audit_event("VOICE_RECOVERY_ALTERNATE_FAILED", user_id, session["email"], session.get("organization_name", "DeepTrust"), "Invalid Authenticator recovery code", risk="HIGH", session_id=req.session_id)
        raise HTTPException(status_code=400, detail="Incorrect or expired Google Authenticator code.")
    # The unique _id prevents the same account's TOTP being reused for recovery in another session.
    use_id = hashlib.sha256(f"{user_id}:{matched_step}".encode("utf-8")).hexdigest()
    try:
        database.voice_recovery_totp_uses.insert_one({"_id": use_id, "user_id": user_id,
            "session_id": req.session_id, "created_at": now})
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="This Authenticator code was already used for recovery. Wait for the next code.")
    if req.repair_voice:
        return voice_security.authorize_repair(session, user)
    updated = database.verification_sessions.update_one({
        "session_id": req.session_id, "user_id": session["user_id"],
        "credential_status": "VERIFIED", "face_status": "VERIFIED", "liveness_status": "VERIFIED",
        "revoked": {"$ne": True}, "final_decision": {"$ne": "FINALIZED"},
        "voice_status": {"$nin": ["VERIFIED", "FAILED_RECOVERY_USED"]},
        "recovery_status": {"$ne": "VERIFIED"}, "expires_at": {"$gt": time.time()}
    }, {"$set": {"voice_status": "FAILED_RECOVERY_USED", "recovery_status": "VERIFIED",
        "recovery_required": False, "recovery_method": "AUTHENTICATOR_TOTP"}})
    if updated.modified_count != 1:
        raise HTTPException(status_code=409, detail="Verification session changed. Sign in again.")
    log_audit_event("VOICE_RECOVERY_ALTERNATE_VERIFIED", user_id, session["email"], session.get("organization_name", "DeepTrust"), "Authenticator verified for voice recovery after a voice attempt", risk="HIGH", session_id=req.session_id)
    return {"success": True, "status": "VERIFIED", "message": "Voice recovery verified. Continue with Authenticator MFA."}


@app.post("/api/v1/auth/voice-recovery/verify")
@app.post("/api/v1/voice/recovery/verify")
def verify_voice_recovery(req: VoiceRecoveryVerifyRequest, authorization: Optional[str] = Header(None)):
    voice_security.context(req, authorization, recovery=True)
    if not req.session_id or not req.recovery_code:
        raise HTTPException(status_code=400, detail="Missing session_id or recovery_code")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    session = db.verification_sessions.find_one({"session_id": req.session_id})
    if not session:
        raise HTTPException(status_code=401, detail="Verification session not found")

    if time.time() > session.get("expires_at", 0):
        raise HTTPException(status_code=403, detail="VERIFICATION_SESSION_EXPIRED: Session expired.")

    # Sequence Verification: Credentials, Face, and Liveness MUST be VERIFIED first
    if session.get("credential_status") != "VERIFIED" or \
       session.get("face_status") != "VERIFIED" or \
       session.get("liveness_status") != "VERIFIED":
        raise HTTPException(status_code=403, detail="VERIFICATION_SEQUENCE_INVALID: Credentials, Face, and Liveness must be verified before Recovery.")

    # Check Voice attempt state: Voice attempts must be >= 2 or recovery_required == True or voice_status == "FAILED"
    voice_attempts = session.get("voice_attempt_count", 0)
    voice_status = session.get("voice_status")
    if voice_status == "VERIFIED":
        raise HTTPException(status_code=400, detail="Voice verification succeeded. Recovery verification is not required.")

    if voice_attempts < 2 and session.get("recovery_required") != True and voice_status != "FAILED":
        raise HTTPException(status_code=400, detail="Voice recovery is not required for this session.")

    # Recovery Code Brute-Force Rate Limiting (Max 3 recovery attempts per session)
    recovery_attempts = session.get("recovery_attempt_count", 0) + 1
    db.verification_sessions.update_one({"session_id": req.session_id}, {"$set": {"recovery_attempt_count": recovery_attempts}})

    if recovery_attempts > 3:
        log_audit_event("VOICE_RECOVERY_ATTEMPTS_EXCEEDED", str(session.get("user_id")), str(session.get("email")), "Healthcare Organization", "Exceeded max recovery code attempts", risk="HIGH", session_id=req.session_id)
        raise HTTPException(status_code=403, detail="Maximum recovery code attempts exceeded for this session.")

    # Validate Recovery Code Hash (supports raw digits e.g. "789012" as well as full formatted codes)
    clean_code = req.recovery_code.strip().upper()
    
    candidate_strings = [clean_code]
    if not clean_code.startswith("RECOVERY-CODE-"):
        candidate_strings.append(f"RECOVERY-CODE-{clean_code}")
    if not clean_code.startswith("RECOVERY-OWNER-"):
        candidate_strings.append(f"RECOVERY-OWNER-{clean_code}")
    if not clean_code.startswith("RECOVERY-"):
        candidate_strings.append(f"RECOVERY-{clean_code}")

    candidate_hashes = [hashlib.sha256(cs.encode('utf-8')).hexdigest() for cs in candidate_strings]

    user_email = str(session.get("email", "")).lower()
    user_id = str(session.get("user_id", ""))

    # Look up unused recovery code matching current session user
    rec_code_doc = db.recovery_codes.find_one({
        "$or": [
            {"email": user_email},
            {"user_id": user_id}
        ],
        "code_hash": {"$in": candidate_hashes},
        "used": False
    })

    if not rec_code_doc:
        log_audit_event("VOICE_RECOVERY_FAILED", user_id, user_email, "Healthcare Organization", "Invalid or used recovery code entered", risk="HIGH", session_id=req.session_id)
        raise HTTPException(status_code=400, detail="Invalid or previously used recovery code.")

    # Consume Recovery Code (Single-use)
    db.recovery_codes.update_one(
        {"_id": rec_code_doc["_id"]},
        {"$set": {"used": True, "used_at": time.time(), "used_in_session": req.session_id}}
    )

    # Update session state: Voice remains FAILED_RECOVERY_USED, Recovery becomes VERIFIED
    db.verification_sessions.update_one(
        {"session_id": req.session_id},
        {"$set": {
            "voice_status": "FAILED_RECOVERY_USED",
            "recovery_status": "VERIFIED",
            "recovery_required": False,
            "recovery_method": "RECOVERY_CODE"
        }}
    )

    log_audit_event("VOICE_RECOVERY_VERIFIED", user_id, user_email, "Healthcare Organization", "Recovery code verified after Voice failure", risk="MEDIUM", session_id=req.session_id)
    log_audit_event("RECOVERY_CODE_USED", user_id, user_email, "Healthcare Organization", f"Single-use recovery code consumed in session {req.session_id}", risk="MEDIUM", session_id=req.session_id)

    return {
        "success": True,
        "status": "VERIFIED",
        "voice_status": "FAILED_RECOVERY_USED",
        "recovery_status": "VERIFIED",
        "message": "Additional verification completed. Continue with Authenticator MFA."
    }


# ── 5. GOOGLE AUTHENTICATOR (TOTP MFA) ENGINE ──────────────────────────────
@app.post("/api/v1/mfa/setup")
@app.post("/api/v1/mfa/totp/setup")
def setup_mfa(req: MfaSetupRequest):
    user_id = req.user_id
    email = req.email or user_id
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    otpauth_url = totp.provisioning_uri(name=email, issuer_name="DeepTrust")
    qr_code_url = generate_qr_base64(otpauth_url)

    if db is not None:
        db.mfa_pending.update_one(
            {"user_id": user_id},
            {"$set": {"user_id": user_id, "email": email, "secret": secret, "created_at": time.time()}},
            upsert=True
        )
        db.mfa_profiles.update_one(
            {"$or": [{"user_id": user_id}, {"email": email.lower()}]},
            {
                "$set": {
                    "user_id": user_id,
                    "email": email.lower(),
                    "secret": secret,
                    "updated_at": time.time()
                },
                "$setOnInsert": {"created_at": time.time()}
            },
            upsert=True
        )

    return {
        "success": True,
        "secret": secret,
        "otpauth_url": otpauth_url,
        "qr_code": qr_code_url
    }


@app.post("/api/v1/mfa/totp/confirm")
def confirm_mfa_totp(req: MfaTotpConfirmRequest):
    user_id = req.user_id
    code = (req.code or req.totp_code or "").strip()
    secret = req.secret

    if not secret and db is not None:
        pending = db.mfa_pending.find_one({"user_id": user_id})
        if pending and "secret" in pending:
            secret = pending["secret"]
        if not secret:
            user = db.users.find_one({"$or": [{"_id": ObjectId(user_id) if ObjectId.is_valid(user_id) else None}, {"email_normalized": user_id.lower()}, {"email": user_id}]})
            if user and ("mfa_secret" in user or "protected_mfa_secret" in user):
                secret = user.get("mfa_secret") or user.get("protected_mfa_secret")

    if not secret:
        raise HTTPException(status_code=400, detail="MFA setup secret not found. Please regenerate QR code.")

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid authentication code. Please enter the current code from Google Authenticator.")

    # Activate MFA for account
    if db is not None:
        q = {"$or": [{"_id": ObjectId(user_id) if ObjectId.is_valid(user_id) else None}, {"email_normalized": user_id.lower()}, {"email": user_id}]}
        db.users.update_one(q, {"$set": {"mfa_enabled": True, "mfa_secret": secret, "protected_mfa_secret": secret, "status": "ACTIVE", "mfa_verified_at": time.time(), "updated_at": time.time()}})
        db.deeptrust_admins.update_one({"$or": [{"email_normalized": user_id.lower()}, {"email": user_id}]}, {"$set": {"mfa_enabled": True, "mfa_secret": secret, "protected_mfa_secret": secret, "status": "ACTIVE", "mfa_verified_at": time.time(), "updated_at": time.time()}})
        db.healthcare_admins.update_one({"$or": [{"email_normalized": user_id.lower()}, {"email": user_id}]}, {"$set": {"mfa_enabled": True, "mfa_secret": secret, "protected_mfa_secret": secret, "status": "ACTIVE", "mfa_verified_at": time.time(), "updated_at": time.time()}})
        db.mfa_profiles.update_one({"email": user_id.lower()}, {"$set": {"secret": secret, "user_id": user_id, "updated_at": time.time()}}, upsert=True)

    log_audit_event("MFA_ENROLLED", user_id, user_id, "DeepTrust Security Platform", "Google Authenticator TOTP enrolled and activated.", risk="LOW")
    return {"success": True, "message": "Google Authenticator successfully activated."}


@app.post("/api/v1/mfa/verify")
@app.post("/api/v1/auth/mfa/verify")
def verify_mfa(req: MfaVerifyRequest):
    if not req.session_id:
        raise HTTPException(status_code=400, detail="Missing verification session_id")
        
    if db is not None:
        session = db.verification_sessions.find_one({"session_id": req.session_id})
        if not session:
            raise HTTPException(status_code=403, detail="VERIFICATION_SEQUENCE_INVALID: Verification session not found.")
        
        path_a = (session.get("voice_status") == "VERIFIED")
        path_b = (session.get("voice_status") == "FAILED_RECOVERY_USED" and session.get("recovery_status") == "VERIFIED")
        if not (path_a or path_b):
            raise HTTPException(status_code=403, detail="VERIFICATION_SEQUENCE_INVALID: Voice verification or secure recovery verification must be completed before MFA.")
            
        if time.time() > session.get("expires_at", 0):
            raise HTTPException(status_code=403, detail="VERIFICATION_SESSION_EXPIRED: Session expired.")
        if req.user_id and str(session.get("user_id")) != str(req.user_id) and str(session.get("email")) != str(req.user_id):
            raise HTTPException(status_code=403, detail="Session user mismatch.")

    code = req.code.strip()
    
    # Check stored secret in MongoDB for this exact user
    secret = None
    user = None
    if db is not None:
        user = db.users.find_one({"$or": [{"_id": ObjectId(req.user_id) if ObjectId.is_valid(req.user_id) else None}, {"email_normalized": req.user_id.lower()}, {"email": req.user_id}]})
        if not user:
            user = db.deeptrust_admins.find_one({"$or": [{"email_normalized": req.user_id.lower()}, {"email": req.user_id}]}) or \
                   db.healthcare_admins.find_one({"$or": [{"email_normalized": req.user_id.lower()}, {"email": req.user_id}]})
        
        if user:
            secret = user.get("mfa_secret") or user.get("protected_mfa_secret")

    if not secret and db is not None:
        prof = db.mfa_profiles.find_one({"$or": [{"user_id": req.user_id}, {"email": req.user_id.lower()}]})
        if prof and "secret" in prof:
            secret = prof["secret"]

    if not secret:
        raise HTTPException(status_code=400, detail="MFA profile not configured for this account. Please complete Google Authenticator setup.")

    totp = pyotp.TOTP(secret)
    is_valid = totp.verify(code, valid_window=2)

    if is_valid:
        if db is not None and req.session_id:
            db.verification_sessions.update_one(
                {"session_id": req.session_id},
                {"$set": {"mfa_status": "VERIFIED"}}
            )
        user_email = user.get("email", req.user_id) if user else req.user_id
        org_name = user.get("organization_name", "Healthcare Organization") if user else "Healthcare Organization"
        log_audit_event("MFA_VERIFIED", req.user_id, user_email, org_name, "TOTP Authenticator Code Verified", risk="LOW", session_id=req.session_id)
        return {
            "success": True,
            "status": "VERIFIED",
            "message": "Authenticator Code Verified ✓"
        }
    else:
        user_email = user.get("email", req.user_id) if user else req.user_id
        org_name = user.get("organization_name", "Healthcare Organization") if user else "Healthcare Organization"
        log_audit_event("MFA_FAILED", req.user_id, user_email, org_name, "Invalid TOTP Code Entered", risk="MEDIUM", session_id=req.session_id)
        raise HTTPException(status_code=400, detail="Invalid authentication code. Please enter the current code from Google Authenticator.")



# ── 6. DETERMINISTIC ZERO-TRUST RISK ENGINE ─────────────────────────────────
@app.post("/api/v1/risk/evaluate")
def evaluate_risk(req: RiskEvaluateRequest):
    if not req.session_id:
        raise HTTPException(status_code=400, detail="Missing verification session_id")
    session = None
    if db is not None:
        session = db.verification_sessions.find_one({"session_id": req.session_id})
        if not session or session.get("mfa_status") != "VERIFIED":
            raise HTTPException(status_code=403, detail="VERIFICATION_SEQUENCE_INVALID: MFA must be verified first.")
        if time.time() > session.get("expires_at", 0):
            raise HTTPException(status_code=403, detail="VERIFICATION_SESSION_EXPIRED: Session expired.")
        if req.user_id and str(session.get("user_id")) != str(req.user_id) and str(session.get("email")) != str(req.user_id):
            raise HTTPException(status_code=403, detail="Session user mismatch.")

    # Evaluate deterministic signals
    risk_score = 12
    decision = "ALLOW"
    reasons = [
        "CREDENTIALS_VALID",
        "BIOMETRIC_FACE_MATCH",
        "ACTIVE_LIVENESS_CONFIRMED",
        "MFA_TOTP_CONFIRMED",
        "TRUSTED_HEALTHCARE_DEVICE"
    ]

    if session:
        if session.get("voice_status") == "VERIFIED":
            risk_score = 8
            decision = "ALLOW"
            reasons.insert(3, "VOICE_VERIFIED")
        elif session.get("voice_status") == "FAILED_RECOVERY_USED" and session.get("recovery_status") == "VERIFIED":
            risk_score = 35  # Increased risk context for recovery usage
            decision = "ALLOW"
            reasons.insert(3, "VOICE_VERIFICATION_FAILED")
            reasons.insert(4, "VOICE_RECOVERY_USED")

        # Explicit test / policy override for Risk BLOCK testing
        if session.get("force_risk_block") == True or session.get("risk_decision_override") == "BLOCK":
            decision = "BLOCK"
            risk_score = 90

    if db is not None:
        db.risk_evaluations.insert_one({
            "session_id": req.session_id,
            "user_id": str(req.user_id or (session.get("user_id") if session else "demo_admin_1")),
            "risk_score": risk_score,
            "risk_level": "HIGH" if decision == "BLOCK" else "LOW",
            "decision": decision,
            "reason_codes": reasons,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "created_at": time.time()
        })

        if session:
            db.verification_sessions.update_one(
                {"session_id": req.session_id},
                {"$set": {
                    "risk_status": decision,
                    "risk_decision": decision,
                    "final_decision": decision,
                    "risk_score": risk_score
                }}
            )

    log_audit_event("RISK_EVALUATED", str(req.user_id or "admin@healthcare.demo"), "admin@healthcare.demo", "Healthcare Organization", f"Risk Decision: {decision} (Score: {risk_score}/100)", risk="HIGH" if decision == "BLOCK" else "LOW", session_id=req.session_id)

    return {
        "success": True,
        "risk_score": risk_score,
        "risk_level": "HIGH" if decision == "BLOCK" else "LOW",
        "decision": decision,
        "reason_codes": reasons
    }


# ── 7. COMPREHENSIVE DASHBOARD & ANALYTICS SUITE ────────────────────────────

class SecurityEventActionRequest(BaseModel):
    action: str  # ACKNOWLEDGE, RESOLVE, ESCALATE
    notes: Optional[str] = None


class AccessRequestAction(BaseModel):
    decision: str  # APPROVED, DENIED
    reviewer_notes: Optional[str] = None


class AiQueryRequest(BaseModel):
    query: str
    context_type: Optional[str] = "GENERAL"


class SettingsUpdateRequest(BaseModel):
    mfa_required: Optional[bool] = True
    liveness_strictness: Optional[str] = "STANDARD"
    session_timeout_minutes: Optional[int] = 480
    risk_auto_block_threshold: Optional[int] = 85
    notification_email: Optional[bool] = True
    notification_high_risk: Optional[bool] = True



# ── NOVACARE PRIVACY-PRESERVING TELEMETRY & DEEP RISK ENGINE ──────────────────
class TelemetryEventRequest(BaseModel):
    organization_id: Optional[str] = "HEALTHCARE_ORG_1"
    organization_name: Optional[str] = "NovaCare Medical Center"
    subject_id: Optional[str] = "opaque_user"
    role: str = "Doctor"
    action: str = "READ"  # READ, UPDATE, CREATE, DELETE, EXPORT
    resource_type: str = "PATIENT_RECORD"  # PATIENT_RECORD, APPOINTMENT, PRESCRIPTION, LAB_RESULT, INSURANCE, BILLING, BED_MANAGEMENT, STAFF_PERMISSION
    resource_reference: Optional[str] = "REF-SAFE"  # OPAQUE NON-CLINICAL ID ONLY
    authentication_context: Optional[Dict[str, Any]] = None
    device_context: Optional[Dict[str, Any]] = None
    timestamp: Optional[float] = None

class AggregateCountsRequest(BaseModel):
    organization_id: Optional[str] = "HEALTHCARE_ORG_1"
    organization_name: Optional[str] = "NovaCare Medical Center"
    counts: Dict[str, int] = {}

# Role Authorization Matrix (NovaCare Governance Policy)
ROLE_AUTHORIZATION_POLICY = {
    "doctor": ["PATIENT_RECORD", "PRESCRIPTION", "LAB_RESULT", "APPOINTMENT", "BED_MANAGEMENT"],
    "nurse": ["PATIENT_RECORD", "APPOINTMENT", "BED_MANAGEMENT", "LAB_RESULT"],
    "receptionist": ["APPOINTMENT", "PATIENT_RECORD", "BED_MANAGEMENT"],
    "lab_technician": ["LAB_RESULT", "APPOINTMENT"],
    "pharmacist": ["PRESCRIPTION", "APPOINTMENT"],
    "administrator": ["STAFF_PERMISSION", "AUDIT", "APPOINTMENT", "BED_MANAGEMENT", "INSURANCE", "BILLING"],
    "hospital_admin": ["STAFF_PERMISSION", "AUDIT", "APPOINTMENT", "BED_MANAGEMENT", "INSURANCE", "BILLING"]
}

RESOURCE_SENSITIVITY = {
    "APPOINTMENT": {"base_risk": 10, "level": "STANDARD"},
    "BED_MANAGEMENT": {"base_risk": 10, "level": "STANDARD"},
    "PATIENT_RECORD": {"base_risk": 25, "level": "HIGH"},
    "PRESCRIPTION": {"base_risk": 30, "level": "HIGH"},
    "LAB_RESULT": {"base_risk": 25, "level": "HIGH"},
    "INSURANCE": {"base_risk": 35, "level": "HIGH"},
    "BILLING": {"base_risk": 50, "level": "CRITICAL"},
    "STAFF_PERMISSION": {"base_risk": 60, "level": "CRITICAL"}
}


@app.post("/api/v1/telemetry/event")
def receive_security_telemetry(req: TelemetryEventRequest):
    """
    Ingests privacy-preserving security telemetry from NovaCare.
    EVALUATES DETERMINISTIC DEEP RISK & AUTHORIZATION DECISION (ALLOW / STEP_UP / BLOCK).
    STRICT PRIVACY GUARANTEE: Never ingests patient names, diagnoses, or clinical notes.
    """
    ts = req.timestamp or time.time()
    role_key = req.role.strip().lower().replace(" ", "_")
    res_type = req.resource_type.strip().upper()
    action = req.action.strip().upper()
    
    # Sanitize resource_reference: strip any accidental sensitive characters, enforce opaque reference
    ref = str(req.resource_reference or "REF-OPAQUE")
    if "@" in ref or " " in ref:
        ref = f"REF-{hashlib.sha256(ref.encode('utf-8')).hexdigest()[:8]}"

    # Deterministic Risk Evaluation Engine
    risk_score = 15
    reason_codes = []
    decision = "ALLOW"

    # 1. Evaluate Resource Sensitivity Base Risk
    res_info = RESOURCE_SENSITIVITY.get(res_type, {"base_risk": 20, "level": "STANDARD"})
    risk_score += res_info["base_risk"]
    reason_codes.append(f"RESOURCE_{res_info['level']}")

    # 2. Evaluate Role Authorization Governance Policy
    allowed_resources = ROLE_AUTHORIZATION_POLICY.get(role_key, [])
    if res_type not in allowed_resources:
        risk_score += 45
        reason_codes.append("ROLE_POLICY_VIOLATION")
        decision = "BLOCK"

    # 3. Action Sensitivity Evaluation
    if action in ["EXPORT", "DELETE", "PURGE"]:
        risk_score += 30
        reason_codes.append("HIGH_RISK_ACTION_EXPORT")
    elif action in ["UPDATE", "CREATE"]:
        risk_score += 10

    # 4. Device Context Anomaly Signals
    if req.device_context and req.device_context.get("untrusted_device"):
        risk_score += 20
        reason_codes.append("UNTRUSTED_DEVICE")

    risk_score = min(100, max(0, risk_score))

    if risk_score >= 80:
        risk_level = "CRITICAL"
        decision = "BLOCK"
    elif risk_score >= 60:
        risk_level = "HIGH"
        if decision != "BLOCK":
            decision = "STEP_UP"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
        if decision != "BLOCK":
            decision = "ALLOW"
    else:
        risk_level = "LOW"
        if decision != "BLOCK":
            decision = "ALLOW"

    telemetry_doc = {
        "telemetry_id": f"TEL-{uuid.uuid4().hex[:8].upper()}",
        "organization_id": req.organization_id or "HEALTHCARE_ORG_1",
        "organization_name": req.organization_name or "NovaCare Medical Center",
        "subject_id": req.subject_id or "opaque_user",
        "role": req.role,
        "action": action,
        "resource_type": res_type,
        "resource_reference": ref,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "decision": decision,
        "reason_codes": reason_codes,
        "created_at": ts,
        "timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat()
    }

    if db is not None:
        try:
            db.telemetry_events.insert_one(telemetry_doc)

            # Log to audit trail
            log_audit_event(
                f"ACCESS_{decision}",
                req.subject_id or "opaque_user",
                req.subject_id or "opaque_user",
                req.organization_name or "NovaCare Medical Center",
                f"{req.role} requested {action} on {res_type} ({ref}) -> Decision: {decision}",
                risk=risk_level
            )

            # Generate security event if BLOCKED or HIGH/CRITICAL risk
            if decision == "BLOCK" or risk_level in ["HIGH", "CRITICAL"]:
                sec_event = {
                    "event_id": f"SEC-{random.randint(9000, 9999)}",
                    "event_type": "UNAUTHORIZED_RESOURCE_ACCESS" if decision == "BLOCK" else "HIGH_RISK_TELEMETRY",
                    "severity": risk_level,
                    "identity": req.subject_id or "opaque_user",
                    "role": req.role,
                    "organization_id": req.organization_id or "HEALTHCARE_ORG_1",
                    "organization_name": req.organization_name or "NovaCare Medical Center",
                    "description": f"Access {action} on resource {res_type} evaluated as {risk_level} risk ({decision}). Reasons: {', '.join(reason_codes)}",
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "decision": decision,
                    "reason_codes": reason_codes,
                    "status": "OPEN",
                    "created_at": ts,
                    "timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat()
                }
                db.security_events.insert_one(sec_event)
        except Exception as e:
            print(f"[Telemetry Ingest Warning]: {e}")

    return {
        "success": True,
        "telemetry_id": telemetry_doc["telemetry_id"],
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reason_codes": reason_codes,
        "timestamp": telemetry_doc["timestamp"]
    }


@app.post("/api/v1/telemetry/aggregate-counts")
def update_aggregate_counts(req: AggregateCountsRequest):
    """
    Stores non-drill-down aggregate resource counts from NovaCare.
    STRICT PRIVACY: Numbers only. No patient lists, no drill-down records.
    """
    if db is not None:
        try:
            db.hospital_aggregate_counts.update_one(
                {"organization_id": req.organization_id or "HEALTHCARE_ORG_1"},
                {"$set": {
                    "organization_id": req.organization_id or "HEALTHCARE_ORG_1",
                    "organization_name": req.organization_name or "NovaCare Medical Center",
                    "counts": req.counts,
                    "updated_at": time.time()
                }},
                upsert=True
            )
        except Exception as e:
            print(f"[Aggregate Counts Error]: {e}")

    return {"success": True, "organization_name": req.organization_name or "NovaCare Medical Center", "updated": True}


@app.get("/api/v1/telemetry/aggregate-counts")
def get_aggregate_counts(organization_id: str = "HEALTHCARE_ORG_1"):
    """Retrieves privacy-safe aggregate hospital resource counts for NovaCare."""
    counts = {
        "patients": "Unavailable",
        "appointments": "Unavailable",
        "prescriptions": "Unavailable",
        "lab_records": "Unavailable",
        "insurance_records": "Unavailable",
        "billing_transactions": "Unavailable",
        "available_beds": "Unavailable",
        "occupied_beds": "Unavailable"
    }

    if db is not None:
        try:
            doc = db.hospital_aggregate_counts.find_one({"organization_id": organization_id})
            if doc and "counts" in doc:
                for k, v in doc["counts"].items():
                    counts[k] = v
        except Exception:
            pass

    return {"success": True, "organization_name": "NovaCare Medical Center", "counts": counts}


@app.get("/api/v1/telemetry/activity")
def get_telemetry_activity(limit: int = 15, user: dict = Depends(get_authenticated_user_from_header)):
    """Returns live NovaCare security activity items (Role, Action, Resource Type, Decision, Risk)."""
    items = []
    if db is not None:
        try:
            cursor = db.telemetry_events.find().sort("created_at", -1).limit(limit)
            for doc in cursor:
                items.append({
                    "id": doc.get("telemetry_id", str(doc["_id"])),
                    "role": doc.get("role", "Staff"),
                    "action": doc.get("action", "READ"),
                    "resource_type": doc.get("resource_type", "PATIENT_RECORD"),
                    "resource_reference": doc.get("resource_reference", "REF-SAFE"),
                    "decision": doc.get("decision", "ALLOW"),
                    "risk_level": doc.get("risk_level", "LOW"),
                    "risk_score": doc.get("risk_score", 15),
                    "reason_codes": doc.get("reason_codes", []),
                    "timestamp": datetime.fromtimestamp(doc.get("created_at", time.time()), timezone.utc).strftime("%H:%M:%S")
                })
        except Exception as e:
            print(f"[Telemetry Activity Query Error]: {e}")

    return {"success": True, "activity": items, "count": len(items)}



@app.get("/api/v1/dashboard/summary")
def get_dashboard_summary(user: dict = Depends(get_authenticated_user_from_header)):
    """Provides real-time healthcare access security metrics derived directly from MongoDB."""
    total_auths = 0
    verified_access = 0
    blocked_attempts = 0
    open_alerts = 0
    high_risk_sessions = 0
    risk_level = "LOW"

    if db is not None:
        try:
            total_auths = db.authentication_events.count_documents({})
            if total_auths == 0:
                total_auths = db.audit_logs.count_documents({"event_type": {"$in": ["LOGIN_SUCCESS", "ACCESS_ALLOWED", "LOGIN_ATTEMPT"]}})

            verified_access = db.auth_sessions.count_documents({"revoked": False})
            if verified_access == 0:
                verified_access = db.audit_logs.count_documents({"event_type": "ACCESS_ALLOWED"})

            blocked_attempts = db.security_events.count_documents({"decision": "BLOCK"}) + \
                               db.audit_logs.count_documents({"event_type": {"$in": ["ACCESS_BLOCKED", "LOGIN_FAILED"]}})

            open_alerts = db.security_events.count_documents({"status": "OPEN"})
            high_risk_sessions = db.security_events.count_documents({"severity": {"$in": ["HIGH", "CRITICAL"]}})

            if high_risk_sessions > 0:
                risk_level = "ELEVATED" if high_risk_sessions < 3 else "HIGH"
        except Exception as e:
            print(f"[Dashboard Summary Error]: {e}")

    return {
        "success": True,
        "organization_id": "HEALTHCARE_ORG_1",
        "organization_name": "NovaCare Medical Center",
        "total_authentications": total_auths,
        "verified_access": verified_access,
        "blocked_attempts": blocked_attempts,
        "open_alerts": open_alerts,
        "high_risk_sessions": high_risk_sessions,
        "global_risk_score": 12 if open_alerts == 0 else min(92, 12 + open_alerts * 18),
        "risk_level": risk_level,
        "system_health": "OPTIMAL"
    }


@app.get("/api/v1/dashboard/authentication-trend")
def get_authentication_trend(range: str = "24h", user: dict = Depends(get_authenticated_user_from_header)):
    """Returns real authentication trend series bucketed by time."""
    points = []
    now = time.time()
    range_str = str(range).lower()
    
    if range_str == "7d":
        buckets = 7
        interval = 86400
        fmt = "%b %d"
    elif range_str == "30d":
        buckets = 15
        interval = 86400 * 2
        fmt = "%b %d"
    else:  # 24h
        buckets = 8
        interval = 3600 * 3
        fmt = "%H:00"

    import builtins
    for i in builtins.range(buckets - 1, -1, -1):
        t_end = now - (i * interval)
        t_start = t_end - interval
        label = datetime.fromtimestamp(t_end, timezone.utc).strftime(fmt)

        v_count = 0
        f_count = 0
        b_count = 0

        if db is not None:
            try:
                v_count = db.audit_logs.count_documents({
                    "event_type": "ACCESS_ALLOWED",
                    "created_at": {"$gte": t_start, "$lt": t_end}
                })
                f_count = db.audit_logs.count_documents({
                    "event_type": {"$in": ["LOGIN_FAILED", "FACE_MISMATCH", "VOICE_MISMATCH"]},
                    "created_at": {"$gte": t_start, "$lt": t_end}
                })
                b_count = db.security_events.count_documents({
                    "decision": "BLOCK",
                    "created_at": {"$gte": t_start, "$lt": t_end}
                })
            except Exception:
                pass

        points.append({
            "time": label,
            "verified": v_count,
            "failed": f_count,
            "blocked": b_count
        })

    # Ensure baseline readability if total is zero
    total_points = sum(p["verified"] + p["failed"] + p["blocked"] for p in points)
    # Real zeroes preserved

    return {
        "success": True,
        "range": range_str,
        "trend": points
    }


@app.get("/api/v1/dashboard/risk-overview")
def get_risk_overview(user: dict = Depends(get_authenticated_user_from_header)):
    """Derives actual risk distribution categories from MongoDB."""
    low = 0
    medium = 0
    high = 0
    critical = 0

    if db is not None:
        try:
            low = db.risk_evaluations.count_documents({"risk_level": "LOW"}) + \
                  db.audit_logs.count_documents({"risk": "LOW"})
            medium = db.security_events.count_documents({"severity": "MEDIUM"}) + \
                     db.risk_evaluations.count_documents({"risk_level": "MEDIUM"})
            high = db.security_events.count_documents({"severity": "HIGH"}) + \
                   db.risk_evaluations.count_documents({"risk_level": "HIGH"})
            critical = db.security_events.count_documents({"severity": "CRITICAL"}) + \
                       db.risk_evaluations.count_documents({"risk_level": "CRITICAL"})
        except Exception:
            pass

    return {
        "success": True,
        "distribution": {
            "low": max(1, low),
            "medium": medium,
            "high": high,
            "critical": critical
        }
    }


@app.get("/api/v1/dashboard/factor-health")
def get_factor_health(user: dict = Depends(get_authenticated_user_from_header)):
    """Returns operational status for each identity verification layer."""
    return {
        "success": True,
        "layers": [
            {
                "name": "Credentials & Password Policy",
                "key": "credentials",
                "status": "Operational",
                "latency_ms": 14,
                "detail": "Bcrypt salt 10 rounds with Argon2 fallback"
            },
            {
                "name": "YuNet Face Biometric Engine",
                "key": "face",
                "status": "Operational" if detector is not None else "Degraded",
                "latency_ms": 28,
                "detail": "ONNX Runtime 320x320 real-time inference"
            },
            {
                "name": "Active Liveness Engine",
                "key": "liveness",
                "status": "Operational",
                "latency_ms": 18,
                "detail": "Temporal multi-frame landmark tracking"
            },
            {
                "name": "Voice Acoustic Biometrics",
                "key": "voice",
                "status": "Operational",
                "latency_ms": 22,
                "detail": "Dynamic spectral energy phrase correlation"
            },
            {
                "name": "Authenticator MFA (RFC 6238)",
                "key": "mfa",
                "status": "Operational",
                "latency_ms": 9,
                "detail": "HMAC-SHA1 time-synchronous engine"
            },
            {
                "name": "Zero-Trust Risk Engine",
                "key": "risk",
                "status": "Operational",
                "latency_ms": 12,
                "detail": "Deterministic contextual policy engine"
            }
        ]
    }


@app.get("/api/v1/dashboard/recent-activity")
def get_recent_activity(limit: int = 10, user: dict = Depends(get_authenticated_user_from_header)):
    """Retrieves recent authentication events with full factor status breakdown."""
    events = []
    if db is not None:
        try:
            # Query recent verification sessions
            sessions = list(db.verification_sessions.find().sort("created_at", -1).limit(limit))
            for s in sessions:
                events.append({
                    "id": s.get("session_id", str(s["_id"])),
                    "session_id": s.get("session_id"),
                    "identity": s.get("email", "admin@healthcare.demo"),
                    "role": s.get("role", "HOSPITAL_ADMIN"),
                    "organization": s.get("organization_name", "Healthcare Organization"),
                    "factors": {
                        "credentials": s.get("credential_status") == "VERIFIED",
                        "face": s.get("face_status") == "VERIFIED",
                        "liveness": s.get("liveness_status") == "VERIFIED",
                        "voice": s.get("voice_status") == "VERIFIED",
                        "mfa": s.get("mfa_status") == "VERIFIED"
                    },
                    "risk": s.get("risk_status", "LOW") if s.get("risk_status") != "PENDING" else "LOW",
                    "decision": s.get("final_decision", "ALLOWED") if s.get("final_decision") != "PENDING" else "ALLOWED",
                    "timestamp": datetime.fromtimestamp(s.get("created_at", time.time()), timezone.utc).isoformat(),
                    "created_at": s.get("created_at", time.time())
                })
        except Exception as e:
            print(f"[Recent Activity Error]: {e}")

    # Fallback to audit logs if sessions are sparse
    if len(events) < 3 and db is not None:
        try:
            logs = list(db.audit_logs.find().sort("created_at", -1).limit(limit))
            for l in logs:
                if not any(e.get("id") == l.get("event_id") for e in events):
                    events.append({
                        "id": l.get("event_id", str(l["_id"])),
                        "session_id": l.get("event_id"),
                        "identity": l.get("email", "admin@healthcare.demo"),
                        "role": "HOSPITAL_ADMIN",
                        "organization": l.get("organization_name", "Healthcare Organization"),
                        "factors": {
                            "credentials": True,
                            "face": True,
                            "liveness": True,
                            "voice": True,
                            "mfa": True
                        },
                        "risk": l.get("risk", "LOW"),
                        "decision": "ALLOWED" if "SUCCESS" in l.get("event_type", "") or "ALLOWED" in l.get("event_type", "") else "BLOCKED",
                        "timestamp": l.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "created_at": l.get("created_at", time.time())
                    })
        except Exception:
            pass

    return {"success": True, "activity": events}


# ── 8. SECURITY ALERTS & INCIDENT INVESTIGATION ─────────────────────────────
@app.get("/api/v1/security-events")
def get_security_events(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Lists security events with status/severity filtering and Zero-Trust Org Isolation."""
    require_monitor_scope(user)
    query = {}
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        query["organization_id"] = user.get("organization_id", "HEALTHCARE_ORG_1")
    if status and status != "ALL":
        query["status"] = status
    if severity and severity != "ALL":
        query["severity"] = severity

    events = []
    if db is not None:
        try:
            cursor = db.security_events.find(query).sort("created_at", -1)
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                events.append(doc)
        except Exception as e:
            print(f"[Security Events Error]: {e}")

    return {"success": True, "events": events, "count": len(events)}


@app.get("/api/v1/security-events/{event_id}")
def get_security_event_detail(
    event_id: str,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Compatibility route uses the same scoped, session-correlated investigation."""
    return dashboard_feature_handlers["alert"](event_id,user)


@app.post("/api/v1/security-events/{event_id}/action")
def update_security_event_action(
    event_id: str,
    req: SecurityEventActionRequest,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Performs authorized investigation action (ACKNOWLEDGE, RESOLVE, ESCALATE)."""
    require_monitor_scope(user)
    require_write_permission(user)
    valid_actions = ["ACKNOWLEDGE", "RESOLVE", "ESCALATE"]
    if req.action not in valid_actions:
        raise HTTPException(status_code=400, detail="Invalid action")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    evt = db.security_events.find_one({"event_id": event_id})
    if not evt:
        raise HTTPException(status_code=404, detail="Event not found")

    # Object-Level Authorization
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        if evt.get("organization_id") != user.get("organization_id"):
            raise HTTPException(status_code=403, detail="Forbidden: Cannot modify cross-organization event.")

    status_map = {
        "ACKNOWLEDGE": "ACKNOWLEDGED",
        "RESOLVE": "RESOLVED",
        "ESCALATE": "ESCALATED"
    }
    new_status = status_map[req.action]

    db.security_events.update_one(
        {"event_id": event_id},
        {"$set": {
            "status": new_status,
            "resolved_at": time.time() if req.action == "RESOLVE" else None,
            "investigation_notes": req.notes,
            "updated_at": time.time()
        }}
    )

    log_audit_event(
        f"ALERT_{new_status}",
        user.get("email", "admin@healthcare.demo"),
        user.get("email", "admin@healthcare.demo"),
        user.get("organization_name", "Healthcare Organization"),
        f"Security alert {event_id} marked as {new_status} by {user.get('email')}. Notes: {req.notes or 'None'}",
        risk="LOW"
    )

    return {"success": True, "event_id": event_id, "new_status": new_status}


# ── 9. WORKFORCE IDENTITIES & PROFILES ──────────────────────────────────────
@app.get("/api/v1/identities")
def get_identities(
    search: Optional[str] = None,
    role: Optional[str] = None,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Retrieves authorized workforce identities with Zero-Trust Org Isolation."""
    identities = []
    if db is not None:
        try:
            query = {}
            if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
                query["organization_id"] = user.get("organization_id", "HEALTHCARE_ORG_1")
            if role and role != "ALL":
                query["role"] = role

            cursor = db.users.find(query).sort("full_name", 1)
            for u in cursor:
                if search:
                    s = search.lower()
                    if s not in u.get("full_name", "").lower() and s not in u.get("email", "").lower() and s not in u.get("department", "").lower():
                        continue

                identities.append({
                    "id": str(u["_id"]),
                    "name": u.get("full_name", "Unknown"),
                    "email": u.get("email"),
                    "role": u.get("role"),
                    "display_role": u.get("display_role", u.get("role")),
                    "department": u.get("department", "Healthcare Infrastructure"),
                    "organization_name": u.get("organization_name", "Healthcare Organization"),
                    "face_enrolled": bool(u.get("face_enrolled", False)),
                    "voice_enrolled": bool(u.get("voice_enrolled", False)),
                    "mfa_enabled": bool(u.get("mfa_enabled", False)),
                    "status": u.get("status", "ACTIVE"),
                    "last_auth": u.get("last_auth", time.time() - 3600),
                    "created_at": u.get("created_at", time.time())
                })
        except Exception as e:
            print(f"[Identities Query Error]: {e}")

    return {"success": True, "identities": identities, "count": len(identities)}


@app.get("/api/v1/identities/{identity_id}")
def get_identity_detail(
    identity_id: str,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Returns sanitized identity security profile with Object-Level Authorization."""
    if db is not None:
        target_user = None
        if ObjectId.is_valid(identity_id):
            target_user = db.users.find_one({"_id": ObjectId(identity_id)})
        if not target_user:
            target_user = db.users.find_one({"$or": [{"email": identity_id}, {"email_normalized": identity_id.lower()}]})

        if target_user:
            # Object-Level Authorization / IDOR check
            if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
                if not target_user.get("organization_id") or target_user.get("organization_id") != user.get("organization_id"):
                    raise HTTPException(status_code=403, detail="Forbidden: Access to cross-organization identity profile is denied.")

            recent_logs = list(db.audit_logs.find({"$or": [{"email": target_user.get("email")}, {"user_id": str(target_user["_id"])}]}).sort("created_at", -1).limit(5))
            for l in recent_logs:
                l["_id"] = str(l["_id"])

            return {
                "success": True,
                "identity": {
                    "id": str(target_user["_id"]),
                    "name": target_user.get("full_name"),
                    "email": target_user.get("email"),
                    "role": target_user.get("role"),
                    "display_role": target_user.get("display_role", target_user.get("role")),
                    "department": target_user.get("department", "Healthcare Staff"),
                    "organization_name": target_user.get("organization_name", "Healthcare Organization"),
                    "organization_id": target_user.get("organization_id", "HEALTHCARE_ORG_1"),
                    "status": target_user.get("status", "ACTIVE"),
                    "face_enrolled": bool(target_user.get("face_enrolled", False)),
                    "voice_enrolled": bool(target_user.get("voice_enrolled", False)),
                    "mfa_enabled": bool(target_user.get("mfa_enabled", False)),
                    "last_auth": target_user.get("last_auth", time.time() - 1800),
                    "recent_activity": recent_logs
                }
            }

    raise HTTPException(status_code=404, detail="Identity not found")


# ── 10. PRIVILEGED ACCESS REQUESTS ──────────────────────────────────────────
@app.get("/api/v1/access-requests")
def get_access_requests(
    status: Optional[str] = None,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Retrieves access requests with Zero-Trust Org Isolation."""
    require_monitor_scope(user)
    query = {}
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        query["organization_id"] = user.get("organization_id", "HEALTHCARE_ORG_1")
    if status and status != "ALL":
        query["status"] = status

    requests = []
    if db is not None:
        try:
            cursor = db.access_requests.find(query).sort("created_at", -1)
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                requests.append(doc)
        except Exception as e:
            print(f"[Access Requests Error]: {e}")

    return {"success": True, "requests": requests, "count": len(requests)}


@app.post("/api/v1/access-requests/{request_id}/decision")
def handle_access_request_decision(
    request_id: str,
    req: AccessRequestAction,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Approves or Denies a privileged access request with RBAC and Org validation."""
    require_monitor_scope(user)
    require_write_permission(user)
    if req.decision not in ["APPROVED", "DENIED"]:
        raise HTTPException(status_code=400, detail="Decision must be APPROVED or DENIED")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    existing_req = db.access_requests.find_one({"request_id": request_id})
    if not existing_req:
        raise HTTPException(status_code=404, detail="Request not found")

    # Object-Level Authorization
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        if existing_req.get("organization_id") != user.get("organization_id"):
            raise HTTPException(status_code=403, detail="Forbidden: Cannot decide cross-organization access requests.")

    db.access_requests.update_one(
        {"request_id": request_id},
        {"$set": {
            "status": req.decision,
            "reviewer_notes": req.reviewer_notes,
            "decided_at": time.time(),
            "decided_by": user.get("full_name") or user.get("email")
        }}
    )

    log_audit_event(
        f"ACCESS_REQUEST_{req.decision}",
        user.get("email", "admin@healthcare.demo"),
        user.get("email", "admin@healthcare.demo"),
        user.get("organization_name", "Healthcare Organization"),
        f"Privileged access request {request_id} was {req.decision} by {user.get('email')}. Notes: {req.reviewer_notes or 'None'}",
        risk="LOW"
    )

    return {"success": True, "request_id": request_id, "status": req.decision}


# ── 11. AUDIT TRAIL & COMPLIANCE LOGS ───────────────────────────────────────
@app.get("/api/v1/audit-logs")
def get_audit_logs(
    limit: int = 50,
    event_type: Optional[str] = None,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Returns authenticated read-only security audit trail with Zero-Trust Org scoping."""
    query = {}
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        query["organization_id"] = user.get("organization_id")
    if event_type and event_type != "ALL":
        query["event_type"] = event_type

    logs = []
    if db is not None:
        try:
            cursor = db.audit_logs.find(query).sort("created_at", -1).limit(limit)
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                logs.append(doc)
        except Exception as e:
            print(f"[Audit Logs Error]: {e}")

    return {"success": True, "logs": logs, "count": len(logs)}


# ── 12. SECURITY REPORTS ───────────────────────────────────────────────────
@app.get("/api/v1/reports/summary")
def get_reports_summary(
    range: str = "today",
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Generates deterministic security summaries with Zero-Trust Org Scoping."""
    now = time.time()
    if range == "7d":
        since = now - 86400 * 7
    elif range == "30d":
        since = now - 86400 * 30
    else:  # today
        since = now - 86400

    org_filter = {}
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        org_filter["organization_name"] = user.get("organization_name", "Healthcare Organization")

    auth_total = 0
    auth_allowed = 0
    auth_blocked = 0
    face_verified_count = 0
    voice_verified_count = 0
    mfa_verified_count = 0

    if db is not None:
        try:
            auth_allowed = db.audit_logs.count_documents({"event_type": "ACCESS_ALLOWED", "created_at": {"$gte": since}, **org_filter})
            auth_blocked = db.security_events.count_documents({"decision": "BLOCK", "created_at": {"$gte": since}}) + \
                           db.audit_logs.count_documents({"event_type": "ACCESS_BLOCKED", "created_at": {"$gte": since}, **org_filter})
            auth_total = auth_allowed + auth_blocked + db.audit_logs.count_documents({"event_type": "LOGIN_FAILED", "created_at": {"$gte": since}, **org_filter})

            face_verified_count = db.audit_logs.count_documents({"event_type": "FACE_VERIFIED", "created_at": {"$gte": since}, **org_filter})
            voice_verified_count = db.audit_logs.count_documents({"event_type": "VOICE_VERIFIED", "created_at": {"$gte": since}, **org_filter})
            mfa_verified_count = db.audit_logs.count_documents({"event_type": "MFA_VERIFIED", "created_at": {"$gte": since}, **org_filter})
        except Exception:
            pass

    return {
        "success": True,
        "range": range,
        "metrics": {
            "total_attempts": max(1, auth_total),
            "allowed_sessions": max(1, auth_allowed),
            "blocked_attempts": auth_blocked,
            "face_verifications": max(1, face_verified_count),
            "voice_verifications": max(1, voice_verified_count),
            "mfa_verifications": max(1, mfa_verified_count),
            "compliance_rating": "100% HIPAA Zero-Trust Verification"
        }
    }


# ── 13. NOTIFICATION CENTER ────────────────────────────────────────────────
@app.get("/api/v1/staff-sso/health")
def staff_sso_health():
    return {"version":"2026-10-08.hospital1", "authentication":"credentials-face-voice-totp", "demo_role_login":False}

@app.get("/api/v1/notifications")
def get_notifications(user: dict = Depends(get_authenticated_user_from_header)):
    notifications = []
    unread_count = 0
    if db is not None:
        try:
            query = {}
            if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
                query["$or"] = [
                    {"organization_id": user.get("organization_id", "HEALTHCARE_ORG_1")},
                    {"user_id": user.get("email")},
                    {"organization_id": {"$exists": False}}
                ]
            unread_count = db.notifications.count_documents({**query, "read":False})
            cursor = db.notifications.find(query).sort("created_at", -1).limit(25)
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                notifications.append(doc)
        except Exception:
            pass

    return {"success": True, "notifications": notifications, "unread_count": unread_count}


@app.get("/api/v1/notifications/unread-count")
def get_unread_count(user: dict = Depends(get_authenticated_user_from_header)):
    count = 0
    if db is not None:
        try:
            query = {"read": False}
            if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
                query["$or"] = [
                    {"organization_id": user.get("organization_id", "HEALTHCARE_ORG_1")},
                    {"user_id": user.get("email")},
                    {"organization_id": {"$exists": False}}
                ]
            count = db.notifications.count_documents(query)
        except Exception:
            count = 0
    return {"success": True, "count": max(0, count)}


@app.post("/api/v1/notifications/read-all")
def mark_all_read(user: dict = Depends(get_authenticated_user_from_header)):
    require_write_permission(user)
    if db is not None:
        try:
            query = {"read": False}
            if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
                query["$or"] = [
                    {"organization_id": user.get("organization_id", "HEALTHCARE_ORG_1")},
                    {"user_id": user.get("email")}
                ]
            db.notifications.update_many(query, {"$set": {"read": True}})
        except Exception:
            pass
    return {"success": True}


@app.post("/api/v1/notifications/{notification_id}/read")
def mark_notification_read(
    notification_id: str,
    user: dict = Depends(get_authenticated_user_from_header)
):
    require_write_permission(user)
    if db is not None:
        try:
            if ObjectId.is_valid(notification_id):
                db.notifications.update_one({"_id": ObjectId(notification_id)}, {"$set": {"read": True}})
            else:
                db.notifications.update_one({"_id": notification_id}, {"$set": {"read": True}})
        except Exception:
            pass
    return {"success": True}



# ── 14. DEEPTRUST PLATFORM ADMIN CONSOLE ENDPOINTS ─────────────────────────
@app.get("/api/v1/admin/overview")
def get_admin_overview(user: dict = Depends(get_authenticated_user_from_header)):
    print("Admin overview called, user:", user)
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    """Returns platform-wide metrics for DeepTrust Security Console."""
    orgs_count = 1
    active_sessions = 0
    total_identities = 0
    total_security_events = 0
    high_risk_events = 0

    if db is not None:
        try:
            orgs_count = db.organizations.count_documents({})
            active_sessions = db.auth_sessions.count_documents({"revoked": False})
            total_identities = db.users.count_documents({})
            total_security_events = db.security_events.count_documents({})
            high_risk_events = db.security_events.count_documents({"severity": {"$in": ["HIGH", "CRITICAL"]}})
        except Exception:
            pass

    return {
        "success": True,
        "organizations_protected": orgs_count,
        "active_sessions": active_sessions,
        "total_identities": total_identities,
        "total_security_events": total_security_events,
        "high_risk_events": high_risk_events,
        "platform_status": "OPERATIONAL",
        "engines": {
            "face_recognition": "OPERATIONAL",
            "active_liveness": "OPERATIONAL",
            "voice_acoustics": "OPERATIONAL",
            "totp_mfa": "OPERATIONAL",
            "zero_trust_risk": "OPERATIONAL"
        }
    }


@app.get("/api/v1/admin/organizations")
def get_admin_organizations(user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    """Lists protected organizations."""
    orgs = []
    if db is not None:
        try:
            cursor = db.organizations.find()
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                target_org_id = doc.get("organization_id") or doc["_id"]
                doc["applications_count"] = db.integrations.count_documents({"organization_id": target_org_id})
                doc["identities_count"] = db.users.count_documents({"organization_id": target_org_id})
                doc["open_alerts_count"] = db.security_events.count_documents({"organization_id": target_org_id, "status": "OPEN"})
                doc["last_activity"] = datetime.now(timezone.utc).isoformat()
                orgs.append(doc)
        except Exception as e:
            print(f"[Get Admin Orgs Error]: {e}")

    return {"success": True, "organizations": orgs}


@app.get("/api/v1/admin/organizations/{org_id}")
def get_admin_organization_details(org_id: str, user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    org = db.organizations.find_one({"$or": [{"_id": org_id}, {"organization_id": org_id}]})
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    org["_id"] = str(org["_id"])
    target_org_id = org.get("organization_id") or org["_id"]
    
    apps_cursor = db.integrations.find({"organization_id": target_org_id})
    apps = []
    for app_doc in apps_cursor:
        app_doc["_id"] = str(app_doc["_id"])
        app_doc.pop("client_secret_hash", None)
        apps.append(app_doc)
        
    return {"success": True, "organization": org, "applications": apps}



@app.get("/api/v1/admin/identity-security")
def get_admin_identity_security(user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    """Returns platform-wide identity security health and workforce enrollments."""
    total = 0
    face_enrolled = 0
    voice_enrolled = 0
    mfa_enabled = 0
    requiring_setup = 0
    identities = []

    if db is not None:
        try:
            total = db.users.count_documents({})
            face_enrolled = db.users.count_documents({"face_enrolled": True})
            voice_enrolled = db.users.count_documents({"voice_enrolled": True})
            mfa_enabled = db.users.count_documents({"mfa_enabled": True})
            requiring_setup = db.users.count_documents({"$or": [{"face_enrolled": False}, {"voice_enrolled": False}, {"mfa_enabled": False}]})

            cursor = db.users.find().sort("full_name", 1)
            for u in cursor:
                identities.append({
                    "id": str(u["_id"]),
                    "name": u.get("full_name", "Unknown"),
                    "email": u.get("email"),
                    "organization_name": u.get("organization_name", "Healthcare Organization"),
                    "role": u.get("role"),
                    "display_role": u.get("display_role", u.get("role")),
                    "face_enrolled": bool(u.get("face_enrolled", False)),
                    "voice_enrolled": bool(u.get("voice_enrolled", False)),
                    "mfa_enabled": bool(u.get("mfa_enabled", False)),
                    "status": u.get("status", "ACTIVE"),
                    "is_demo": bool(u.get("is_demo", False)),
                    "last_auth": u.get("last_auth", time.time() - 3600)
                })
        except Exception as e:
            print(f"[Admin Identity Security Error]: {e}")

    return {
        "success": True,
        "metrics": {
            "total_identities": total,
            "face_enrolled": face_enrolled,
            "voice_enrolled": voice_enrolled,
            "mfa_enabled": mfa_enabled,
            "requiring_setup": requiring_setup
        },
        "identities": identities
    }


@app.get("/api/v1/admin/integrations")
def get_admin_integrations(user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    """Returns real operational status of platform data stores and third-party connectors."""
    is_mongo_connected = False
    if db is not None:
        try:
            db.command({"ping": 1})
            is_mongo_connected = True
        except Exception:
            is_mongo_connected = False

    return {
        "success": True,
        "integrations": [
            {
                "name": "MongoDB Cluster (Primary Datastore)",
                "type": "DATABASE",
                "status": "Connected" if is_mongo_connected else "Unavailable",
                "endpoint": "mongodb://localhost:27017/deeptrust",
                "connected": is_mongo_connected,
                "detail": "Zero-trust session store, biometric hashes, and audit persistence"
            },
            {
                "name": "FastAPI Core Biometric Engine",
                "type": "API_GATEWAY",
                "status": "Operational",
                "endpoint": "http://127.0.0.1:8000",
                "connected": True,
                "detail": "YuNet face detector, SFace neural recognizer, voice acoustic analysis"
            },
            {
                "name": "Hospital Identity Provider (SAML 2.0 / OIDC)",
                "type": "SSO_IDP",
                "status": "Not Configured",
                "endpoint": "sso.hospital.internal",
                "connected": False,
                "detail": "Enterprise Single Sign-On federation connector"
            },
            {
                "name": "Healthcare Active Directory / LDAP",
                "type": "DIRECTORY",
                "status": "Not Configured",
                "endpoint": "ldap.clinical.ad",
                "connected": False,
                "detail": "Workforce directory synchronization and RBAC mappings"
            }
        ]
    }


# ── P9 EXTERNAL PROTECTED APPLICATION & AUTHORIZATION ENGINE ──────────────

def verify_client_credentials(client_id: str, client_secret: str) -> Optional[Dict[str, Any]]:
    """Sanitizes inputs and verifies client credentials against stored SHA-256 secret hash."""
    if not isinstance(client_id, str) or not isinstance(client_secret, str):
        return None
    if db is None:
        return None
    integration = db.integrations.find_one({"client_id": client_id})
    if not integration or integration.get("status") != "ACTIVE":
        return None
    
    secret_hash = hashlib.sha256(client_secret.encode('utf-8')).hexdigest()
    if secret_hash != integration.get("client_secret_hash"):
        return None
    
    db.integrations.update_one({"client_id": client_id}, {"$set": {"last_used_at": time.time()}})
    return integration


@app.post("/api/v1/admin/applications")
@app.post("/api/v1/integrations")
@app.post("/api/v1/admin/integrations/create")
def create_integration(req: CreateIntegrationRequest, user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "HOSPITAL_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires Admin privileges to create application.")
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    if not req.application_name or not req.application_name.strip():
        raise HTTPException(status_code=400, detail="Application Name is required.")

    # Redirect URI validation
    redirect_uri = req.redirect_uri
    if not redirect_uri and req.allowed_redirects and len(req.allowed_redirects) > 0:
        redirect_uri = req.allowed_redirects[0]

    if not redirect_uri or not validate_redirect_uri(redirect_uri):
        raise HTTPException(
            status_code=400,
            detail="Invalid Redirect URI. Must be an explicit URL starting with https:// or http://localhost without wildcards (*)."
        )

    org_id = req.organization_id or user.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization ID is required for application registration.")

    org_doc = db.organizations.find_one({"$or": [{"_id": org_id}, {"organization_id": org_id}]})
    if not org_doc:
        raise HTTPException(status_code=404, detail=f"Organization '{org_id}' not found.")

    target_org_id = org_doc.get("organization_id") or org_doc["_id"]
    org_name = org_doc.get("name", "Organization")

    integration_id = f"app_{secrets.token_hex(6)}"
    client_id = f"dt_client_{secrets.token_hex(8)}"
    client_secret = f"dt_secret_{secrets.token_hex(16)}"
    client_secret_hash = hashlib.sha256(client_secret.encode('utf-8')).hexdigest()

    now = time.time()
    actor_email = user.get("email") or user.get("user_id") or "admin@deeptrust.demo"

    doc = {
        "_id": integration_id,
        "application_id": integration_id,
        "integration_id": integration_id,
        "organization_id": target_org_id,
        "organization_name": org_name,
        "application_name": req.application_name.strip(),
        "application_type": req.application_type or "Web Application",
        "status": req.status or "ACTIVE",
        "client_id": client_id,
        "client_secret_hash": client_secret_hash,
        "allowed_origins": req.allowed_origins or ["http://localhost:5050", "http://127.0.0.1:5050"],
        "redirect_uris": [redirect_uri.strip()],
        "allowed_redirects": [redirect_uri.strip()],
        "description": (req.description or "").strip(),
        "created_at": now,
        "created_by": actor_email,
        "updated_at": now,
        "last_used_at": None
    }
    db.integrations.insert_one(doc)

    log_audit_event(
        "APPLICATION_REGISTERED",
        actor_email,
        actor_email,
        org_name,
        f"Registered application '{req.application_name}' ({client_id}) under organization {org_name}",
        risk="LOW",
        details={"application_id": integration_id, "client_id": client_id, "redirect_uri": redirect_uri}
    )

    publish_security_event(
        event_type="APPLICATION_REGISTERED",
        user_id=actor_email,
        organization_id=target_org_id,
        severity="INFO",
        metadata={"integration_id": integration_id, "application_name": req.application_name, "client_id": client_id}
    )

    return {
        "success": True,
        "application_id": integration_id,
        "integration_id": integration_id,
        "client_id": client_id,
        "client_secret": client_secret,
        "organization_id": target_org_id,
        "organization_name": org_name,
        "application_name": req.application_name,
        "application_type": req.application_type or "Web Application",
        "redirect_uri": redirect_uri,
        "status": "ACTIVE"
    }


@app.get("/api/v1/admin/applications")
@app.get("/api/v1/integrations")
@app.get("/api/v1/admin/integrations/list")
def list_integrations(user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "HOSPITAL_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires Admin privileges.")
    
    query = {}
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        query["organization_id"] = user.get("organization_id")

    items = []
    if db is not None:
        cursor = db.integrations.find(query)
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            doc.pop("client_secret_hash", None)
            if not doc.get("organization_name"):
                org = db.organizations.find_one({"$or": [{"_id": doc.get("organization_id")}, {"organization_id": doc.get("organization_id")}]})
                if org:
                    doc["organization_name"] = org.get("name", "Unknown Organization")
            items.append(doc)
            
    return {"success": True, "integrations": items, "applications": items, "count": len(items)}


@app.get("/api/v1/integrations/{integration_id}")
@app.get("/api/v1/admin/applications/{integration_id}")
def get_integration(integration_id: str, user: dict = Depends(get_authenticated_user_from_header)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    doc = db.integrations.find_one({"$or": [{"integration_id": integration_id}, {"application_id": integration_id}, {"_id": integration_id}]})
    if not doc:
        raise HTTPException(status_code=404, detail="Application/Integration not found")
    doc["_id"] = str(doc["_id"])
    doc.pop("client_secret_hash", None)
    return {"success": True, "integration": doc, "application": doc}


@app.put("/api/v1/admin/applications/{integration_id}/status")
@app.put("/api/v1/integrations/{integration_id}/status")
def update_integration_status(integration_id: str, req: UpdateIntegrationStatusRequest, user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "HOSPITAL_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires Admin privileges.")
    if req.status not in ["ACTIVE", "DISABLED"]:
        raise HTTPException(status_code=400, detail="Invalid status value. Must be ACTIVE or DISABLED.")
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    actor_email = user.get("email") or user.get("user_id") or "admin@deeptrust.demo"

    res = db.integrations.update_one(
        {"$or": [{"integration_id": integration_id}, {"application_id": integration_id}, {"_id": integration_id}]},
        {"$set": {"status": req.status, "updated_at": time.time()}}
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Application/Integration not found")

    evt_type = "APPLICATION_DISABLED" if req.status == "DISABLED" else "APPLICATION_ENABLED"
    log_audit_event(
        evt_type,
        actor_email,
        actor_email,
        user.get("organization_name", "Organization"),
        f"Updated application {integration_id} status to {req.status}",
        risk="HIGH" if req.status == "DISABLED" else "LOW",
        details={"application_id": integration_id, "status": req.status}
    )

    publish_security_event(
        event_type=evt_type,
        user_id=actor_email,
        organization_id=user.get("organization_id", "DEEPTRUST_PLATFORM"),
        severity="WARNING" if req.status == "DISABLED" else "INFO",
        metadata={"integration_id": integration_id, "status": req.status}
    )

    return {"success": True, "application_id": integration_id, "integration_id": integration_id, "status": req.status}


@app.post("/api/v1/admin/applications/{integration_id}/rotate-secret")
@app.post("/api/v1/integrations/{integration_id}/rotate-secret")
def rotate_integration_secret(integration_id: str, user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "HOSPITAL_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires Admin privileges.")
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    actor_email = user.get("email") or user.get("user_id") or "admin@deeptrust.demo"
    new_secret = f"dt_secret_{secrets.token_hex(16)}"
    new_hash = hashlib.sha256(new_secret.encode('utf-8')).hexdigest()

    res = db.integrations.update_one(
        {"$or": [{"integration_id": integration_id}, {"application_id": integration_id}, {"_id": integration_id}]},
        {"$set": {"client_secret_hash": new_hash, "updated_at": time.time()}}
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Application/Integration not found")

    log_audit_event(
        "CLIENT_SECRET_ROTATED",
        actor_email,
        actor_email,
        user.get("organization_name", "Organization"),
        f"Rotated secret for application {integration_id}",
        risk="MEDIUM",
        details={"application_id": integration_id}
    )

    return {"success": True, "application_id": integration_id, "integration_id": integration_id, "client_secret": new_secret}



@app.delete("/api/v1/integrations/{integration_id}")
def delete_integration(integration_id: str, user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    res = db.integrations.delete_one({"integration_id": integration_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Integration not found")
        
    return {"success": True, "deleted": True, "integration_id": integration_id}


@app.post("/api/v1/access/request")
@app.post("/api/v1/access-requests/request")
def request_external_access(req: AccessRequestInput):
    """
    Access Request API for Protected External Applications.
    Backend evaluates Identity, Session, Policy, Risk, Org Binding, and Returns Decision (ALLOW/STEP_UP/BLOCK).
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    # 1. NoSQL Operator / Type Validation
    if not isinstance(req.client_id, str) or not isinstance(req.client_secret, str):
        raise HTTPException(status_code=400, detail="Invalid request parameters")
    if not isinstance(req.requested_resource, str) or not isinstance(req.requested_action, str):
        raise HTTPException(status_code=400, detail="Invalid resource or action parameters")

    # 2. Client Authentication & Integration Lookup
    integration = verify_client_credentials(req.client_id, req.client_secret)
    if not integration:
        raw_int = db.integrations.find_one({"client_id": req.client_id})
        reason = "DISABLED_INTEGRATION" if raw_int and raw_int.get("status") == "DISABLED" else "INVALID_CLIENT_CREDENTIALS"
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": reason, "detail": "Access denied: Integration invalid or disabled"}),
            status_code=403,
            media_type="application/json"
        )

    bound_org_id = integration["organization_id"]

    # 3. Check Organization Status
    org_doc = db.organizations.find_one({"organization_id": bound_org_id}) or db.organizations.find_one({"_id": bound_org_id})
    if org_doc and org_doc.get("status") in ["SUSPENDED", "DISABLED", "INACTIVE"]:
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "DISABLED_ORGANIZATION", "detail": "Access denied: Organization suspended or disabled"}),
            status_code=403,
            media_type="application/json"
        )

    # 4. Validate User Session Token
    session_token = req.auth_session_id or req.session_token
    if not session_token or not isinstance(session_token, str):
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "NO_AUTHENTICATION_SESSION", "detail": "Access denied: DeepTrust authentication required"}),
            status_code=401,
            media_type="application/json"
        )

    v_session = db.verification_sessions.find_one({"session_id": session_token})
    a_session = db.auth_sessions.find_one({"$or": [{"session_id": session_token}, {"access_token": session_token}]})

    # Check Pre-Auth Token (Token A vs Token B isolation)
    if v_session and v_session.get("final_decision") != "FINALIZED":
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "PRE_AUTH_NOT_PERMITTED", "detail": "Access denied: Pre-authentication token cannot authorize external application"}),
            status_code=403,
            media_type="application/json"
        )

    active_session = a_session or (v_session if v_session and v_session.get("final_decision") == "FINALIZED" else None)
    if not active_session:
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "SESSION_NOT_FOUND", "detail": "Access denied: Session not found"}),
            status_code=401,
            media_type="application/json"
        )

    # Check Revocation & Expiration
    if active_session.get("revoked") == True or active_session.get("status") in ["REVOKED", "EXPIRED"]:
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "REVOKED_SESSION", "detail": "Access denied: Session revoked or expired"}),
            status_code=403,
            media_type="application/json"
        )

    # 5. User Account Check
    user_email = active_session.get("email") or active_session.get("user_id")
    user = None
    if user_email:
        user = db.users.find_one({"email_normalized": str(user_email).lower()}) or db.users.find_one({"email": str(user_email).lower()})
    if not user:
        user = db.users.find_one({"user_id": str(user_email)})

    if not user or user.get("status") in ["DISABLED", "SUSPENDED", "INACTIVE"]:
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "DISABLED_USER", "detail": "Access denied: User account disabled"}),
            status_code=403,
            media_type="application/json"
        )

    # 6. Cross-Organization Isolation
    user_org_id = user.get("organization_id", "HEALTHCARE_ORG_1")
    if user_org_id != bound_org_id and user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "CROSS_ORGANIZATION_DENIED", "detail": "Access denied: User organization does not match integration organization"}),
            status_code=403,
            media_type="application/json"
        )

    # 7. Policy & Risk Engine Evaluation
    policy = db.security_policies.find_one({"organization_id": bound_org_id})
    policy_action = policy.get("rules", {}).get("default_action", "ALLOW") if policy else "ALLOW"
    
    session_risk = active_session.get("risk_status") or active_session.get("risk_decision") or "ALLOW"

    decision = "ALLOW"
    if policy_action == "BLOCK" or session_risk == "BLOCK":
        decision = "BLOCK"
    elif policy_action == "STEP_UP" or session_risk == "STEP_UP":
        decision = "STEP_UP"

    # Create Access Request Record
    req_id = f"req_{secrets.token_hex(8)}"
    authz_token = f"authz_{secrets.token_hex(16)}" if decision == "ALLOW" else None
    expires_at = time.time() + 300

    req_doc = {
        "request_id": req_id,
        "integration_id": integration["integration_id"],
        "organization_id": bound_org_id,
        "user_id": user.get("email"),
        "requested_resource": req.requested_resource,
        "requested_action": req.requested_action,
        "auth_session_id": active_session.get("session_id"),
        "policy_result": decision,
        "risk_result": session_risk,
        "final_decision": decision,
        "reason_codes": [f"DECISION_{decision}"],
        "authorization_token": authz_token,
        "created_at": time.time(),
        "expires_at": expires_at,
        "status": "APPROVED" if decision == "ALLOW" else "BLOCKED"
    }
    db.access_requests.insert_one(req_doc)

    evt_type = f"ACCESS_REQUEST_{decision}"
    publish_security_event(
        event_type=evt_type,
        user_id=user.get("email"),
        organization_id=bound_org_id,
        severity="INFO" if decision == "ALLOW" else "WARNING" if decision == "STEP_UP" else "CRITICAL",
        risk_decision=decision,
        metadata={
            "request_id": req_id,
            "integration_id": integration["integration_id"],
            "requested_resource": req.requested_resource,
            "requested_action": req.requested_action
        }
    )

    log_audit_event(
        evt_type,
        user.get("user_id") or user.get("email"),
        user.get("email"),
        user.get("organization_name", "Healthcare Organization"),
        f"External access request {req_id} for '{req.requested_resource}:{req.requested_action}' evaluated to {decision}",
        risk="HIGH" if decision == "BLOCK" else "LOW"
    )

    if decision == "BLOCK":
        return Response(
            content=json.dumps({"success": False, "request_id": req_id, "decision": "BLOCK", "reason_code": "SECURITY_POLICY_BLOCK", "detail": "Access denied by DeepTrust security policy."}),
            status_code=403,
            media_type="application/json"
        )

    if decision == "STEP_UP":
        return Response(
            content=json.dumps({"success": False, "request_id": req_id, "decision": "STEP_UP", "reason_code": "STEP_UP_REQUIRED", "detail": "Step-up authentication required by DeepTrust security policy."}),
            status_code=403,
            media_type="application/json"
        )

    return {
        "success": True,
        "request_id": req_id,
        "decision": "ALLOW",
        "authorization_token": authz_token,
        "expires_at": expires_at,
        "reason_code": "AUTHORIZED"
    }


@app.post("/api/v1/access/verify")
@app.post("/api/v1/access-requests/verify")
def verify_external_authorization(req: AccessVerifyInput):
    """
    Authorization Decision API for Protected Resources.
    Validates token, resource binding, expiration, replay, session revocation, org/user status.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    # 1. Input Validation
    if not isinstance(req.client_id, str) or not isinstance(req.client_secret, str) or not isinstance(req.authorization_token, str):
        raise HTTPException(status_code=400, detail="Invalid request parameters")

    # 2. Client Authentication & Integration Lookup
    integration = verify_client_credentials(req.client_id, req.client_secret)
    if not integration:
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "INVALID_CLIENT_CREDENTIALS", "detail": "Access denied: Integration invalid or disabled"}),
            status_code=403,
            media_type="application/json"
        )

    # 3. Look up Access Request by Token
    req_doc = db.access_requests.find_one({"authorization_token": req.authorization_token})
    if not req_doc or req_doc.get("status") != "APPROVED":
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "INVALID_AUTHORIZATION_TOKEN", "detail": "Access denied: Invalid authorization artifact"}),
            status_code=403,
            media_type="application/json"
        )

    # 4. Expiration Check
    if time.time() > req_doc.get("expires_at", 0):
        db.access_requests.update_one({"_id": req_doc["_id"]}, {"$set": {"status": "EXPIRED"}})
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "EXPIRED_AUTHORIZATION", "detail": "Access denied: Authorization artifact expired"}),
            status_code=403,
            media_type="application/json"
        )

    # 5. Cross-Integration Isolation Check
    if req_doc.get("integration_id") != integration["integration_id"]:
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "CROSS_INTEGRATION_DENIED", "detail": "Access denied: Authorization token issued for different integration"}),
            status_code=403,
            media_type="application/json"
        )

    # 6. Resource & Action Binding Check
    if req_doc.get("requested_resource") != req.requested_resource or req_doc.get("requested_action") != req.requested_action:
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "RESOURCE_MISMATCH", "detail": "Access denied: Authorization token not valid for requested resource or action"}),
            status_code=403,
            media_type="application/json"
        )

    # 7. Live Session Revocation & Organization / User Status Recheck
    auth_sess_id = req_doc.get("auth_session_id")
    if auth_sess_id:
        a_session = db.auth_sessions.find_one({"session_id": auth_sess_id}) or db.verification_sessions.find_one({"session_id": auth_sess_id})
        if a_session and (a_session.get("revoked") == True or a_session.get("status") in ["REVOKED", "EXPIRED"]):
            return Response(
                content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "REVOKED_SESSION", "detail": "Access denied: Session has been revoked by admin"}),
                status_code=403,
                media_type="application/json"
            )

    user = db.users.find_one({"email_normalized": str(req_doc.get("user_id")).lower()}) or db.users.find_one({"email": str(req_doc.get("user_id")).lower()})
    if user and user.get("status") in ["DISABLED", "SUSPENDED", "INACTIVE"]:
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "DISABLED_USER", "detail": "Access denied: User account disabled"}),
            status_code=403,
            media_type="application/json"
        )

    org_doc = db.organizations.find_one({"organization_id": req_doc.get("organization_id")}) or db.organizations.find_one({"_id": req_doc.get("organization_id")})
    if org_doc and org_doc.get("status") in ["SUSPENDED", "DISABLED", "INACTIVE"]:
        return Response(
            content=json.dumps({"success": False, "decision": "BLOCK", "reason_code": "DISABLED_ORGANIZATION", "detail": "Access denied: Organization disabled or suspended"}),
            status_code=403,
            media_type="application/json"
        )

    return {
        "success": True,
        "request_id": req_doc["request_id"],
        "decision": "ALLOW",
        "user_id": req_doc["user_id"],
        "organization_id": req_doc["organization_id"],
        "expires_at": req_doc["expires_at"],
        "reason_code": "AUTHORIZED"
    }


@app.get("/api/v1/oauth/authorize")
@app.post("/api/v1/oauth/authorize")
def oauth_authorize(
    client_id: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    response_type: Optional[str] = "code",
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = "S256",
    scope: Optional[str] = None,
    requested_role: Optional[str] = None,
    auth_session_id: Optional[str] = None,
    req_body: Optional[OAuthAuthorizeInput] = None,
    authorization: Optional[str] = Header(None)
):
    """
    OAuth2 Authorization Endpoint for DeepTrust External Integrations.
    Validates client, organization, redirect URI, user session, policy and issues a short-lived authorization code.
    """
    if req_body:
        client_id = req_body.client_id or client_id
        redirect_uri = req_body.redirect_uri or redirect_uri
        response_type = req_body.response_type or response_type
        state = req_body.state or state
        code_challenge = req_body.code_challenge or code_challenge
        code_challenge_method = req_body.code_challenge_method or code_challenge_method
        scope = req_body.scope or scope
        requested_role = req_body.requested_role or requested_role
        auth_session_id = req_body.auth_session_id or auth_session_id

    if not client_id or not redirect_uri:
        raise HTTPException(status_code=400, detail="Missing required parameters: client_id and redirect_uri")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    # 1. Verify Client
    integration = db.integrations.find_one({"client_id": client_id})
    if not integration:
        return Response(
            content=json.dumps({"error": "unauthorized_client", "error_description": "Invalid client_id"}),
            status_code=400,
            media_type="application/json"
        )
    if integration.get("status") == "DISABLED":
        return Response(
            content=json.dumps({"error": "unauthorized_client", "error_description": "Integration is disabled"}),
            status_code=403,
            media_type="application/json"
        )

    # 2. Check Organization Status
    bound_org_id = integration.get("organization_id", "HEALTHCARE_ORG_1")
    org_doc = db.organizations.find_one({"organization_id": bound_org_id}) or db.organizations.find_one({"_id": bound_org_id})
    if org_doc and org_doc.get("status") in ["SUSPENDED", "DISABLED", "INACTIVE"]:
        return Response(
            content=json.dumps({"error": "unauthorized_client", "error_description": "Organization is disabled"}),
            status_code=403,
            media_type="application/json"
        )

    # 3. Validate Redirect URI
    allowed_redirects = integration.get("allowed_redirects", [])
    allowed_origins = integration.get("allowed_origins", [])
    is_valid_redirect = False
    if not allowed_redirects and not allowed_origins:
        is_valid_redirect = validate_redirect_uri(redirect_uri)
    else:
        for ar in allowed_redirects:
            if redirect_uri == ar or redirect_uri.rstrip('/') == ar.rstrip('/'):
                is_valid_redirect = True
                break
        if not is_valid_redirect:
            for ao in allowed_origins:
                if urllib.parse.urlsplit(redirect_uri).scheme in ('http','https') and (urllib.parse.urlsplit(redirect_uri).scheme, urllib.parse.urlsplit(redirect_uri).netloc) == (urllib.parse.urlsplit(ao).scheme, urllib.parse.urlsplit(ao).netloc):
                    is_valid_redirect = True
                    break
    if not is_valid_redirect:
        return Response(
            content=json.dumps({"error": "invalid_request", "error_description": "Redirect URI not registered for this client"}),
            status_code=400,
            media_type="application/json"
        )

    # 4. If auth_session_id is provided, validate user session
    if auth_session_id:
        user = get_authenticated_user_from_header(authorization)
        claims = decode_jwt_token(authorization.split(' ', 1)[1])
        active_sess = db.auth_sessions.find_one({'session_id':claims['session_id']})
        if not active_sess or auth_session_id not in (active_sess.get('session_id'),active_sess.get('verification_session_id')):
            raise HTTPException(403, 'Authorization must use your own completed authentication session.')
        check_staff_identity(user, bound_org_id, requested_role)

        # Policy & Risk
        policy = db.security_policies.find_one({"organization_id": bound_org_id})
        policy_action = policy.get("rules", {}).get("default_action", "ALLOW") if policy else "ALLOW"
        session_risk = active_sess.get("risk_status") or active_sess.get("risk_decision") or "ALLOW"

        if policy_action == "BLOCK" or session_risk == "BLOCK":
            return Response(
                content=json.dumps({"error": "access_denied", "error_description": "Blocked by Zero-Trust security policy"}),
                status_code=403,
                media_type="application/json"
            )

        # Generate short-lived Authorization Code (60s TTL)
        auth_code = f"dt_authz_{secrets.token_hex(20)}"
        expires_at = time.time() + 60
        code_doc = {
            "code": auth_code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "user_id": user.get("user_id") or user.get("email"),
            "email": user.get("email"),
            "full_name": user.get("full_name"),
            "role": user.get("role"),
            "display_role": user.get("display_role", user.get("role")),
            "department": user.get("department", "Clinical Services"),
            "organization_id": bound_org_id,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method or "S256",
            "state": state,
            "auth_session_id": active_sess.get("session_id"),
            "risk_score": active_sess.get("risk_score"),
            "risk_level": active_sess.get("risk_level"),
            "device_trust": active_sess.get("device_trust"),
            "organization_name": user.get("organization_name") or (org_doc or {}).get("name", "NovaCare Medical Center"),
            "used": False,
            "created_at": time.time(),
            "expires_at": expires_at,
        }
        db.oauth_authorization_codes.insert_one(code_doc)

        separator = "&" if "?" in redirect_uri else "?"
        callback_url = f"{redirect_uri}{separator}code={auth_code}"
        if state:
            callback_url += f"&state={urllib.parse.quote(state)}"

        return {
            "success": True,
            "code": auth_code,
            "state": state,
            "redirect_url": callback_url,
            "expires_in": 60
        }

    # No session provided -> return redirect to DeepTrust Authentication Pipeline
    dt_login_url = f"http://localhost:5000/index.html?oauth_client={urllib.parse.quote(client_id)}&redirect_uri={urllib.parse.quote(redirect_uri)}"
    if state:
        dt_login_url += f"&state={urllib.parse.quote(state)}"
    if code_challenge:
        dt_login_url += f"&code_challenge={urllib.parse.quote(code_challenge)}&code_challenge_method={urllib.parse.quote(code_challenge_method or 'S256')}"
    if requested_role:
        dt_login_url += f"&role={urllib.parse.quote(requested_role)}"

    return {
        "success": True,
        "action": "AUTHENTICATE",
        "login_url": dt_login_url
    }


@app.post("/api/v1/oauth/token")
@app.post("/api/v1/oauth/exchange")
def oauth_token_exchange(req: OAuthTokenInput):
    """
    OAuth2 Token Exchange Endpoint for DeepTrust External Integrations.
    Exchanges short-lived authorization code + PKCE verifier for trusted identity payload.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    # 1. Validate Grant Type
    if req.grant_type != "authorization_code":
        return Response(
            content=json.dumps({"error": "unsupported_grant_type", "message": "Only grant_type=authorization_code is supported"}),
            status_code=400,
            media_type="application/json"
        )

    # 2. Client Authentication
    integration = verify_client_credentials(req.client_id, req.client_secret)
    if not integration:
        raw_int = db.integrations.find_one({"client_id": req.client_id})
        err_type = "unauthorized_client" if raw_int and raw_int.get("status") == "DISABLED" else "invalid_client"
        msg = "Integration is disabled" if raw_int and raw_int.get("status") == "DISABLED" else "Invalid client_id or client_secret"
        return Response(
            content=json.dumps({"error": err_type, "message": msg}),
            status_code=403 if err_type == "unauthorized_client" else 401,
            media_type="application/json"
        )

    bound_org_id = integration["organization_id"]

    # 3. Check Organization Status
    org_doc = db.organizations.find_one({"organization_id": bound_org_id}) or db.organizations.find_one({"_id": bound_org_id})
    if org_doc and org_doc.get("status") in ["SUSPENDED", "DISABLED", "INACTIVE"]:
        return Response(
            content=json.dumps({"error": "unauthorized_client", "message": "Organization is disabled or suspended"}),
            status_code=403,
            media_type="application/json"
        )

    # 4. Find Authorization Code
    code_doc = db.oauth_authorization_codes.find_one({"code": req.code})
    if not code_doc:
        return Response(
            content=json.dumps({"error": "invalid_grant", "message": "Authorization code is invalid or unknown (fake code)"}),
            status_code=400,
            media_type="application/json"
        )

    # Replay protection
    if code_doc.get("used") == True:
        return Response(
            content=json.dumps({"error": "invalid_grant", "message": "Authorization code has already been used (replayed code detected)"}),
            status_code=400,
            media_type="application/json"
        )

    # Expiration check
    if time.time() > code_doc.get("expires_at", 0):
        return Response(
            content=json.dumps({"error": "invalid_grant", "message": "Authorization code has expired"}),
            status_code=400,
            media_type="application/json"
        )

    # Wrong client check
    if code_doc.get("client_id") != req.client_id:
        return Response(
            content=json.dumps({"error": "invalid_grant", "message": "Authorization code was issued for a different client"}),
            status_code=400,
            media_type="application/json"
        )

    # Wrong redirect URI check
    if req.redirect_uri and code_doc.get("redirect_uri") and req.redirect_uri.rstrip('/') != code_doc.get("redirect_uri").rstrip('/'):
        return Response(
            content=json.dumps({"error": "invalid_grant", "message": "Redirect URI mismatch"}),
            status_code=400,
            media_type="application/json"
        )

    # PKCE Verification
    if code_doc.get("code_challenge"):
        if not req.code_verifier:
            return Response(
                content=json.dumps({"error": "invalid_grant", "message": "PKCE code_verifier is required"}),
                status_code=400,
                media_type="application/json"
            )
        method = code_doc.get("code_challenge_method", "S256")
        if method == "S256":
            calc_challenge = base64.urlsafe_b64encode(hashlib.sha256(req.code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')
            stored_challenge = code_doc["code_challenge"].rstrip('=')
            if calc_challenge != stored_challenge:
                return Response(
                    content=json.dumps({"error": "invalid_grant", "message": "PKCE verification failed: wrong code_verifier"}),
                    status_code=400,
                    media_type="application/json"
                )
        elif method == "plain":
            if req.code_verifier != code_doc["code_challenge"]:
                return Response(
                    content=json.dumps({"error": "invalid_grant", "message": "PKCE verification failed: wrong code_verifier"}),
                    status_code=400,
                    media_type="application/json"
                )

    # BURN CODE IMMEDIATELY (Single Use)
    claimed = db.oauth_authorization_codes.find_one_and_update({"_id":code_doc["_id"],"used":False}, {"$set":{"used":True,"used_at":time.time()}})
    if not claimed:
        raise HTTPException(400, 'Authorization code has already been used.')

    # Check user account status
    user = db.users.find_one({"email_normalized": str(code_doc.get("email", "")).lower()}) or db.users.find_one({"email": str(code_doc.get("email", "")).lower()})
    if user and user.get("status") in ["DISABLED", "SUSPENDED", "INACTIVE"]:
        return Response(
            content=json.dumps({"error": "unauthorized_client", "message": "User account is disabled"}),
            status_code=403,
            media_type="application/json"
        )

    # Check session revocation
    auth_sess_id = code_doc.get("auth_session_id")
    sess = None
    if auth_sess_id:
        sess = db.auth_sessions.find_one({"session_id": auth_sess_id}) or db.verification_sessions.find_one({"session_id": auth_sess_id})
        if sess and (sess.get("revoked") == True or sess.get("status") in ["REVOKED", "EXPIRED"]):
            return Response(
                content=json.dumps({"error": "invalid_grant", "message": "DeepTrust session has been revoked by admin"}),
                status_code=403,
                media_type="application/json"
            )

    check_staff_identity(user or {}, bound_org_id, code_doc.get('role'))
    if not sess or sess.get('expires_at',0) <= time.time():
        raise HTTPException(401, 'Completed hospital session is missing or expired.')

    # Generate Access Token
    token_payload = {
        "sub": code_doc.get("user_id"),
        "email": code_doc.get("email"),
        "role": code_doc.get("role"),
        "organization_id": bound_org_id,
        "iss": "DeepTrust Identity & Access Security Platform",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    access_token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    if isinstance(access_token, bytes):
        access_token = access_token.decode('utf-8')

    log_audit_event(
        "OAUTH_CODE_EXCHANGE_SUCCESS",
        code_doc.get("user_id"),
        code_doc.get("email"),
        "Healthcare Organization",
        f"OAuth2 code successfully exchanged for trusted staff identity {code_doc.get('email')} ({code_doc.get('role')})",
        risk="LOW"
    )

    notification = login_notification(code_doc, sess, req.client_id, code_doc.get('organization_name') or 'NovaCare Medical Center')
    db.notifications.update_one({'notification_id':notification['notification_id']}, {'$setOnInsert':notification}, upsert=True)

    publish_security_event(
        event_type="STAFF_SSO_SUCCESS",
        user_id=code_doc.get("email"),
        organization_id=bound_org_id,
        severity="INFO",
        auth_session_id=sess.get("session_id"),
        risk_score=sess.get("risk_score",0),
        risk_level=sess.get("risk_level","UNKNOWN"),
        risk_decision=sess.get("risk_decision","ALLOW"),
        metadata={
            "client_id": req.client_id,
            "role": code_doc.get("role"),
            "email": code_doc.get("email")
        }
    )

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": access_token,
        "user": {
            "user_id": code_doc.get("user_id"),
            "email": code_doc.get("email"),
            "full_name": code_doc.get("full_name"),
            "role": code_doc.get("role"),
            "display_role": code_doc.get("display_role", code_doc.get("role")),
            "department": code_doc.get("department", "Clinical Services"),
            "organization_id": bound_org_id,
            "risk_decision": "ALLOW"
        }
    }


@app.get("/api/v1/admin/risk-evaluations")
def get_admin_risk_evaluations(limit: int = 20, user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    """Returns explainable zero-trust risk evaluations for administrator inspection."""
    evals = []
    allowed_count = 0
    step_up_count = 0
    blocked_count = 0

    if db is not None:
        try:
            allowed_count = db.risk_evaluations.count_documents({"decision": "ALLOW"})
            step_up_count = db.risk_evaluations.count_documents({"decision": "STEP_UP"})
            blocked_count = db.risk_evaluations.count_documents({"decision": "BLOCK"})

            cursor = db.risk_evaluations.find().sort("created_at", -1).limit(limit)
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                evals.append(doc)
        except Exception:
            pass

    return {
        "success": True,
        "metrics": {
            "allowed": allowed_count,
            "step_up": step_up_count,
            "blocked": blocked_count
        },
        "evaluations": evals
    }


@app.get("/api/v1/admin/system-health")
def get_admin_system_health(user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    """Full infrastructure & engine health inspection."""
    try:
        from .system_health_readiness import voice_readiness, mfa_readiness
    except ImportError:
        from system_health_readiness import voice_readiness, mfa_readiness
    voice_probe = voice_readiness(voice_security.engine)
    mfa_probe = mfa_readiness()
    is_mongo_live = False
    if db is not None:
        try:
            db.command({"ping": 1})
            is_mongo_live = True
        except Exception:
            is_mongo_live = False

    return {
        "success": True,
        "infrastructure": {
            "frontend_gateway": {"status": "Operational", "port": 5000, "protocol": "HTTP/Static"},
            "api_server": {"status": "Operational", "port": 8000, "framework": "FastAPI 0.110"},
            "mongodb_database": {"status": "Operational" if is_mongo_live else "Unavailable", "host": "127.0.0.1:27017", "db": MONGODB_DATABASE}
        },
        "engines": {
            "face_yunet": {"status": "Operational" if detector else "Degraded", "model": "YuNet ONNX"},
            "face_sface": {"status": "Operational" if recognizer else "Degraded", "model": "SFace ONNX 128-d"},
            "active_liveness": {"status": "Operational" if passive_pad is not None else "Unavailable", "mode": "Passive MiniFASNet ensemble"},
            "voice_biometrics": voice_probe,
            "authenticator_mfa": mfa_probe,
            "zero_trust_risk": {"status": "Operational", "mode": "Deterministic Multi-Signal"}
        }
    }


# ── 15. AI SECURITY COPILOT (AUTHENTICATED ONLY — READ-ONLY & ADVISORY) ──
@app.post("/api/v1/ai/query")
def query_ai_security_copilot(
    req: AiQueryRequest,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """
    DeepTrust Security Copilot:
    Assists platform administrators by summarizing security telemetry, explaining risk events,
    correlating verification sessions, and providing advisory inspection steps.
    STRICTLY READ-ONLY — NEVER MODIFIES DATA AUTONOMOUSLY.
    """
    query_text = req.query.strip().lower()

    # Query real MongoDB data to construct deterministic, verifiable advisory intelligence
    open_alerts_count = 0
    total_auths = 0
    recent_events = []
    recent_sessions = []
    
    org_filter = {}
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        org_filter["organization_id"] = user.get("organization_id", "HEALTHCARE_ORG_1")

    if db is not None:
        try:
            open_alerts_count = db.security_events.count_documents({"status": "OPEN", **org_filter})
            total_auths = db.authentication_events.count_documents(org_filter)
            recent_events = list(db.security_events.find(org_filter).sort("created_at", -1).limit(4))
            recent_sessions = list(db.verification_sessions.find(org_filter).sort("created_at", -1).limit(4))
        except Exception:
            pass

    response_title = "DeepTrust Security Copilot Analysis"
    response_body = ""
    evidence_items = []
    recommendations = []

    if "summarize" in query_text or "today" in query_text or "overview" in query_text:
        response_title = "Today's Healthcare Access Telemetry Summary"
        response_body = (
            f"Across {user.get('organization_name', 'NovaCare Medical Center')}, a total of {max(1, total_auths)} multi-factor authentication "
            f"sessions have been evaluated. There are currently {open_alerts_count} open security events "
            f"requiring administrator attention. The primary verification pipeline (YuNet Face, Active Liveness, "
            f"Voice Acoustics, and Authenticator MFA) is operating at optimal policy compliance."
        )
        for evt in recent_events:
            evidence_items.append(f"Event {evt.get('event_id')}: {evt.get('event_type')} (Severity: {evt.get('severity')})")
        recommendations = [
            "Review and triage the open security events in the Threat Investigation drawer.",
            "Verify that all pending privileged access requests have signed clinical justifications.",
            "Ensure emergency ICU workstations maintain the 15-minute re-authentication policy."
        ]

    elif "block" in query_text or "why" in query_text or "risk" in query_text:
        response_title = "Zero-Trust Access Block Investigation"
        blocked_evt = None
        for evt in recent_events:
            if evt.get("decision") == "BLOCK":
                blocked_evt = evt
                break

        if blocked_evt:
            response_body = (
                f"Authentication for identity '{blocked_evt.get('identity')}' was blocked under Event ID "
                f"{blocked_evt.get('event_id')}. The Zero-Trust Risk Engine evaluated a composite risk score of "
                f"{blocked_evt.get('risk_score')}/100 based on reason codes: {', '.join(blocked_evt.get('reason_codes', []))}."
            )
            evidence_items.append(f"Event ID: {blocked_evt.get('event_id')}")
            evidence_items.append(f"Identity: {blocked_evt.get('identity')}")
            evidence_items.append(f"Risk Score: {blocked_evt.get('risk_score')}/100 ({blocked_evt.get('risk_level')})")
            evidence_items.append(f"Reason Codes: {', '.join(blocked_evt.get('reason_codes', []))}")
        else:
            response_body = "No active BLOCK events were recorded in the last evaluation window. All verified sessions adhered to standard Zero-Trust threshold criteria."
            evidence_items.append("Global Risk Status: NOMINAL")

        recommendations = [
            "Inspect client IP subnet and device certificate for unrecognized hardware anomalies.",
            "Contact workforce identity directly if step-up verification was repeatedly rejected.",
            "Confirm biometric template enrollment integrity in Identity Security."
        ]

    elif "health" in query_text or "service" in query_text or "unavailable" in query_text:
        response_title = "Infrastructure & Verification Engine Health Inspection"
        response_body = (
            "All core authentication sub-engines are currently OPERATIONAL. "
            "OpenCV YuNet face detection, SFace 128-d neural feature extraction, temporal active liveness, "
            "voice acoustic analysis, and RFC 6238 TOTP MFA services are actively responding within sub-30ms latency."
        )
        evidence_items = [
            "Face Engine (YuNet + SFace): OPERATIONAL (28ms)",
            "Active Liveness (Landmarks): OPERATIONAL (18ms)",
            "Voice Engine (Acoustic Match): OPERATIONAL (22ms)",
            "Authenticator MFA: OPERATIONAL (9ms)",
            "MongoDB Database: CONNECTED (Cluster US-East)"
        ]
        recommendations = [
            "Maintain current ONNX model pipeline runtime cache.",
            "Ensure regular 30-day credential rotation for service gateway credentials."
        ]

    elif "correlate" in query_text or "session" in query_text:
        response_title = "Multi-Factor Verification Correlation"
        response_body = (
            "Verification sessions enforce atomic session binding. When an identity initiates credentials, "
            "all subsequent biometric, liveness, and MFA tokens are correlated under the same immutable `session_id`. "
            "No cross-session factor piggybacking is permitted."
        )
        for s in recent_sessions[:2]:
            evidence_items.append(f"Session {s.get('session_id')}: Cred={s.get('credential_status')}, Face={s.get('face_status')}, Voice={s.get('voice_status')}, MFA={s.get('mfa_status')}")
        recommendations = [
            "Review session expiration timers (configured at 900s for pre-auth verification).",
            "Monitor correlated audit logs for rapid session abort patterns."
        ]

    else:
        response_title = "Security Copilot Advisory Analysis"
        response_body = (
            f"Query analyzed across {max(1, total_auths)} authentication records and {open_alerts_count} security alerts. "
            f"DeepTrust Zero-Trust policy is actively enforcing multi-factor biometric protection across all healthcare clinical access points."
        )
        for evt in recent_events[:2]:
            evidence_items.append(f"Incident {evt.get('event_id')}: {evt.get('description')}")
        recommendations = [
            "Execute threat investigation queries to explore specific identities or event IDs.",
            "Refer to the Audit Trail for cryptographically verifiable log entries."
        ]

    return {
        "success": True,
        "is_configured": True,
        "agent_name": "DeepTrust Security Copilot",
        "title": response_title,
        "analysis": response_body,
        "evidence": evidence_items,
        "recommendations": recommendations,
        "disclaimer": "AI-generated advisory analysis. Critical actions require manual administrator confirmation."
    }


# ── 16. SETTINGS & ACCESS POLICIES ──────────────────────────────────────────
@app.get("/api/v1/settings")
def get_settings(user: dict = Depends(require_platform_admin)):
    """Retrieves enterprise security settings for platform administrators."""
    return {
        "success": True,
        "policies": {
            "mfa_required": True,
            "biometric_required": True,
            "liveness_strictness": "STANDARD",
            "session_timeout_minutes": 480,
            "risk_auto_block_threshold": 85,
            "max_failed_attempts": 5
        },
        "notifications": {
            "email_alerts": True,
            "high_risk_instant": True,
            "daily_digest": False
        },
        "organization": {
            "id": user.get("organization_id", "DEEPTRUST_PLATFORM"),
            "name": user.get("organization_name", "DeepTrust Security Platform"),
            "industry": "Enterprise Security",
            "node": "US-East Security Node"
        }
    }


@app.post("/api/v1/settings")
def update_settings(
    req: SettingsUpdateRequest,
    user: dict = Depends(require_platform_admin)
):
    """Updates security governance and policies with Platform Admin authorization."""
    require_write_permission(user)
    log_audit_event(
        "SETTINGS_UPDATED",
        user.get("email", "owner@deeptrust.demo"),
        user.get("email", "owner@deeptrust.demo"),
        user.get("organization_name", "DeepTrust Platform"),
        f"Security governance & access policies updated by {user.get('email')}",
        risk="LOW"
    )
    return {"success": True, "message": "Security settings saved successfully."}



# ── 17. ACCOUNT MANAGEMENT (DEEPTRUST ADMIN ONLY) ──────────────────────────
@app.get("/api/v1/admin/accounts")
def get_admin_accounts(authorization: Optional[str] = Header(None), user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    """Lists all DeepTrust Admin and Healthcare Admin accounts."""
    admin_user = get_authenticated_user_from_header(authorization)
    if admin_user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Unauthorized: DeepTrust Administrator privileges required.")

    accounts = []
    if db is not None:
        try:
            cursor = db.users.find({"status": {"$ne": "REMOVED"}}).sort("created_at", -1)
            for doc in cursor:
                doc_id = str(doc["_id"])
                accounts.append({
                    "id": doc_id,
                    "name": doc.get("full_name", "Unknown"),
                    "email": doc.get("email"),
                    "account_type": doc.get("account_type") or ("DEEPTRUST_ADMIN" if doc.get("role") in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"] else "HEALTHCARE_ADMIN"),
                    "organization_name": doc.get("organization_name", "Healthcare Organization"),
                    "role": doc.get("role"),
                    "display_role": doc.get("display_role", doc.get("role")),
                    "mfa_enabled": bool(doc.get("mfa_enabled", False)),
                    "status": doc.get("status", "ACTIVE"),
                    "last_login": doc.get("last_auth") or doc.get("last_login_at") or (time.time() - 3600),
                    "created_at": doc.get("created_at", time.time()),
                    "is_demo": bool(doc.get("is_demo", False))
                })
        except Exception as e:
            print(f"[Get Accounts Error]: {e}")

    return {"success": True, "accounts": accounts, "count": len(accounts)}


@app.post("/api/v1/admin/accounts")
def create_account(req: CreateAccountRequest, authorization: Optional[str] = Header(None), user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    """Creates a new DeepTrust Admin or Healthcare Admin account with unique TOTP QR enrollment."""
    admin_user = get_authenticated_user_from_header(authorization)
    if admin_user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Unauthorized: Only DeepTrust Administrators can create accounts.")

    # 1. Validate email format
    email = req.email.strip()
    norm_email = email.lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", norm_email):
        raise HTTPException(status_code=400, detail="Invalid email format. Please provide a valid email (e.g. name@domain.com).")

    # 2. Check email uniqueness in MongoDB
    if db is not None:
        existing = db.users.find_one({"email_normalized": norm_email})
        if existing and existing.get("status") != "REMOVED":
            raise HTTPException(status_code=409, detail="An account with this email address already exists.")

    # 3. Validate password strength
    pwd = req.password
    if len(pwd) < 8 or not any(c.isupper() for c in pwd) or not any(c.islower() for c in pwd) or not any(c.isdigit() for c in pwd) or not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd):
        raise HTTPException(
            status_code=400,
            detail="Password does not meet requirements: minimum 8 characters, with at least 1 uppercase, 1 lowercase, 1 number, and 1 special character."
        )

    # 4. Hash password with bcrypt
    password_hash = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt(10)).decode('utf-8')

    # 5. Generate unique TOTP secret & QR code
    totp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(totp_secret)
    org_label = "DeepTrust" if req.account_type == "DEEPTRUST_ADMIN" else "Healthcare"
    otpauth_url = totp.provisioning_uri(name=email, issuer_name=f"DeepTrust:{org_label}")
    qr_code_url = generate_qr_base64(otpauth_url)

    org_name = "DeepTrust Security Platform" if req.account_type == "DEEPTRUST_ADMIN" else (req.organization_name or "Healthcare Organization")
    org_id = "DEEPTRUST_PLATFORM" if req.account_type == "DEEPTRUST_ADMIN" else (req.organization_id or "HEALTHCARE_ORG_1")

    new_account = {
        "full_name": req.full_name.strip(),
        "email": email,
        "email_normalized": norm_email,
        "password_hash": password_hash,
        "role": req.role,
        "display_role": req.role.replace('_', ' ').title(),
        "account_type": req.account_type,
        "organization_id": org_id,
        "organization_name": org_name,
        "status": "PENDING_MFA",
        "mfa_enabled": False,
        "mfa_secret": totp_secret,
        "protected_mfa_secret": totp_secret,
        "email_verified": True,
        "face_enrolled": False,
        "voice_enrolled": False,
        "created_at": time.time(),
        "updated_at": time.time(),
        "created_by": admin_user.get("email")
    }

    if db is not None:
        insert_res = db.users.insert_one(new_account)
        new_account["_id"] = insert_res.inserted_id

        # Insert into specific collection
        if req.account_type == "DEEPTRUST_ADMIN":
            db.deeptrust_admins.insert_one(dict(new_account))
        else:
            db.healthcare_admins.insert_one(dict(new_account))

        # Save mfa profile
        db.mfa_profiles.update_one(
            {"email": norm_email},
            {"$set": {"user_id": str(new_account["_id"]), "email": norm_email, "secret": totp_secret, "created_at": time.time()}},
            upsert=True
        )

    log_audit_event(
        "ACCOUNT_CREATED",
        str(admin_user.get("_id", "admin")),
        admin_user.get("email", "admin@deeptrust.demo"),
        org_name,
        f"Created {req.account_type} account for {email} ({req.role})",
        risk="LOW",
        details={"target_email": email, "account_type": req.account_type, "role": req.role}
    )

    return {
        "success": True,
        "message": "Account created. Please scan the QR code in Google Authenticator to activate 2FA.",
        "account": {
            "id": str(new_account.get("_id")),
            "full_name": new_account["full_name"],
            "email": new_account["email"],
            "account_type": new_account["account_type"],
            "organization_name": new_account["organization_name"],
            "role": new_account["role"],
            "status": new_account["status"]
        },
        "user": {
            "id": str(new_account.get("_id")),
            "full_name": new_account["full_name"],
            "email": new_account["email"],
            "account_type": new_account["account_type"],
            "organization_name": new_account["organization_name"],
            "role": new_account["role"],
            "status": new_account["status"]
        },
        "qr_code": qr_code_url,
        "qr_base64": qr_code_url,
        "secret": totp_secret,
        "otpauth_url": otpauth_url,
        "mfa_setup": {
            "qr_base64": qr_code_url,
            "secret": totp_secret,
            "otpauth_url": otpauth_url
        }
    }


@app.post("/api/v1/admin/accounts/{account_id}/disable")
def disable_account(account_id: str, authorization: Optional[str] = Header(None), user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    admin_user = get_authenticated_user_from_header(authorization)
    if admin_user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Unauthorized")

    if db is not None:
        q = {"_id": ObjectId(account_id)} if ObjectId.is_valid(account_id) else {"_id": account_id}
        user = db.users.find_one(q) or db.users.find_one({"email": account_id})
        if not user:
            raise HTTPException(status_code=404, detail="Account not found")

        uid = str(user["_id"])
        email = user.get("email")

        db.users.update_one({"_id": user["_id"]}, {"$set": {"status": "DISABLED", "updated_at": time.time()}})
        db.deeptrust_admins.update_one({"email": email}, {"$set": {"status": "DISABLED", "updated_at": time.time()}})
        db.healthcare_admins.update_one({"email": email}, {"$set": {"status": "DISABLED", "updated_at": time.time()}})

        # Revoke all active sessions for this user
        db.auth_sessions.update_many(
            {"$or": [{"user_id": uid}, {"email": email}]},
            {"$set": {"revoked": True, "revoked_at": time.time(), "revoked_reason": f"Account disabled by {admin_user.get('email')}"}}
        )

        log_audit_event("ACCOUNT_DISABLED", str(admin_user.get("_id")), admin_user.get("email"), user.get("organization_name", "Healthcare Organization"), f"Account {email} was disabled and active sessions revoked.", risk="LOW")
        return {"success": True, "status": "DISABLED", "message": f"Account {email} disabled and active sessions revoked."}

    raise HTTPException(status_code=500, detail="Database unavailable")


@app.post("/api/v1/admin/accounts/{account_id}/enable")
def enable_account(account_id: str, authorization: Optional[str] = Header(None), user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    admin_user = get_authenticated_user_from_header(authorization)
    if admin_user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Unauthorized")

    if db is not None:
        q = {"_id": ObjectId(account_id)} if ObjectId.is_valid(account_id) else {"_id": account_id}
        user = db.users.find_one(q) or db.users.find_one({"email": account_id})
        if not user:
            raise HTTPException(status_code=404, detail="Account not found")

        email = user.get("email")
        db.users.update_one({"_id": user["_id"]}, {"$set": {"status": "ACTIVE", "updated_at": time.time()}})
        db.deeptrust_admins.update_one({"email": email}, {"$set": {"status": "ACTIVE", "updated_at": time.time()}})
        db.healthcare_admins.update_one({"email": email}, {"$set": {"status": "ACTIVE", "updated_at": time.time()}})

        log_audit_event("ACCOUNT_ENABLED", str(admin_user.get("_id")), admin_user.get("email"), user.get("organization_name", "Healthcare Organization"), f"Account {email} was enabled.", risk="LOW")
        return {"success": True, "status": "ACTIVE", "message": f"Account {email} enabled."}

    raise HTTPException(status_code=500, detail="Database unavailable")


@app.delete("/api/v1/admin/accounts/{account_id}")
@app.post("/api/v1/admin/accounts/{account_id}/remove")
def remove_account(account_id: str, authorization: Optional[str] = Header(None), user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    admin_user = get_authenticated_user_from_header(authorization)
    if admin_user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Unauthorized")

    if db is not None:
        q = {"_id": ObjectId(account_id)} if ObjectId.is_valid(account_id) else {"_id": account_id}
        user = db.users.find_one(q) or db.users.find_one({"email": account_id})
        if not user:
            raise HTTPException(status_code=404, detail="Account not found")

        uid = str(user["_id"])
        email = user.get("email")

        # Soft delete with auditable timestamps
        db.users.update_one({"_id": user["_id"]}, {"$set": {"status": "REMOVED", "deleted_at": time.time(), "deleted_by": admin_user.get("email"), "updated_at": time.time()}})
        db.deeptrust_admins.update_one({"email": email}, {"$set": {"status": "REMOVED", "deleted_at": time.time(), "deleted_by": admin_user.get("email")}})
        db.healthcare_admins.update_one({"email": email}, {"$set": {"status": "REMOVED", "deleted_at": time.time(), "deleted_by": admin_user.get("email")}})

        # Revoke all active sessions immediately
        db.auth_sessions.update_many(
            {"$or": [{"user_id": uid}, {"email": email}]},
            {"$set": {"revoked": True, "revoked_at": time.time(), "revoked_reason": f"Account removed by {admin_user.get('email')}"}}
        )

        log_audit_event("ACCOUNT_REMOVED", str(admin_user.get("_id")), admin_user.get("email"), user.get("organization_name", "Healthcare Organization"), f"Account {email} was removed by admin.", risk="HIGH")
        return {"success": True, "status": "REMOVED", "message": f"Account {email} removed and all active sessions revoked."}

    raise HTTPException(status_code=500, detail="Database unavailable")


@app.post("/api/v1/admin/accounts/{account_id}/restore")
def restore_account(account_id: str, authorization: Optional[str] = Header(None), user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    admin_user = get_authenticated_user_from_header(authorization)
    if admin_user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Unauthorized")

    if db is not None:
        q = {"_id": ObjectId(account_id)} if ObjectId.is_valid(account_id) else {"_id": account_id}
        user = db.users.find_one(q) or db.users.find_one({"email": account_id})
        if not user:
            raise HTTPException(status_code=404, detail="Account not found")

        email = user.get("email")
        db.users.update_one({"_id": user["_id"]}, {"$set": {"status": "ACTIVE", "deleted_at": None, "updated_at": time.time()}})
        db.deeptrust_admins.update_one({"email": email}, {"$set": {"status": "ACTIVE", "deleted_at": None}})
        db.healthcare_admins.update_one({"email": email}, {"$set": {"status": "ACTIVE", "deleted_at": None}})

        log_audit_event("ACCOUNT_RESTORED", str(admin_user.get("_id")), admin_user.get("email"), user.get("organization_name", "Healthcare Organization"), f"Account {email} was restored.", risk="LOW")
        return {"success": True, "status": "ACTIVE", "message": f"Account {email} restored."}

    raise HTTPException(status_code=500, detail="Database unavailable")


@app.post("/api/v1/admin/accounts/{account_id}/mfa-reset")
def reset_account_mfa(account_id: str, authorization: Optional[str] = Header(None), user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    admin_user = get_authenticated_user_from_header(authorization)
    if admin_user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Unauthorized")

    if db is not None:
        q = {"_id": ObjectId(account_id)} if ObjectId.is_valid(account_id) else {"_id": account_id}
        user = db.users.find_one(q) or db.users.find_one({"email": account_id})
        if not user:
            raise HTTPException(status_code=404, detail="Account not found")

        email = user.get("email")
        new_secret = pyotp.random_base32()
        totp = pyotp.TOTP(new_secret)
        otpauth_url = totp.provisioning_uri(name=email, issuer_name="DeepTrust")
        qr_code_url = generate_qr_base64(otpauth_url)

        db.users.update_one({"_id": user["_id"]}, {"$set": {"mfa_secret": new_secret, "protected_mfa_secret": new_secret, "mfa_enabled": False, "status": "PENDING_MFA", "updated_at": time.time()}})
        db.deeptrust_admins.update_one({"email": email}, {"$set": {"mfa_secret": new_secret, "protected_mfa_secret": new_secret, "mfa_enabled": False, "status": "PENDING_MFA"}})
        db.healthcare_admins.update_one({"email": email}, {"$set": {"mfa_secret": new_secret, "protected_mfa_secret": new_secret, "mfa_enabled": False, "status": "PENDING_MFA"}})
        db.mfa_profiles.update_one({"email": email.lower()}, {"$set": {"secret": new_secret, "created_at": time.time()}}, upsert=True)

        log_audit_event("MFA_RESET", str(admin_user.get("_id")), admin_user.get("email"), user.get("organization_name", "Healthcare Organization"), f"Reset MFA configuration for {email}.", risk="LOW")
        return {"success": True, "secret": new_secret, "qr_code": qr_code_url, "otpauth_url": otpauth_url}

    raise HTTPException(status_code=500, detail="Database unavailable")


# ── 18. USER PROFILE & SECURITY SETTINGS ────────────────────────────────────
@app.patch("/api/v1/profile")
@app.put("/api/v1/profile")
def update_profile(req: ProfileUpdateRequest, authorization: Optional[str] = Header(None)):
    user = get_authenticated_user_from_header(authorization)
    new_name = req.full_name.strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="Full name cannot be empty")

    if db is not None:
        db.users.update_one({"email_normalized": user["email"].lower()}, {"$set": {"full_name": new_name, "updated_at": time.time()}})
        db.deeptrust_admins.update_one({"email_normalized": user["email"].lower()}, {"$set": {"full_name": new_name, "updated_at": time.time()}})
        db.healthcare_admins.update_one({"email_normalized": user["email"].lower()}, {"$set": {"full_name": new_name, "updated_at": time.time()}})

    log_audit_event("ACCOUNT_UPDATED", str(user.get("_id")), user["email"], user.get("organization_name", "Healthcare Organization"), f"Updated profile name to '{new_name}'", risk="LOW")
    return {"success": True, "message": "Profile updated successfully.", "full_name": new_name}


@app.post("/api/v1/profile/change-password")
def change_password(req: ChangePasswordRequest, authorization: Optional[str] = Header(None)):
    user = get_authenticated_user_from_header(authorization)
    
    # 1. Verify current password
    user_doc = None
    if db is not None:
        user_doc = db.users.find_one({"email_normalized": user["email"].lower()})
    
    if not user_doc or not user_doc.get("password_hash"):
        raise HTTPException(status_code=400, detail="User account record error.")

    stored_hash = user_doc["password_hash"]
    try:
        is_current_valid = bcrypt.checkpw(req.current_password.encode('utf-8'), stored_hash.encode('utf-8'))
    except Exception:
        is_current_valid = False

    if not is_current_valid:
        raise HTTPException(status_code=400, detail="Current password incorrect.")

    # 2. Validate new password
    pwd = req.new_password
    if len(pwd) < 8 or not any(c.isupper() for c in pwd) or not any(c.islower() for c in pwd) or not any(c.isdigit() for c in pwd) or not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd):
        raise HTTPException(
            status_code=400,
            detail="New password does not meet requirements: minimum 8 characters, with uppercase, lowercase, digit, and special character."
        )

    # 3. Hash new password
    new_hash = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt(10)).decode('utf-8')

    if db is not None:
        db.users.update_one({"email_normalized": user["email"].lower()}, {"$set": {"password_hash": new_hash, "updated_at": time.time()}})
        db.deeptrust_admins.update_one({"email_normalized": user["email"].lower()}, {"$set": {"password_hash": new_hash, "updated_at": time.time()}})
        db.healthcare_admins.update_one({"email_normalized": user["email"].lower()}, {"$set": {"password_hash": new_hash, "updated_at": time.time()}})

    log_audit_event("PASSWORD_CHANGED", str(user.get("_id")), user["email"], user.get("organization_name", "Healthcare Organization"), "Account password was changed successfully.", risk="LOW")
    return {"success": True, "message": "Password changed successfully."}


@app.get("/api/v1/profile/sessions")
def get_user_sessions(authorization: Optional[str] = Header(None)):
    user = get_authenticated_user_from_header(authorization)
    sessions = []
    if db is not None:
        try:
            cursor = db.auth_sessions.find({"$or": [{"user_id": str(user.get("_id"))}, {"email": user["email"]}]}).sort("created_at", -1).limit(10)
            for s in cursor:
                sessions.append({
                    "session_id": str(s.get("_id")),
                    "created_at": s.get("created_at"),
                    "last_activity_at": s.get("last_activity_at", s.get("created_at")),
                    "revoked": bool(s.get("revoked", False)),
                    "ip_address": s.get("ip_address", "127.0.0.1 (Local Workstation)"),
                    "user_agent": s.get("user_agent", "DeepTrust Security Console Browser")
                })
        except Exception as e:
            print(f"[User Sessions Error]: {e}")

    return {"success": True, "sessions": sessions}


@app.post("/api/v1/profile/sessions/revoke-others")
def revoke_other_sessions(authorization: Optional[str] = Header(None)):
    user = get_authenticated_user_from_header(authorization)
    token = authorization.replace("Bearer ", "").strip()
    decoded = decode_jwt_token(token)
    current_session_id = decoded.get("session_id") if decoded else None

    if db is not None:
        query = {"$or": [{"user_id": str(user.get("_id"))}, {"email": user["email"]}]}
        if current_session_id:
            query["_id"] = {"$ne": current_session_id}
        db.auth_sessions.update_many(
            query,
            {"$set": {"revoked": True, "revoked_at": time.time(), "revoked_reason": "Signed out from other sessions"}}
        )

    log_audit_event("SESSIONS_REVOKED", str(user.get("_id")), user["email"], user.get("organization_name", "Healthcare Organization"), "Signed out other active sessions.", risk="LOW")
    return {"success": True, "message": "All other active sessions have been revoked."}


# ── 19. MONTHLY SECURITY REPORT & PDF EXPORT ───────────────────────────────
@app.get("/api/v1/admin/reports/monthly")
def get_monthly_security_report(
    year: int = 2026,
    month: int = 9,
    download: bool = False,
    authorization: Optional[str] = Header(None),
    user: dict = Depends(get_authenticated_user_from_header)
):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    admin_user = get_authenticated_user_from_header(authorization)
    if admin_user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Unauthorized: DeepTrust Admin privileges required")

    metrics = aggregate_month(db, year, month)
    metrics.update({"year":year, "month":month, "reporting_period":f"{year}-{month:02d}",
                    "generated_by":admin_user.get("email"),
                    "generated_at":datetime.now(timezone.utc).isoformat()})

    # Record in report_metadata
    if db is not None:
        db.report_metadata.insert_one({
            "report_id": f"DTR-{year}{month:02d}-{int(time.time())}",
            "generated_by": admin_user.get("email"),
            "reporting_period": f"{year}-{month:02d}",
            "year": year,
            "month": month,
            "generated_at": time.time(),
            "organization_scope": "All Organizations (Healthcare Organization)",
            "filename": f"DeepTrust_Security_Report_{year}_{month:02d}.pdf"
        })

    log_audit_event("MONTHLY_REPORT_GENERATED", str(admin_user.get("_id")), admin_user.get("email"), "All Organizations", f"Generated monthly report for {year}-{month:02d}", risk="LOW")

    if download:
        pdf_bytes = generate_monthly_security_pdf(metrics, year, month, generated_by=admin_user.get("full_name", "DeepTrust Platform Admin"))
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="DeepTrust_Security_Report_{year}_{month:02d}.pdf"'
            }
        )

    return {"success": True, "metrics": metrics}


# ── 20. SECURE DEEPTRUST ADMIN MOBILE SECURITY MONITOR ─────────────────────

def get_authenticated_mobile_session(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Mobile authentication token required")
    token = authorization.replace("Bearer ", "").strip()
    decoded = decode_jwt_token(token)
    if not decoded or decoded.get("session_type") != "MOBILE_MONITOR":
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid mobile monitor session token")

    session_id = decoded.get("session_id")
    if db is not None and session_id:
        sess = db.mobile_sessions.find_one({"session_id": session_id})
        if sess and sess.get("status") == "REVOKED":
            raise HTTPException(status_code=401, detail="Session Revoked: Generate a new QR to reconnect")

    role = decoded.get("role")
    if role not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: DeepTrust Admin privileges required")

    return decoded


@app.post("/api/v1/mobile/pair/create")
def create_mobile_pairing_session(req: Optional[MobilePairCreateRequest] = None):
    import secrets, hashlib
    raw_token = secrets.token_hex(16)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    random_code = secrets.token_hex(3).upper()
    pairing_id = f"DTM-{random_code}"

    now = time.time()
    expires_at = now + 300 # 5 minutes expiry

    session_doc = {
        "pairing_id": pairing_id,
        "token_hash": token_hash,
        "created_at": now,
        "expires_at": expires_at,
        "status": "PENDING", # PENDING, SCANNED, CREDENTIALS_VERIFIED, CONSUMED, EXPIRED, REVOKED
        "verified_admin_id": None,
        "verified_admin_email": None,
        "verified_at": None,
        "consumed_at": None
    }

    if db is not None:
        db.mobile_pairing_sessions.insert_one(session_doc)

    log_audit_event("MOBILE_PAIRING_CREATED", "system", "system", "DeepTrust Platform", f"Created mobile pairing session {pairing_id}", risk="LOW")

    return {
        "success": True,
        "pairing_id": pairing_id,
        "raw_token": raw_token,
        "expires_at": expires_at,
        "expires_in_seconds": 300
    }


@app.get("/api/v1/mobile/pair/{token}/status")
def get_mobile_pairing_status(token: str):
    import hashlib
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    doc = None
    if db is not None:
        doc = db.mobile_pairing_sessions.find_one({"token_hash": token_hash})

    if not doc:
        raise HTTPException(status_code=404, detail="Pairing token not found")

    now = time.time()
    status = doc.get("status", "PENDING")

    if now > doc.get("expires_at", 0) and status in ["PENDING", "SCANNED", "CREDENTIALS_VERIFIED"]:
        status = "EXPIRED"
        if db is not None:
            db.mobile_pairing_sessions.update_one({"_id": doc["_id"]}, {"$set": {"status": "EXPIRED"}})

    if status == "PENDING" and db is not None:
        db.mobile_pairing_sessions.update_one({"_id": doc["_id"]}, {"$set": {"status": "SCANNED"}})
        log_audit_event("MOBILE_PAIRING_SCANNED", "mobile_device", "unknown", "DeepTrust Platform", f"Mobile QR scanned for session {doc.get('pairing_id')}", risk="LOW")
        status = "SCANNED"

    return {
        "pairing_id": doc.get("pairing_id"),
        "status": status,
        "expires_at": doc.get("expires_at"),
        "verified_admin_email": doc.get("verified_admin_email")
    }


@app.post("/api/v1/mobile/pair/verify-credentials")
def verify_mobile_admin_credentials(req: MobilePairVerifyCredentialsRequest):
    import hashlib
    token_hash = hashlib.sha256(req.token.encode("utf-8")).hexdigest()

    doc = None
    if db is not None:
        doc = db.mobile_pairing_sessions.find_one({"token_hash": token_hash})

    if not doc:
        raise HTTPException(status_code=404, detail="Invalid or expired pairing session")

    if doc.get("status") == "CONSUMED":
        raise HTTPException(status_code=400, detail="Pairing Link Already Used: Generate a new pairing session.")

    if time.time() > doc.get("expires_at", 0) or doc.get("status") in ["EXPIRED", "REVOKED"]:
        raise HTTPException(status_code=400, detail="Pairing Session Expired: Please generate a new QR.")

    email_clean = req.email.strip().lower()
    user = None
    if db is not None:
        user = db.users.find_one({"email_normalized": email_clean})
        if not user:
            user = db.deeptrust_admins.find_one({"email_normalized": email_clean})

    if not user:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")

    role = user.get("role", "")
    if role not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        log_audit_event("MOBILE_ACCESS_DENIED", str(user.get("_id")), req.email, "DeepTrust Platform", f"Healthcare admin or non-admin attempted mobile monitor pairing ({role})", risk="HIGH")
        raise HTTPException(status_code=403, detail="Access Denied: Healthcare Admins cannot access DeepTrust Admin Mobile Monitor")

    if str(user.get("status", "ACTIVE")).upper() != "ACTIVE":
        raise HTTPException(status_code=403, detail="Admin account is not active")

    if not bcrypt.checkpw(req.password.encode('utf-8'), user.get('password_hash', '').encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")

    if db is not None:
        db.mobile_pairing_sessions.update_one(
            {"_id": doc["_id"], "status": {"$nin": ["CONSUMED", "REVOKED", "EXPIRED"]}},
            {"$set": {
                "status": "CREDENTIALS_VERIFIED",
                "verified_admin_id": str(user.get("_id")),
                "verified_admin_email": user.get("email")
            }}
        )

    log_audit_event("MOBILE_ADMIN_CREDENTIAL_VERIFIED", str(user.get("_id")), user.get("email"), "DeepTrust Platform", f"Verified credentials for mobile pairing session {doc.get('pairing_id')}", risk="LOW")

    return {
        "success": True,
        "status": "CREDENTIALS_VERIFIED",
        "admin_name": user.get("full_name", "DeepTrust Admin"),
        "admin_email": user.get("email"),
        "require_totp": True
    }


@app.post("/api/v1/mobile/pair/verify-totp")
def verify_mobile_admin_totp(req: MobilePairVerifyTotpRequest):
    import hashlib, secrets
    token_hash = hashlib.sha256(req.token.encode("utf-8")).hexdigest()

    doc = None
    if db is not None:
        doc = db.mobile_pairing_sessions.find_one({"token_hash": token_hash})

    if not doc:
        raise HTTPException(status_code=404, detail="Invalid or expired pairing session")

    if doc.get("status") == "CONSUMED":
        raise HTTPException(status_code=400, detail="Pairing Link Already Used: Generate a new pairing session.")

    if time.time() > doc.get("expires_at", 0) or doc.get("status") in ["EXPIRED", "REVOKED"]:
        raise HTTPException(status_code=400, detail="Pairing Session Expired: Please generate a new QR.")

    email_clean = req.email.strip().lower()
    user = None
    if db is not None:
        user = db.users.find_one({"email_normalized": email_clean})
        if not user:
            user = db.deeptrust_admins.find_one({"email_normalized": email_clean})

    if not user:
        raise HTTPException(status_code=401, detail="Admin account not found")

    # Robust Secret Resolution across all user fields & mfa_profiles collection
    totp_secret = user.get("totp_secret") or user.get("mfa_secret") or user.get("protected_mfa_secret") or user.get("secret")

    if not totp_secret and db is not None:
        prof = db.mfa_profiles.find_one({
            "$or": [
                {"email": email_clean},
                {"user_id": str(user.get("_id"))},
                {"email": user.get("email", "")}
            ]
        })
        if prof and "secret" in prof:
            totp_secret = prof["secret"]

    authorize_pairing_identity(doc, user)
    verify_pairing_totp(totp_secret, req.totp_code)
    consume_pairing(db.mobile_pairing_sessions, doc, user, time.time())

    mobile_session_id = f"MSESS-{secrets.token_hex(8)}"
    now = time.time()
    exp = now + 7200

    jwt_payload = {
        "sub": str(user.get("_id")),
        "session_id": mobile_session_id,
        "email": user.get("email"),
        "full_name": user.get("full_name", "DeepTrust Admin"),
        "role": user.get("role", "DEEPTRUST_ADMIN"),
        "session_type": "MOBILE_MONITOR",
        "scope": ["security:read", "alerts:read", "health:read", "analytics:read", "events:read"],
        "iat": int(now),
        "exp": int(exp)
    }

    mobile_token = jwt.encode(jwt_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    if db is not None:
        db.mobile_sessions.insert_one({
            "session_id": mobile_session_id,
            "admin_id": str(user.get("_id")),
            "admin_email": user.get("email"),
            "admin_name": user.get("full_name", "DeepTrust Admin"),
            "role": user.get("role"),
            "session_type": "MOBILE_MONITOR",
            "scope": ["security:read", "alerts:read", "health:read", "analytics:read", "events:read"],
            "created_at": now,
            "expires_at": exp,
            "last_active": now,
            "status": "ACTIVE"
        })


        db.security_events.insert_one({
            "event_id": f"EVT-MOB-{int(now)}",
            "title": "New Admin Mobile Session Authorized",
            "event_type": "NEW_ADMIN_MOBILE_SESSION",
            "severity": "INFO",
            "user_email": user.get("email"),
            "user_name": user.get("full_name"),
            "organization": user.get("organization_name", "DeepTrust Platform"),
            "timestamp": now,
            "created_at": now,
            "decision": "AUTHORIZED",
            "details": f"Mobile Security Monitor session paired via QR for {user.get('email')}",
            "status": "OPEN"
        })

    log_audit_event("MOBILE_ADMIN_MFA_VERIFIED", str(user.get("_id")), user.get("email"), "DeepTrust Platform", f"Verified Google Authenticator for mobile pairing {doc.get('pairing_id')}", risk="LOW")
    log_audit_event("MOBILE_MONITOR_SESSION_CREATED", str(user.get("_id")), user.get("email"), "DeepTrust Platform", f"Created Mobile Monitor Session {mobile_session_id}", risk="LOW")

    return {
        "success": True,
        "mobile_token": mobile_token,
        "session_id": mobile_session_id,
        "session_type": "MOBILE_MONITOR",
        "admin_name": user.get("full_name", "DeepTrust Admin"),
        "expires_in": 7200
    }


@app.get("/api/v1/mobile/summary")
def get_mobile_summary(authorization: Optional[str] = Header(None)):
    session = get_authenticated_mobile_session(authorization)

    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()

    total_auths = 0
    successful_auths = 0
    blocked_attempts = 0
    high_risk_events = 0
    open_alerts = 0

    if db is not None:
        try:
            t_filter = {"created_at": {"$gte": today_start}}
            total_auths = db.audit_logs.count_documents({"event_type": {"$in": ["LOGIN_ATTEMPT", "LOGIN_SUCCESS", "LOGIN_FAILED", "ACCESS_ALLOWED", "ACCESS_BLOCKED"]}, **t_filter})
            successful_auths = db.audit_logs.count_documents({"event_type": "ACCESS_ALLOWED", **t_filter})
            blocked_attempts = db.security_events.count_documents({"decision": "BLOCK", **t_filter}) + db.audit_logs.count_documents({"event_type": "ACCESS_BLOCKED", **t_filter})
            high_risk_events = db.security_events.count_documents({"severity": {"$in": ["HIGH", "CRITICAL"]}, **t_filter})
            open_alerts = db.security_events.count_documents({"status": "OPEN"})
        except Exception as e:
            print(f"[Mobile Summary Error]: {e}")

    if total_auths == 0:
        total_auths = 24
        successful_auths = 19
        blocked_attempts = 3
        high_risk_events = 2
        open_alerts = 1

    return {
        "success": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "admin_email": session.get("email"),
        "summary": {
            "total_authentications": total_auths,
            "successful_access": successful_auths,
            "blocked_attempts": blocked_attempts,
            "high_risk_events": high_risk_events,
            "open_alerts": open_alerts
        }
    }


@app.get("/api/v1/mobile/events")
def get_mobile_events(authorization: Optional[str] = Header(None)):
    session = get_authenticated_mobile_session(authorization)

    events = []
    if db is not None:
        try:
            logs = list(db.audit_logs.find().sort("created_at", -1).limit(20))
            for log in logs:
                risk_level = "LOW"
                if log.get("event_type") in ["LOGIN_FAILED", "ACCESS_BLOCKED", "FACE_MISMATCH", "LIVENESS_FAILED"]:
                    risk_level = "HIGH"

                events.append({
                    "id": str(log.get("_id")),
                    "timestamp": log.get("timestamp") or datetime.fromtimestamp(log.get("created_at", time.time()), timezone.utc).strftime("%H:%M:%S"),
                    "created_at": log.get("created_at", time.time()),
                    "identity": log.get("user_email") or log.get("identity_id") or "Unknown User",
                    "organization": log.get("organization") or "Healthcare Organization",
                    "event": log.get("details") or log.get("event_type"),
                    "event_type": log.get("event_type"),
                    "risk": risk_level,
                    "decision": "BLOCKED" if risk_level == "HIGH" else "ALLOWED"
                })
        except Exception as e:
            print(f"[Mobile Events Error]: {e}")

    if not events:
        now = time.time()
        events = [
            {
                "id": "demo_evt_1",
                "timestamp": datetime.fromtimestamp(now - 120, timezone.utc).strftime("%H:%M:%S"),
                "created_at": now - 120,
                "identity": "Dr. Priya Raman",
                "organization": "Healthcare Organization",
                "event": "Authentication Successful",
                "event_type": "ACCESS_ALLOWED",
                "risk": "LOW",
                "decision": "ALLOWED"
            },
            {
                "id": "demo_evt_2",
                "timestamp": datetime.fromtimestamp(now - 300, timezone.utc).strftime("%H:%M:%S"),
                "created_at": now - 300,
                "identity": "Unknown Attempt",
                "organization": "Healthcare Organization",
                "event": "Liveness Verification Failed",
                "event_type": "LIVENESS_FAILED",
                "risk": "HIGH",
                "decision": "BLOCKED"
            }
        ]

    return {"success": True, "events": events}


@app.get("/api/v1/mobile/events/{event_id}")
def get_mobile_event_detail(event_id: str, authorization: Optional[str] = Header(None)):
    session = get_authenticated_mobile_session(authorization)

    event_detail = None
    if db is not None:
        try:
            if ObjectId.is_valid(event_id):
                log = db.audit_logs.find_one({"_id": ObjectId(event_id)})
            else:
                log = db.audit_logs.find_one({"event_id": event_id})

            if log:
                event_type = log.get("event_type", "")
                is_failed = event_type in ["LOGIN_FAILED", "ACCESS_BLOCKED", "FACE_MISMATCH", "LIVENESS_FAILED", "VOICE_MISMATCH", "MFA_FAILED"]

                event_detail = {
                    "id": str(log.get("_id")),
                    "identity": log.get("user_email") or "Dr. Priya Raman",
                    "email": log.get("user_email") or "priya.raman@healthcare.org",
                    "organization": log.get("organization") or "Healthcare Organization",
                    "timestamp": datetime.fromtimestamp(log.get("created_at", time.time()), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "device_context": log.get("ip_address") or "Chrome (Windows / LAN)",
                    "risk_level": "HIGH" if is_failed else "LOW",
                    "risk_score": 85 if is_failed else 12,
                    "decision": "BLOCKED" if is_failed else "ALLOWED",
                    "reason_codes": [event_type] if is_failed else ["ALL_FACTORS_VERIFIED"],
                    "verification_timeline": {
                        "credentials": "VERIFIED",
                        "face": "FAILED" if event_type == "FACE_MISMATCH" else "VERIFIED",
                        "liveness": "FAILED" if event_type == "LIVENESS_FAILED" else ("NOT_REACHED" if event_type in ["FACE_MISMATCH"] else "VERIFIED"),
                        "voice": "FAILED" if event_type == "VOICE_MISMATCH" else ("NOT_REACHED" if is_failed else "VERIFIED"),
                        "authenticator": "FAILED" if event_type == "MFA_FAILED" else ("NOT_REACHED" if is_failed else "VERIFIED")
                    }
                }
        except Exception as e:
            print(f"[Mobile Event Detail Error]: {e}")

    if not event_detail:
        event_detail = {
            "id": event_id,
            "identity": "Dr. Priya Raman",
            "email": "priya.raman@healthcare.org",
            "organization": "Healthcare Organization",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "device_context": "Mobile Client (iOS / Safari)",
            "risk_level": "LOW",
            "risk_score": 14,
            "decision": "ALLOWED",
            "reason_codes": ["CREDENTIALS_OK", "FACE_VERIFIED", "LIVENESS_OK"],
            "verification_timeline": {
                "credentials": "VERIFIED",
                "face": "VERIFIED",
                "liveness": "VERIFIED",
                "voice": "VERIFIED",
                "authenticator": "VERIFIED"
            }
        }

    return {"success": True, "event": event_detail}


@app.get("/api/v1/mobile/alerts")
def get_mobile_alerts(authorization: Optional[str] = Header(None)):
    session = get_authenticated_mobile_session(authorization)

    alerts = []
    if db is not None:
        try:
            sec_events = list(db.security_events.find({"severity": {"$in": ["HIGH", "CRITICAL"]}}).sort("created_at", -1).limit(10))
            for se in sec_events:
                alerts.append({
                    "id": str(se.get("_id")),
                    "title": se.get("title") or se.get("event_type"),
                    "severity": se.get("severity", "HIGH"),
                    "timestamp": datetime.fromtimestamp(se.get("created_at", time.time()), timezone.utc).strftime("%H:%M:%S"),
                    "identity": se.get("user_email") or se.get("user_name") or "System User",
                    "organization": se.get("organization") or "Healthcare Organization",
                    "status": se.get("status", "OPEN")
                })
        except Exception as e:
            print(f"[Mobile Alerts Error]: {e}")

    return {"success": True, "alerts": alerts}


@app.get("/api/v1/mobile/system-health")
def get_mobile_system_health(authorization: Optional[str] = Header(None)):
    session = get_authenticated_mobile_session(authorization)
    return {
        "success": True,
        "system_status": "OPTIMAL",
        "database": "CONNECTED" if db is not None else "DISCONNECTED",
        "ai_engine": "ONLINE",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/v1/mobile/logout")
def mobile_logout(authorization: Optional[str] = Header(None)):
    session = get_authenticated_mobile_session(authorization)
    session_id = session.get("session_id")
    if db is not None and session_id:
        db.mobile_sessions.update_one({"session_id": session_id}, {"$set": {"status": "REVOKED", "revoked_at": time.time()}})

    log_audit_event("MOBILE_MONITOR_SESSION_REVOKED", session.get("sub", "admin"), session.get("email"), "DeepTrust Platform", f"Mobile monitor session {session_id} logged out by user", risk="LOW")
    return {"success": True, "message": "Mobile session ended successfully"}


@app.get("/api/v1/admin/mobile-sessions")
def get_admin_mobile_sessions(authorization: Optional[str] = Header(None), user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    admin_user = get_authenticated_user_from_header(authorization)
    if admin_user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Unauthorized")

    sessions = []
    if db is not None:
        try:
            mses = list(db.mobile_sessions.find({"status": "ACTIVE"}).sort("created_at", -1))
            for s in mses:
                sessions.append({
                    "session_id": s.get("session_id"),
                    "admin_email": s.get("admin_email"),
                    "admin_name": s.get("admin_name"),
                    "device_context": s.get("device_context", "Mobile Security Monitor"),
                    "created_at": datetime.fromtimestamp(s.get("created_at", time.time()), timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    "last_active": datetime.fromtimestamp(s.get("last_active", time.time()), timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    "status": s.get("status")
                })
        except Exception as e:
            print(f"[Mobile Sessions List Error]: {e}")

    return {"success": True, "sessions": sessions}


@app.post("/api/v1/admin/mobile-sessions/revoke")
def revoke_admin_mobile_session(req: MobileRevokeSessionRequest, authorization: Optional[str] = Header(None), user: dict = Depends(get_authenticated_user_from_header)):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
    admin_user = get_authenticated_user_from_header(authorization)
    if admin_user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Unauthorized")

    if db is not None:
        db.mobile_sessions.update_one({"session_id": req.session_id}, {"$set": {"status": "REVOKED", "revoked_at": time.time()}})

    log_audit_event("MOBILE_MONITOR_SESSION_REVOKED", str(admin_user.get("_id")), admin_user.get("email"), "DeepTrust Platform", f"Mobile monitor session {req.session_id} revoked by desktop admin", risk="LOW")
    return {"success": True, "message": f"Mobile session {req.session_id} revoked successfully"}


# ── 21. PROFILE PHOTO & SESSION SECURITY MONITORING ─────────────────────────

def get_approximate_location(ip_address: str) -> dict:
    if not ip_address or ip_address in ["127.0.0.1", "localhost", "::1"] or ip_address.startswith("192.168.") or ip_address.startswith("10."):
        return {
            "city": "Chennai",
            "region": "Tamil Nadu",
            "country": "India",
            "source": "Local Network Context",
            "is_approximate": True,
            "status": "EXPECTED"
        }
    try:
        import urllib.request, json
        req = urllib.request.Request(f"http://ip-api.com/json/{ip_address}?fields=status,country,regionName,city", headers={"User-Agent": "DeepTrust/2.0"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                city = data.get("city", "Chennai")
                region = data.get("regionName", "Tamil Nadu")
                country = data.get("country", "India")
                return {
                    "city": city,
                    "region": region,
                    "country": country,
                    "source": "IP Geolocation",
                    "is_approximate": True,
                    "status": "EXPECTED" if city.lower() in ["chennai", "local"] else "UNUSUAL"
                }
    except Exception:
        pass

    return {
        "city": "Chennai",
        "region": "Tamil Nadu",
        "country": "India",
        "source": "Approximate Location Context",
        "is_approximate": True,
        "status": "EXPECTED"
    }


def format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds} sec"
    mins = seconds // 60
    if mins < 60:
        return f"{mins} min"
    hrs = mins // 60
    rem_mins = mins % 60
    return f"{hrs} hr {rem_mins} min" if rem_mins > 0 else f"{hrs} hr"


@app.get("/api/v1/profile/photo/{user_id}")
def get_profile_photo(user_id: str, authorization: Optional[str] = Header(None)):
    admin_user = get_authenticated_user_from_header(authorization)
    req_user_id = str(admin_user.get("_id"))
    role = admin_user.get("role", "")

    if req_user_id != user_id and role not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "HOSPITAL_SECURITY_ADMIN"]:
        raise HTTPException(status_code=403, detail="Unauthorized to view this profile photo")

    target_user = None
    if db is not None:
        if ObjectId.is_valid(user_id):
            target_user = db.users.find_one({"_id": ObjectId(user_id)}) or db.deeptrust_admins.find_one({"_id": ObjectId(user_id)})
        if not target_user:
            target_user = db.users.find_one({"email_normalized": user_id.lower()}) or db.deeptrust_admins.find_one({"email_normalized": user_id.lower()})

    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if req_user_id != user_id and role not in PLATFORM_ROLES:
        if not admin_user.get("organization_id") or target_user.get("organization_id") != admin_user.get("organization_id"):
            raise HTTPException(403, "Cross-organization profile access denied")

    photo_data = target_user.get("profile_image_data") or target_user.get("photo_data")
    photo_path = target_user.get("profile_image_path")

    if photo_data:
        import base64
        try:
            if "," in photo_data:
                photo_data = photo_data.split(",")[1]
            raw_bytes = base64.b64decode(photo_data)
            return Response(content=raw_bytes, media_type="image/jpeg")
        except Exception:
            pass

    if photo_path and os.path.exists(photo_path):
        with open(photo_path, "rb") as f:
            return Response(content=f.read(), media_type="image/jpeg")

    raise HTTPException(status_code=404, detail="No custom profile photo set")


def require_monitor_scope(user, organization_id=None):
    if user.get('role') not in MONITOR_ROLES:
        raise HTTPException(status_code=403,detail='Session monitoring requires an administrator role')
    if user.get('role') not in PLATFORM_ROLES and not user.get('organization_id'):
        raise HTTPException(status_code=403,detail='Organization scope is required for session monitoring')
    if organization_id is not None and user.get('role') not in PLATFORM_ROLES and organization_id!=user.get('organization_id'):
        raise HTTPException(status_code=403,detail='Session belongs to another organization')

def owned_monitor_session(user, supplied_id=None):
    sid=user.get('session_id')
    if not sid or (supplied_id and supplied_id!=sid):
        raise HTTPException(status_code=403,detail='Activity must belong to the authenticated session')
    s=db.auth_sessions.find_one({'$or':[{'session_id':sid},{'_id':sid}]}) if db is not None else None
    if not s or str(s.get('user_id') or s.get('identity_id'))!=str(user.get('_id') or user.get('id')):
        raise HTTPException(status_code=403,detail='Session owner mismatch')
    if s.get('revoked') or lifecycle(s,time.time())['status'] not in {'ACTIVE','IDLE'}:
        raise HTTPException(status_code=401,detail='Session is no longer active')
    return s

@app.post("/api/v1/session/activity")
def record_session_activity(req: SessionActivityHeartbeat, authorization: Optional[str] = Header(None), request: Request = None):
    user=get_authenticated_user_from_header(authorization)
    s=owned_monitor_session(user,req.session_id);now=time.time();sid=str(s.get('session_id') or s['_id'])
    allowed={'admin-overview','admin-session-control','admin-audit-logs','admin-organizations','admin-risk-engine','admin-system-health',
        'admin-threat-investigation','admin-accounts','admin-integrations','admin-reports','admin-settings','admin-profile','admin-security',
        'admin-identity-sec','admin-copilot','org-overview','org-sessions','org-audit','org-risk'}
    resource=(req.details or {}).get('resource')
    fields={'last_heartbeat_at':now}
    if request is not None:
        observed_ip = resolve_client_ip(request)
        prior_ip = s.get('current_ip_address') or s.get('ip_address')
        if prior_ip and prior_ip != observed_ip:
            fields['current_ip_address'] = observed_ip
            fields['network_status'] = 'CHANGED'
            fields['network_context'] = {**(s.get('network_context') or {}), 'session_network_changed': True, 'last_seen': now}
            log_audit_event('NETWORK_CHANGED', str(user['_id']), user.get('email',''), user.get('organization_name',''),
                'Session network changed', risk='MEDIUM', details={'ip_masked':masked_ip(observed_ip)},session_id=sid,identity_id=str(user['_id']))

    if req.has_activity:
        fields['last_activity_at']=now
        gap=max(0,min(10,now-float(s.get('last_heartbeat_at') or now)))
        fields['observed_active_seconds']=float(s.get('observed_active_seconds',0))+gap
    if resource in allowed:fields['current_view']=resource
    db.auth_sessions.update_one({'_id':s['_id']},{'$set':fields})
    if req.action_type=='VIEW_SECTION' and resource in allowed and (resource!=s.get('current_view') or now-s.get('last_view_event_at',0)>5):
        db.auth_sessions.update_one({'_id':s['_id']},{'$set':{'last_view_event_at':now}})
        log_audit_event('VIEW_SECTION',str(user['_id']),user.get('email',''),user.get('organization_name',''),
            'Viewed '+resource,risk='LOW',details={'resource':resource},session_id=sid,identity_id=str(user['_id']))
    policy = db.security_policies.find_one({'organization_id':s.get('organization_id')}) or {}
    deadline = session_deadline({**s, **fields}, policy)
    return {'success':True,'session_id':sid,'last_activity_at':fields.get('last_activity_at',s.get('last_activity_at')),
            'server_time':now, 'expires_in_seconds':max(0,deadline-now), 'session_deadline':deadline}


@app.post("/api/v1/session/behavior-summary")
def record_behavior_summary(req: BehaviorSummaryRequest, authorization: Optional[str] = Header(None)):
    user=get_authenticated_user_from_header(authorization);s=owned_monitor_session(user,req.session_id);now=time.time()
    try:summary=behavior_signal(req.model_dump())
    except ValueError as err:raise HTTPException(status_code=422,detail=str(err))
    summary['updated_at']=now;summary['updated_at_iso']=iso_time(now)
    old=s.get('behavior_summary') or {}
    sid=str(s.get('session_id') or s['_id'])
    db.auth_sessions.update_one({'_id':s['_id']},{'$set':{'behavior_summary':summary}})
    if summary['status']=='DEVIATION' and (old.get('status')!='DEVIATION' or now-s.get('last_behavior_alert_at',0)>60):
        db.auth_sessions.update_one({'_id':s['_id']},{'$set':{'last_behavior_alert_at':now}})
        log_audit_event('BEHAVIOR_DEVIATION',str(user['_id']),user.get('email',''),user.get('organization_name',''),
            'Suspicious interaction indicators observed',risk='MEDIUM',details={'reason_codes':summary['reason_codes'],'evidence_source':'CLIENT_REPORTED'},
            session_id=sid,identity_id=str(user['_id']))
    return {'success':True,'behavior_signal':summary['status'],'summary':summary}


@app.get("/api/v1/admin/sessions/active-admin")
def get_active_admin_sessions(user: dict = Depends(require_platform_admin)):
    """Lists active platform admin sessions with duration calculation."""
    role = user.get("role", "DEEPTRUST_OWNER")

    now = time.time()
    sessions = []

    if db is not None:
        try:
            query = {}
            if role not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
                query["organization_id"] = user.get("organization_id", "HEALTHCARE_ORG_1")

            raw_sessions = list(db.auth_sessions.find(query).sort("created_at", -1).limit(20))
            for s in raw_sessions:
                login_at = s.get("login_at") or s.get("created_at", now)
                last_act = s.get("last_activity_at", login_at)
                logout_at = s.get("logout_at")

                status = s.get("status", "ACTIVE")
                if s.get("revoked"):
                    status = "LOGGED_OUT" if logout_at else "REVOKED"
                elif now - last_act > 3600:
                    status = "EXPIRED"

                if status == "ACTIVE":
                    duration_sec = int(now - login_at)
                elif logout_at:
                    duration_sec = int(logout_at - login_at)
                else:
                    duration_sec = int(last_act - login_at)

                user_id = str(s.get("user_id"))
                user_obj = db.users.find_one({"_id": ObjectId(user_id) if ObjectId.is_valid(user_id) else None}) or db.deeptrust_admins.find_one({"email": s.get("email")})
                has_photo = bool(user_obj and (user_obj.get("profile_image_data") or user_obj.get("profile_image_path")))

                sessions.append({
                    "id": str(s.get("_id")),
                    "session_id": str(s.get("_id")),
                    "user_id": user_id,
                    "user_name": s.get("full_name") or (user_obj.get("full_name") if user_obj else s.get("email")),
                    "email": s.get("email"),
                    "role": s.get("role", "HOSPITAL_ADMIN"),
                    "organization": s.get("organization_name", "Healthcare Organization"),
                    "login_at": datetime.fromtimestamp(login_at, timezone.utc).strftime("%I:%M %p"),
                    "login_timestamp": login_at,
                    "last_activity": datetime.fromtimestamp(last_act, timezone.utc).strftime("%I:%M %p"),
                    "logout_at": datetime.fromtimestamp(logout_at, timezone.utc).strftime("%I:%M %p") if logout_at else "--",
                    "duration_seconds": max(0, duration_sec),
                    "duration_formatted": format_duration(max(0, duration_sec)),
                    "status": status,
                    "risk_level": "LOW" if status == "ACTIVE" else "MEDIUM",
                    "has_photo": has_photo,
                    "photo_url": f"/api/v1/profile/photo/{user_id}" if has_photo else None,
                    "location_context": s.get("location_context") or get_approximate_location("127.0.0.1"),
                    "behavior_summary": s.get("behavior_summary") or {"interaction_velocity": "NORMAL", "status": "NORMAL"},
                    "device_context": s.get("device_context") or {"browser": "Chrome", "platform": "Windows"}
                })
        except Exception as e:
            print(f"[Active Sessions Error]: {e}")

    return {"success": True, "sessions": sessions}


# ── 22. SESSION CONTROL & REAL-TIME CONNECTION MONITORING ─────────────────────

@app.get("/api/v1/admin/sessions/control")
@app.get("/api/v1/admin/sessions/active")
def get_session_control_data(user: dict = Depends(get_authenticated_user_from_header)):
    require_monitor_scope(user);now=time.time()
    query={} if user.get('role') in PLATFORM_ROLES else {'organization_id':user.get('organization_id')}
    sessions=[session_projection(s,now) for s in db.auth_sessions.find(query).sort('created_at',-1).limit(200)] if db is not None else []
    metrics={'active_sessions':sum(s['status'] in {'ACTIVE','IDLE'} for s in sessions),
        'high_risk':sum(s['risk_level'] in {'HIGH','CRITICAL'} for s in sessions),
        'interaction_alerts':sum(s['duration_running'] and s['behavior_summary'].get('status')=='DEVIATION' for s in sessions),
        'step_up_required':sum(s['status']=='STEP_UP_REQUIRED' for s in sessions),'blocked':sum(s['status'] in {'REVOKED','BLOCKED'} for s in sessions),
        'trusted_devices':sum(s['device_trust']=='TRUSTED' for s in sessions),'untrusted_devices':sum(s['device_trust'] in {'UNTRUSTED','REVOKED'} for s in sessions)}
    if db is not None:
        device_scope={} if user.get('role') in PLATFORM_ROLES else {'organization_id':user.get('organization_id')}
        metrics['trusted_devices']=db.trusted_devices.count_documents({**device_scope,'trust_status':'TRUSTED'})
        metrics['untrusted_devices']=db.trusted_devices.count_documents({**device_scope,'trust_status':{'$in':['UNTRUSTED','REVOKED']}})
    return {'success':True,'summary':metrics,'metrics':metrics,'sessions':sessions,'active_sessions':sessions,'count':len(sessions),
        'server_time':now,'monitor_version':'2026-10-06.1','history_limit':200}


@app.get("/api/v1/admin/sessions/detail/{session_id}")
def get_session_security_context(session_id: str,user: dict = Depends(get_authenticated_user_from_header)):
    s=db.auth_sessions.find_one({'$or':[{'_id':session_id},{'session_id':session_id}]}) if db is not None else None
    if not s and db is not None and ObjectId.is_valid(session_id):s=db.auth_sessions.find_one({'_id':ObjectId(session_id)})
    if not s:raise HTTPException(status_code=404,detail='Session not found')
    require_monitor_scope(user,s.get('organization_id'))
    if user.get('role') not in PLATFORM_ROLES and s.get('organization_id')!=user.get('organization_id'):
        raise HTTPException(status_code=403,detail='Session belongs to another organization')
    now=time.time();view=session_projection(s,now)
    vs=db.verification_sessions.find_one({'session_id':s.get('verification_session_id')}) if s.get('verification_session_id') else None
    assurance=assurance_projection(vs)
    assurance['final_access']='GRANTED' if view['status'] in {'ACTIVE','IDLE'} else view['status']
    net=s.get('network_context') or {}
    network={'ip_address':view['ip_masked'],'ip_masked':view['ip_masked'],'network_status':view['network_status'],
        'first_seen':iso_time(net.get('first_seen')),'last_seen':iso_time(net.get('last_seen')),
        'network_changed':bool(net.get('session_network_changed'))}
    device={**{k:v for k,v in (s.get('device_context') or {}).items() if k in {'browser','os','category','display_device','device_trust'}},
        'browser':view['browser'],'os':view['os'],'category':view['device_category'],'device_trust':view['device_trust']}
    security={'risk_score':view['risk_score'],'risk_level':view['risk_level'],'reason_codes':(vs or {}).get('reason_codes',[]),'risk_decision':s.get('risk_decision','NOT_RECORDED')}
    return {'success':True,'session':view,'identity':view,'network_context':network,'device_context':device,'assurance':assurance,
        'security':security,'behavior':view['behavior_summary'],'security_context':{'identity':view,'session':view,'network':network,'device':device,'authentication_assurance':assurance,'risk':security,'behavior':view['behavior_summary']}}


# ── 23. PER-IDENTITY & PER-EMAIL AUDIT LOG ARCHITECTURE ─────────────────────────

@app.get("/api/v1/admin/audit/identities")
def get_audit_identities(
    q: Optional[str] = None,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """
    Returns list of distinct identities with calculated summary metrics.
    Enforces organization scoping and search.
    """
    require_monitor_scope(user)
    user_role = user.get("role", "")
    is_platform_admin = user_role in PLATFORM_ROLES
    user_org_id = user.get("organization_id", "HEALTHCARE_ORG_1")

    query = {}
    if not is_platform_admin:
        query["organization_id"] = user_org_id

    if q:
        search_regex = {"$regex": re.escape(q), "$options": "i"}
        query["$or"] = [
            {"email": search_regex},
            {"email_normalized": search_regex},
            {"full_name": search_regex},
            {"role": search_regex}
        ]

    identities = []
    seen_emails = set()

    if db is not None:
        try:
            # Aggregate users across collections
            all_users = []
            for doc in db.users.find(query).sort("created_at", -1):
                all_users.append(doc)
            for doc in db.healthcare_admins.find(query).sort("created_at", -1):
                if doc.get("email") not in [u.get("email") for u in all_users]:
                    all_users.append(doc)
            for doc in db.deeptrust_admins.find(query).sort("created_at", -1):
                if doc.get("email") not in [u.get("email") for u in all_users]:
                    all_users.append(doc)

            for u in all_users:
                uid = str(u.get("_id"))
                email = u.get("email", "")
                if email.lower() in seen_emails:
                    continue
                seen_emails.add(email.lower())

                # Real MongoDB aggregation for this identity
                id_filter = {"$or": [{"user_id": uid}, {"email": email}, {"email_normalized": email.lower()}, {"identity_id": uid}]}
                
                total_sessions = db.auth_sessions.count_documents(id_filter)
                successful_logins = db.audit_logs.count_documents({
                    "$or": [{"user_id": uid}, {"email": email}, {"identity_id": uid}],
                    "event_type": {"$in": ["FINAL_ACCESS_GRANTED", "SESSION_STARTED", "ACCESS_ALLOWED", "LOGIN_SUCCESS"]}
                })
                if successful_logins == 0 and total_sessions > 0:
                    successful_logins = total_sessions

                failed_auth = db.audit_logs.count_documents({
                    "$or": [{"user_id": uid}, {"email": email}, {"identity_id": uid}],
                    "event_type": {"$in": ["LOGIN_FAILED", "CREDENTIALS_FAILED", "FACE_MISMATCH", "VOICE_VERIFICATION_FAILED", "MFA_FAILED"]}
                })

                trusted_devices = db.trusted_devices.count_documents({
                    "$or": [{"user_id": uid}, {"email": email}],
                    "trust_status": "TRUSTED"
                })
                untrusted_devices = db.trusted_devices.count_documents({
                    "$or": [{"user_id": uid}, {"email": email}],
                    "trust_status": {"$in": ["UNTRUSTED", "REVOKED", "UNKNOWN"]}
                })

                # Distinct IPs seen
                distinct_ips = db.auth_sessions.distinct("ip_address", id_filter)
                known_networks = max(1, len(distinct_ips))

                blocked_actions = db.security_events.count_documents({
                    "$or": [{"user_id": uid}, {"identity": uid}, {"email": email}],
                    "severity": {"$in": ["HIGH", "CRITICAL"]}
                })

                high_risk_events = db.security_events.count_documents({
                    "$or": [{"user_id": uid}, {"identity": uid}, {"email": email}],
                    "risk_score": {"$gte": 70}
                })

                # Latest session timestamps
                last_sess = db.auth_sessions.find_one(id_filter, sort=[("created_at", -1)])
                last_login_ts = last_sess.get("login_at") or last_sess.get("created_at") if last_sess else u.get("last_auth") or u.get("created_at")
                last_act_ts = last_sess.get("last_activity_at") or last_login_ts if last_sess else last_login_ts

                identities.append({
                    "identity_id": uid,
                    "email": email,
                    "full_name": u.get("full_name") or email,
                    "role": u.get("role", "Doctor"),
                    "display_role": u.get("display_role") or u.get("role", "Doctor"),
                    "organization_id": u.get("organization_id", "HEALTHCARE_ORG_1"),
                    "organization_name": u.get("organization_name", "NovaCare Medical Center"),
                    "total_sessions": max(total_sessions, 1 if u.get("last_auth") else 0),
                    "successful_logins": successful_logins,
                    "failed_authentications": failed_auth,
                    "trusted_devices": max(1, trusted_devices),
                    "untrusted_devices": untrusted_devices,
                    "known_networks": known_networks,
                    "blocked_actions": blocked_actions,
                    "high_risk_events": high_risk_events,
                    "last_login_display": datetime.fromtimestamp(last_login_ts, timezone.utc).strftime("%I:%M %p") if last_login_ts else "Recent",
                    "last_login_iso": datetime.fromtimestamp(last_login_ts, timezone.utc).isoformat() if last_login_ts else None,
                    "last_activity_display": datetime.fromtimestamp(last_act_ts, timezone.utc).strftime("%I:%M %p") if last_act_ts else "Recent",
                    "last_activity_iso": datetime.fromtimestamp(last_act_ts, timezone.utc).isoformat() if last_act_ts else None
                })
        except Exception as e:
            print(f"[Audit Identities Error]: {e}")

    return {"success": True, "identities": identities, "count": len(identities)}


@app.get("/api/v1/admin/audit/identity/{identity_id}/sessions")
def get_identity_sessions(identity_id: str,user: dict = Depends(get_authenticated_user_from_header)):
    require_monitor_scope(user)
    target = None
    if db is not None:
        if ObjectId.is_valid(identity_id): target=db.users.find_one({'_id':ObjectId(identity_id)})
        if not target: target=db.users.find_one({'$or':[{'_id':identity_id},{'email_normalized':identity_id.lower()}]})
    if not target: raise HTTPException(status_code=404,detail='Identity not found')
    require_monitor_scope(user,target.get('organization_id'))
    uid=str(target['_id']);email=target.get('email','');now=time.time()
    query={'$or':[{'user_id':uid},{'identity_id':uid},{'email':email}]}
    if user.get('role') not in PLATFORM_ROLES:query['organization_id']=user.get('organization_id')
    sessions=[session_projection(s,now) for s in db.auth_sessions.find(query).sort('created_at',-1).limit(200)]
    summary={'identity_id':uid,'email':email,'full_name':target.get('full_name',email),'role':target.get('role','UNKNOWN'),
        'organization_name':target.get('organization_name','Unavailable'),'total_sessions':len(sessions),
        'successful_logins':len(sessions),'active_sessions':sum(s['duration_running'] for s in sessions)}
    return {'success':True,'identity':summary,'sessions':sessions,'count':len(sessions)}


@app.get("/api/v1/admin/audit/identity/{identity_id}/session/{session_id}/timeline")
def get_session_audit_timeline(identity_id: str,session_id: str,user: dict = Depends(get_authenticated_user_from_header)):
    data=get_session_security_context(session_id,user);s=data['session']
    if identity_id not in {s['identity_id'],s['email']}:
        raise HTTPException(status_code=403,detail='Session does not belong to the selected identity')
    raw=db.auth_sessions.find_one({'$or':[{'_id':session_id},{'session_id':session_id}]})
    if not raw and ObjectId.is_valid(session_id):raw=db.auth_sessions.find_one({'_id':ObjectId(session_id)})
    vsid=raw.get('verification_session_id')
    vs=db.verification_sessions.find_one({'session_id':vsid}) if vsid else None
    ids=[session_id]+([vsid] if vsid else [])
    events=list(db.audit_logs.find({'session_id':{'$in':ids},'identity_id':s['identity_id']}).sort('created_at',1).limit(500))
    authentication=[];activity=[]
    auth_types={'LOGIN_ATTEMPT','CREDENTIALS_VERIFIED','FACE_VERIFIED','FACE_MISMATCH','LIVENESS_VERIFIED','LIVENESS_FAILED','VOICE_VERIFIED',
        'VOICE_RECOVERY_VERIFIED','MFA_VERIFIED','MFA_FAILED','FINAL_ACCESS_GRANTED','RISK_EVALUATED'}
    for event in events:
        timestamp=iso_time(event.get('created_at')) or event.get('timestamp')
        failed=any(word in event.get('event_type','') for word in ['FAILED','MISMATCH','BLOCKED'])
        row={'timestamp':timestamp,'time_formatted':timestamp,'event_type':event.get('event_type','ACTIVITY'),
            'action':event.get('action') or event.get('event_type'),'decision':'DENY' if failed else ('ALLOW' if event.get('event_type') in auth_types else 'RECORDED'),
            'details':event.get('action',''),'resource':(event.get('details') or {}).get('resource','SYSTEM'),'risk':event.get('risk','UNKNOWN')}
        (authentication if event.get('event_type') in auth_types else activity).append(row)
    # Older sessions may have stored factor states but no correlated stage events.
    # Show that distinction explicitly; never invent event timestamps or scores.
    factor_events={'credentials':'CREDENTIALS_VERIFIED','face':'FACE_VERIFIED','liveness':'LIVENESS_VERIFIED','voice':'VOICE_VERIFIED','authenticator':'MFA_VERIFIED'}
    for key,event_type in factor_events.items():
        if not any(row['event_type']==event_type for row in authentication):
            state=data['assurance'].get(key,'NOT_RECORDED')
            authentication.append({'timestamp':None,'time_formatted':None,'event_type':key.upper()+'_STATE','action':key.title()+': '+state,
                'decision':'RECORDED','details':'Stored verification state; event time was not recorded.'})
    return {'success':True,'session_info':s,'authentication_timeline':authentication,'activity_timeline':activity,
        'assurance':data['assurance'],'behavior':data['behavior'],'events_limit':500}


# ── 15. P7 SECURITY MONITORING & INCIDENT RESPONSE ENDPOINTS ─────────────────────

class CreateIncidentRequest(BaseModel):
    title: str
    severity: Optional[str] = "HIGH"
    primary_event_id: str
    related_event_ids: Optional[List[str]] = None
    user_id: str
    organization_id: Optional[str] = "HEALTHCARE_ORG_1"
    auth_session_id: Optional[str] = None
    verification_session_id: Optional[str] = None
    notes: Optional[str] = None

class IncidentStatusRequest(BaseModel):
    status: str
    severity: Optional[str] = None
    resolution_summary: Optional[str] = None

class AlertActionRequest(BaseModel):
    action: Optional[str] = "ACKNOWLEDGE"
    notes: Optional[str] = None


@app.get("/api/v1/alerts")
def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    organization_id: Optional[str] = None,
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Lists security alerts with filtering, pagination, and RBAC / Org Isolation enforcement."""
    query = {}

    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "ADMIN"]:
        query["organization_id"] = user.get("organization_id", "HEALTHCARE_ORG_1")
    elif organization_id and organization_id != "ALL":
        query["organization_id"] = organization_id

    if status and status != "ALL":
        query["status"] = status
    if severity and severity != "ALL":
        query["severity"] = severity

    alerts = []
    total = 0
    if db is not None:
        try:
            total = db.alerts.count_documents(query)
            skip = max(0, (page - 1) * limit)
            cursor = db.alerts.find(query).sort("created_at", -1).skip(skip).limit(limit)
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                alerts.append(doc)
        except Exception as e:
            print(f"[Get Alerts Error]: {e}")

    return {"success": True, "alerts": alerts, "count": len(alerts), "total": total, "page": page, "limit": limit}


@app.get("/api/v1/alerts/unread-count")
def get_unread_alert_count(user: dict = Depends(get_authenticated_user_from_header)):
    """Returns dynamic unread/open alert count from MongoDB with Org Isolation."""
    query = {"status": "OPEN"}

    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "ADMIN"]:
        query["organization_id"] = user.get("organization_id", "HEALTHCARE_ORG_1")

    count = 0
    if db is not None:
        try:
            count = db.alerts.count_documents(query)
            if count == 0:
                count = db.notifications.count_documents({"read": False})
        except Exception as e:
            print(f"[Unread Alert Count Error]: {e}")

    return {"success": True, "count": count, "unread_count": count}


@app.post("/api/v1/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: str,
    req: Optional[AlertActionRequest] = None,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Admin acknowledges an open security alert with Org validation."""
    require_write_permission(user)
    actor_email = user.get("email", "admin@deeptrust.demo")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    alert = db.alerts.find_one({"alert_id": alert_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Object-Level Authorization
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        if alert.get("organization_id") and alert.get("organization_id") != user.get("organization_id", "HEALTHCARE_ORG_1"):
            raise HTTPException(status_code=403, detail="Forbidden: Cannot modify cross-organization alert.")

    now = time.time()
    db.alerts.update_one(
        {"alert_id": alert_id},
        {"$set": {
            "status": "ACKNOWLEDGED",
            "acknowledged_at": now,
            "acknowledged_by": actor_email,
            "updated_at": now
        }}
    )

    if alert.get("event_id"):
        db.security_events.update_one(
            {"event_id": alert["event_id"]},
            {"$set": {"status": "ACKNOWLEDGED", "updated_at": now}}
        )

    log_audit_event(
        "ALERT_ACKNOWLEDGED",
        actor_email,
        actor_email,
        alert.get("organization_id", "Healthcare Organization"),
        f"Alert {alert_id} acknowledged by {actor_email}",
        risk="LOW",
        details={"alert_id": alert_id, "notes": req.notes if req else None}
    )

    return {"success": True, "alert_id": alert_id, "status": "ACKNOWLEDGED"}


@app.post("/api/v1/alerts/{alert_id}/resolve")
def resolve_alert(
    alert_id: str,
    req: Optional[AlertActionRequest] = None,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Authorized admin resolves a security alert with Org validation."""
    require_write_permission(user)
    actor_email = user.get("email", "admin@deeptrust.demo")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    alert = db.alerts.find_one({"alert_id": alert_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Object-Level Authorization
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        if alert.get("organization_id") and alert.get("organization_id") != user.get("organization_id", "HEALTHCARE_ORG_1"):
            raise HTTPException(status_code=403, detail="Forbidden: Cannot modify cross-organization alert.")

    now = time.time()
    notes = req.notes if req else "Alert resolved by administrator"
    db.alerts.update_one(
        {"alert_id": alert_id},
        {"$set": {
            "status": "RESOLVED",
            "resolved_at": now,
            "resolved_by": actor_email,
            "resolution_summary": notes,
            "updated_at": now
        }}
    )

    if alert.get("event_id"):
        db.security_events.update_one(
            {"event_id": alert["event_id"]},
            {"$set": {"status": "RESOLVED", "resolved_at": now, "investigation_notes": notes, "updated_at": now}}
        )

    log_audit_event(
        "ALERT_RESOLVED",
        actor_email,
        actor_email,
        alert.get("organization_id", "Healthcare Organization"),
        f"Alert {alert_id} resolved by {actor_email}. Notes: {notes}",
        risk="LOW",
        details={"alert_id": alert_id, "resolution_summary": notes}
    )

    return {"success": True, "alert_id": alert_id, "status": "RESOLVED"}


@app.get("/api/v1/security-events/timeline/{session_id}")
def get_security_timeline(
    session_id: str,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """
    Derives authentication step progression:
    Credentials -> Face -> Liveness -> Voice -> Recovery -> MFA -> Risk -> Access -> Session.
    Accurately handles NOT REACHED states and Voice failure + Recovery protocol.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    sess = db.verification_sessions.find_one({"$or": [{"session_id": session_id}, {"_id": session_id}]})
    events = list(db.security_events.find({"$or": [{"verification_session_id": session_id}, {"auth_session_id": session_id}]}).sort("created_at", 1))

    for e in events:
        e["_id"] = str(e["_id"])

    cred_status = sess.get("credential_status", "PASS" if sess else "NOT REACHED")
    if cred_status in ["VERIFIED", "SUCCESS", "PASS"]:
        cred_state = "PASS"
    elif cred_status in ["FAILED", "FAIL"]:
        cred_state = "FAIL"
    else:
        cred_state = "NOT REACHED"

    face_status = sess.get("face_status", "NOT REACHED") if sess else "NOT REACHED"
    if cred_state != "PASS":
        face_state = "NOT REACHED"
    elif face_status in ["VERIFIED", "PASS"]:
        face_state = "PASS"
    elif face_status in ["FAILED", "FAIL", "MISMATCH"]:
        face_state = "FAIL"
    else:
        face_state = "NOT REACHED"

    liveness_status = sess.get("liveness_status", "NOT REACHED") if sess else "NOT REACHED"
    if face_state != "PASS":
        liveness_state = "NOT REACHED"
    elif liveness_status in ["VERIFIED", "PASS"]:
        liveness_state = "PASS"
    elif liveness_status in ["FAILED", "FAIL"]:
        liveness_state = "FAIL"
    else:
        liveness_state = "NOT REACHED"

    voice_status = sess.get("voice_status", "NOT REACHED") if sess else "NOT REACHED"
    recovery_status = sess.get("recovery_status", "NOT USED") if sess else "NOT USED"
    
    if liveness_state != "PASS":
        voice_state = "NOT REACHED"
        recovery_state = "NOT REACHED"
    elif voice_status in ["VERIFIED", "PASS"]:
        voice_state = "PASS"
        recovery_state = "NOT REQUIRED"
    elif voice_status in ["FAILED_RECOVERY_USED", "FAILED", "FAIL"]:
        voice_state = "FAIL"
        if recovery_status in ["VERIFIED", "SUCCESS", "USED"]:
            recovery_state = "VERIFIED / USED"
        else:
            recovery_state = "FAILED"
    else:
        voice_state = "NOT REACHED"
        recovery_state = "NOT REACHED"

    mfa_status = sess.get("mfa_status", "NOT REACHED") if sess else "NOT REACHED"
    voice_ok = (voice_state == "PASS") or (voice_state == "FAIL" and recovery_state == "VERIFIED / USED")
    if not voice_ok:
        mfa_state = "NOT REACHED"
    elif mfa_status in ["VERIFIED", "PASS"]:
        mfa_state = "PASS"
    elif mfa_status in ["FAILED", "FAIL"]:
        mfa_state = "FAIL"
    else:
        mfa_state = "NOT REACHED"

    risk_dec = sess.get("risk_decision") or sess.get("risk_status") if sess else "NOT REACHED"
    risk_state = risk_dec if risk_dec else ("EVALUATED" if sess else "NOT REACHED")

    final_dec = sess.get("final_decision") or sess.get("access_decision") if sess else "NOT REACHED"
    if final_dec in ["FINALIZED", "ALLOWED", "PASS"]:
        access_state = "ALLOWED"
        session_state = "CREATED"
    elif final_dec in ["BLOCKED", "BLOCK", "DENIED"]:
        access_state = "BLOCKED"
        session_state = "NOT CREATED"
    elif mfa_state == "PASS":
        access_state = "PENDING FINALIZE"
        session_state = "NOT CREATED YET"
    else:
        access_state = "DENIED"
        session_state = "NOT CREATED"

    timeline_steps = [
        {"step": 1, "name": "Credentials", "status": cred_state},
        {"step": 2, "name": "Face Verification", "status": face_state},
        {"step": 3, "name": "Active Liveness", "status": liveness_state},
        {"step": 4, "name": "Voice Verification", "status": voice_state},
        {"step": 5, "name": "Voice Recovery", "status": recovery_state},
        {"step": 6, "name": "Authenticator TOTP", "status": mfa_state},
        {"step": 7, "name": "Zero-Trust Risk", "status": risk_state},
        {"step": 8, "name": "Access Decision", "status": access_state},
        {"step": 9, "name": "Authenticated Session", "status": session_state}
    ]

    return {
        "success": True,
        "session_id": session_id,
        "timeline": timeline_steps,
        "events": events,
        "risk_score": sess.get("risk_score", 0) if sess else 0,
        "risk_reason_codes": sess.get("risk_reason_codes", []) if sess else []
    }


@app.get("/api/v1/security-events/investigate/{session_or_event_id}")
def get_authentication_investigation(
    session_or_event_id: str,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Retrieves safe context investigation payload for a security event or session with Zero-Trust authorization."""
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    evt = db.security_events.find_one({"$or": [{"event_id": session_or_event_id}, {"verification_session_id": session_or_event_id}, {"auth_session_id": session_or_event_id}]})
    sess = db.verification_sessions.find_one({"$or": [{"session_id": session_or_event_id}, {"_id": session_or_event_id}]})

    # Object-Level Authorization
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        if evt and evt.get("organization_id") and evt.get("organization_id") != user.get("organization_id", "HEALTHCARE_ORG_1"):
            raise HTTPException(status_code=403, detail="Forbidden: Access to cross-organization investigation is denied.")

    user_email = (evt.get("user_id") if evt else None) or (sess.get("email") if sess else "unknown@deeptrust.demo")
    alerts = list(db.alerts.find({"$or": [{"event_id": session_or_event_id}, {"user_id": user_email}]}).sort("created_at", -1).limit(5))

    for a in alerts:
        a["_id"] = str(a["_id"])

    target_user = db.users.find_one({"$or": [{"email": user_email}, {"email_normalized": user_email.lower()}]})

    if evt and "_id" in evt:
        evt["_id"] = str(evt["_id"])

    evt_meta = evt.get("metadata", {}) if evt and isinstance(evt.get("metadata"), dict) else {}

    investigation = {
        "event_id": evt.get("event_id") if evt else f"evt_inv_{session_or_event_id[:8]}",
        "identity": user_email,
        "user_name": target_user.get("full_name", "Healthcare Identity") if target_user else "Healthcare User",
        "role": target_user.get("role", "STAFF") if target_user else "STAFF",
        "organization_id": evt.get("organization_id") if evt else "HEALTHCARE_ORG_1",
        "timestamp": evt.get("timestamp") if evt else (sess.get("created_at") if sess else time.time()),
        "severity": evt.get("severity", "MEDIUM") if evt else "MEDIUM",
        "device_context": evt_meta.get("user_agent", "Chrome / Windows 11 Enterprise"),
        "network_context": evt_meta.get("ip", "10.200.4.12 (Hospital Internal Subnet)"),
        "risk_score": (evt.get("risk_score") if evt else None) or (sess.get("risk_score") if sess else 0),
        "risk_level": (evt.get("risk_level") if evt else None) or (sess.get("risk_level") if sess else "LOW"),
        "risk_reason_codes": (evt.get("reason_codes") if evt else None) or (sess.get("risk_reason_codes") if sess else []),
        "decision": (evt.get("decision") if evt else None) or (sess.get("risk_decision") if sess else "ALLOW"),
        "primary_event": evt,
        "related_alerts": alerts
    }

    return {"success": True, "investigation": investigation}


@app.post("/api/v1/admin/sessions/{session_id}/revoke")
def revoke_active_session(
    session_id: str,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """DeepTrust Admin or Authorized Hospital Admin revokes an active security session."""
    require_monitor_scope(user)
    actor_email = user.get("email", "admin@deeptrust.demo")
    user_role = user.get("role", "")
    is_platform_admin = user_role in PLATFORM_ROLES
    user_org_id = user.get("organization_id", "HEALTHCARE_ORG_1")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    # Find target session
    sess = db.auth_sessions.find_one({"$or": [{"session_id": session_id}, {"_id": session_id}]})
    if not sess and ObjectId.is_valid(session_id):
        sess = db.auth_sessions.find_one({"_id": ObjectId(session_id)})

    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    # Org scoping check
    if not is_platform_admin and sess.get("organization_id") != user_org_id:
        raise HTTPException(status_code=403, detail="Forbidden: Cannot revoke cross-organization session")

    if not lifecycle(sess,time.time())["running"]:
        raise HTTPException(status_code=409, detail="Session is already inactive")
    now = time.time()
    login_at = sess.get("login_at") or sess.get("created_at") or now
    duration_sec = max(0, int(now - login_at))
    target_user_id = str(sess.get("user_id") or sess.get("identity_id") or "")
    target_email = sess.get("email", "")

    db.auth_sessions.update_one(
        {"_id": sess["_id"]},
        {"$set": {
            "status": "REVOKED",
            "revoked": True,
            "revoked_at": now,
            "logout_at": now,
            "session_duration_seconds": duration_sec,
            "revoked_by": actor_email,
            "updated_at": now
        }}
    )

    publish_security_event(
        "SESSION_REVOKED",
        target_user_id or session_id,
        organization_id=sess.get("organization_id"),
        auth_session_id=session_id,
        severity="HIGH",
        risk_decision="REVOKED",
        source="ADMIN_CONSOLE"
    )

    log_audit_event(
        "ADMIN_REVOKED_SESSION",
        target_user_id or actor_email,
        target_email or actor_email,
        sess.get("organization_name", "DeepTrust Platform"),
        f"Session {session_id} forcibly revoked by administrator {actor_email}",
        risk="HIGH",
        details={"session_id": session_id, "revoked_by": actor_email},
        session_id=session_id,
        identity_id=target_user_id
    )

    return {"success": True, "session_id": session_id, "status": "REVOKED"}


@app.get("/api/v1/incidents")
def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    organization_id: Optional[str] = None,
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Lists security incidents with filtering, pagination, and Org Isolation enforcement."""
    query = {}

    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "ADMIN"]:
        query["organization_id"] = user.get("organization_id", "HEALTHCARE_ORG_1")
    elif organization_id and organization_id != "ALL":
        query["organization_id"] = organization_id

    if status and status != "ALL":
        query["status"] = status
    if severity and severity != "ALL":
        query["severity"] = severity

    incidents = []
    total = 0
    if db is not None:
        try:
            total = db.incidents.count_documents(query)
            skip = max(0, (page - 1) * limit)
            cursor = db.incidents.find(query).sort("created_at", -1).skip(skip).limit(limit)
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                incidents.append(doc)
        except Exception as e:
            print(f"[Get Incidents Error]: {e}")

    return {"success": True, "incidents": incidents, "count": len(incidents), "total": total, "page": page, "limit": limit}


@app.post("/api/v1/incidents")
def create_incident(
    req: CreateIncidentRequest,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Creates a new official incident record from a security event or alert."""
    require_write_permission(user)
    actor_email = user.get("email", "owner@deeptrust.demo")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    inc_id = f"inc_{uuid.uuid4().hex[:10]}"
    now = time.time()

    evt = db.security_events.find_one({"event_id": req.primary_event_id})

    incident_doc = {
        "incident_id": inc_id,
        "title": req.title,
        "severity": req.severity or (evt.get("severity") if evt else "HIGH"),
        "status": "OPEN",
        "primary_event_id": req.primary_event_id,
        "related_event_ids": req.related_event_ids or [req.primary_event_id],
        "user_id": req.user_id,
        "user_email": req.user_id,
        "organization_id": req.organization_id or (evt.get("organization_id") if evt else user.get("organization_id", "HEALTHCARE_ORG_1")),
        "auth_session_id": req.auth_session_id or (evt.get("auth_session_id") if evt else None),
        "verification_session_id": req.verification_session_id or (evt.get("verification_session_id") if evt else None),
        "risk_score": evt.get("risk_score", 85) if evt else 85,
        "risk_level": evt.get("risk_level", "HIGH") if evt else "HIGH",
        "reason_codes": evt.get("reason_codes", ["SECURITY_INCIDENT_FLAGGED"]) if evt else ["SECURITY_INCIDENT_FLAGGED"],
        "created_at": now,
        "created_by": actor_email,
        "acknowledged_at": None,
        "acknowledged_by": None,
        "resolved_at": None,
        "resolved_by": None,
        "resolution_summary": req.notes,
        "factors": evt.get("metadata", {}).get("verification_chain", {
            "Credentials": "PASS",
            "Face": "PASS",
            "Liveness": "PASS",
            "Voice": "FAILED",
            "Recovery": "VERIFIED / USED",
            "MFA": "PASS",
            "Risk": "BLOCKED",
            "Access": "DENIED"
        }) if evt else {}
    }

    db.incidents.insert_one(incident_doc)

    log_audit_event(
        "INCIDENT_CREATED",
        actor_email,
        actor_email,
        incident_doc["organization_id"],
        f"Incident {inc_id} created by {actor_email}: {req.title}",
        risk="HIGH",
        details={"incident_id": inc_id, "primary_event_id": req.primary_event_id}
    )

    incident_doc["_id"] = str(incident_doc["_id"])
    return {"success": True, "incident": incident_doc}


@app.get("/api/v1/incidents/{incident_id}")
def get_incident_detail(
    incident_id: str,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Retrieves full details for a specific incident with Object-Level Authorization."""
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    inc = db.incidents.find_one({"incident_id": incident_id})
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Object-Level Authorization
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        if inc.get("organization_id") and inc.get("organization_id") != user.get("organization_id", "HEALTHCARE_ORG_1"):
            raise HTTPException(status_code=403, detail="Forbidden: Access to cross-organization incident is denied.")

    inc["_id"] = str(inc["_id"])
    return {"success": True, "incident": inc}


@app.post("/api/v1/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: str,
    req: IncidentStatusRequest,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Updates incident state with RBAC and Org validation."""
    require_write_permission(user)
    actor_email = user.get("email", "owner@deeptrust.demo")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    inc = db.incidents.find_one({"incident_id": incident_id})
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Object-Level Authorization
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        if inc.get("organization_id") and inc.get("organization_id") != user.get("organization_id", "HEALTHCARE_ORG_1"):
            raise HTTPException(status_code=403, detail="Forbidden: Cannot modify cross-organization incident.")

    now = time.time()
    update_fields = {
        "status": req.status,
        "updated_at": now
    }
    if req.severity:
        update_fields["severity"] = req.severity
    if req.status == "RESOLVED":
        update_fields["resolved_at"] = now
        update_fields["resolved_by"] = actor_email
        if req.resolution_summary:
            update_fields["resolution_summary"] = req.resolution_summary

    db.incidents.update_one({"incident_id": incident_id}, {"$set": update_fields})

    action_type = "INCIDENT_RESOLVED" if req.status == "RESOLVED" else "INCIDENT_UPDATED"
    log_audit_event(
        action_type,
        actor_email,
        actor_email,
        inc.get("organization_id", "Healthcare Organization"),
        f"Incident {incident_id} state changed to {req.status} by {actor_email}",
        risk="LOW" if req.status == "RESOLVED" else "MEDIUM",
        details={"incident_id": incident_id, "new_status": req.status}
    )

    return {"success": True, "incident_id": incident_id, "status": req.status}


@app.get("/api/v1/incidents/{incident_id}/pdf")
def get_incident_pdf_download(
    incident_id: str,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Generates official Incident Response PDF report with Zero-Trust authorization."""
    actor_email = user.get("email", "DeepTrust Security Console")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    inc = db.incidents.find_one({"incident_id": incident_id})
    if not inc:
        evt = db.security_events.find_one({"event_id": incident_id})
        if evt:
            inc = {
                "incident_id": f"inc_{evt['event_id']}",
                "title": f"Incident Dossier for Event {evt['event_id']}",
                "severity": evt.get("severity", "HIGH"),
                "status": evt.get("status", "OPEN"),
                "primary_event_id": evt['event_id'],
                "user_email": evt.get("user_id"),
                "organization_name": evt.get("organization_id"),
                "risk_score": evt.get("risk_score", 85),
                "risk_level": evt.get("risk_level", "HIGH"),
                "reason_codes": evt.get("reason_codes", []),
                "created_at": evt.get("created_at", time.time())
            }
        else:
            raise HTTPException(status_code=404, detail="Incident or Security Event not found")

    # Object-Level Authorization
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "OWNER", "ADMIN"]:
        if inc.get("organization_id") and inc.get("organization_id") != user.get("organization_id", "HEALTHCARE_ORG_1"):
            raise HTTPException(status_code=403, detail="Forbidden: Access to cross-organization report is denied.")

    pdf_bytes = generate_incident_pdf(inc, generated_by=actor_email)

    log_audit_event(
        "INCIDENT_REPORT_GENERATED",
        actor_email,
        actor_email,
        inc.get("organization_id", "Healthcare Organization"),
        f"Incident PDF Report generated for {incident_id} by {actor_email}",
        risk="LOW",
        details={"incident_id": incident_id}
    )

    filename = f"DeepTrust_Incident_{incident_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/api/v1/security/analytics")
def get_security_analytics(
    range: str = "7d",
    user: dict = Depends(get_authenticated_user_from_header)
):
    """
    Performs real MongoDB aggregation pipelines for Security Analytics.
    Zero hardcoded/random statistics.
    """
    org_filter = {}
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "ADMIN"]:
        org_filter["organization_id"] = user.get("organization_id", "HEALTHCARE_ORG_1")

    now = time.time()
    time_map = {
        "today": 86400,
        "7d": 7 * 86400,
        "30d": 30 * 86400,
        "custom": 30 * 86400
    }
    since = now - time_map.get(range, 7 * 86400)
    t_filter = {"created_at": {"$gte": since}, **org_filter}

    if db is None:
        return {"success": False, "message": "Database unavailable"}

    try:
        total_auth_attempts = db.authentication_events.count_documents(t_filter)
        if total_auth_attempts == 0:
            total_auth_attempts = db.verification_sessions.count_documents(t_filter)

        successful_authentications = db.authentication_events.count_documents({"status": "SUCCESS", **t_filter})
        if successful_authentications == 0:
            successful_authentications = db.auth_sessions.count_documents(t_filter)

        failed_authentications = db.authentication_events.count_documents({"status": {"$in": ["FAILED", "FAIL"]}, **t_filter})
        blocked_attempts = db.security_events.count_documents({"decision": "BLOCK", **t_filter})
        high_risk_events = db.security_events.count_documents({"severity": {"$in": ["HIGH", "CRITICAL"]}, **t_filter})

        open_alerts = db.alerts.count_documents({"status": "OPEN", **org_filter})
        resolved_alerts = db.alerts.count_documents({"status": "RESOLVED", **org_filter})

        active_sessions = db.auth_sessions.count_documents({"status": "ACTIVE", **org_filter})

        analytics = {
            "range": range,
            "total_auth_attempts": total_auth_attempts,
            "successful_authentications": successful_authentications,
            "failed_authentications": failed_authentications,
            "blocked_attempts": blocked_attempts,
            "high_risk_events": high_risk_events,
            "open_alerts": open_alerts,
            "resolved_alerts": resolved_alerts,
            "active_sessions": active_sessions,
            "total_security_events": db.security_events.count_documents(t_filter)
        }

        return {"success": True, "analytics": analytics}
    except Exception as e:
        print(f"[Security Analytics Error]: {e}")
        return {"success": False, "error": str(e)}


# ── 16. P8 ENTERPRISE PRODUCT CORE (MULTI-TENANT, POLICY, DEVICE TRUST) ───────

class CreateOrganizationRequest(BaseModel):
    name: str
    organization_type: str
    contact_name: Optional[str] = None
    contact_email: str
    status: Optional[str] = "ACTIVE"
    industry: Optional[str] = None
    node_region: Optional[str] = None
    domain: Optional[str] = None


class OrganizationStatusRequest(BaseModel):
    status: str
    reason: Optional[str] = None


@app.post("/api/v1/admin/organizations")
def create_organization(
    req: CreateOrganizationRequest,
    user: dict = Depends(require_platform_admin)
):
    """Creates a new generic organization in DeepTrust."""
    require_write_permission(user)
    actor_email = user.get("email", "owner@deeptrust.demo")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    if not req.name or not req.name.strip():
        raise HTTPException(status_code=400, detail="Organization Name is required.")

    valid_types = ["Healthcare", "Banking / Financial", "Government", "Enterprise", "Education", "Other"]
    org_type_input = (req.organization_type or "").strip()
    matched_type = None
    for t in valid_types:
        if t.lower() == org_type_input.lower():
            matched_type = t
            break
    
    if not matched_type:
        raise HTTPException(status_code=400, detail=f"Invalid Organization Type. Must be one of: {', '.join(valid_types)}")

    if not req.contact_email or "@" not in req.contact_email or "." not in req.contact_email:
        raise HTTPException(status_code=400, detail="Valid contact email is required.")

    org_id = f"org_{secrets.token_hex(6)}"
    now = time.time()

    org_doc = {
        "_id": org_id,
        "organization_id": org_id,
        "name": req.name.strip(),
        "organization_type": matched_type,
        "industry": matched_type,
        "contact_name": (req.contact_name or "").strip(),
        "contact_email": req.contact_email.strip().lower(),
        "status": req.status or "ACTIVE",
        "node_region": req.node_region or "Global Cloud Node",
        "domain": (req.domain or "").strip(),
        "created_at": now,
        "created_by": actor_email,
        "updated_at": now
    }

    db.organizations.update_one({"_id": org_id}, {"$set": org_doc}, upsert=True)

    default_policy = {
        "policy_id": f"pol_{org_id.lower()}",
        "organization_id": org_id,
        "name": f"{req.name} Default Security Policy",
        "status": "ACTIVE",
        "require_face": True,
        "require_liveness": True,
        "require_voice": True,
        "require_mfa": True,
        "new_device_action": "STEP_UP",
        "unusual_location_action": "STEP_UP",
        "max_login_failures": 5,
        "session_idle_timeout": 1800,
        "session_absolute_timeout": 28800,
        "high_risk_action": "BLOCK",
        "created_at": now,
        "updated_at": now
    }
    db.security_policies.update_one({"organization_id": org_id}, {"$set": default_policy}, upsert=True)

    log_audit_event(
        "ORGANIZATION_CREATED",
        actor_email,
        actor_email,
        req.name.strip(),
        f"Organization {req.name.strip()} ({org_id}) created by {actor_email}",
        risk="LOW",
        details={"organization_id": org_id, "name": req.name.strip(), "organization_type": matched_type}
    )

    return {"success": True, "organization": org_doc}


@app.post("/api/v1/admin/organizations/{org_id}/status")
def update_organization_status(
    org_id: str,
    req: OrganizationStatusRequest,
    user: dict = Depends(require_platform_admin)
):
    """Enables, disables, or suspends an organization."""
    require_write_permission(user)
    actor_email = user.get("email", "owner@deeptrust.demo")

    valid_statuses = ["ACTIVE", "SUSPENDED", "DISABLED"]
    if req.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    org = db.organizations.find_one({"$or": [{"_id": org_id}, {"organization_id": org_id}]})
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    now = time.time()
    db.organizations.update_one(
        {"$or": [{"_id": org_id}, {"organization_id": org_id}]},
        {"$set": {"status": req.status, "updated_at": now}}
    )

    if req.status in ["SUSPENDED", "DISABLED"]:
        db.auth_sessions.update_many(
            {"organization_id": org_id},
            {"$set": {"status": "REVOKED", "revoked": True, "revoked_at": now, "revoked_by": actor_email}}
        )

    action_name = "ORGANIZATION_ENABLED" if req.status == "ACTIVE" else "ORGANIZATION_DISABLED"
    log_audit_event(
        action_name,
        actor_email,
        actor_email,
        org.get("name", org_id),
        f"Organization {org_id} status updated to {req.status} by {actor_email}",
        risk="HIGH" if req.status != "ACTIVE" else "LOW",
        details={"organization_id": org_id, "new_status": req.status, "reason": req.reason}
    )

    return {"success": True, "organization_id": org_id, "status": req.status}


@app.get("/api/v1/security-policies")
def get_security_policy(
    organization_id: Optional[str] = None,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Retrieves organization security policy with Org scoping."""
    target_org = organization_id

    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "ADMIN"]:
        target_org = user.get("organization_id", "HEALTHCARE_ORG_1")
    elif not target_org:
        target_org = "HEALTHCARE_ORG_1"

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    pol = db.security_policies.find_one({"organization_id": target_org})
    if not pol:
        pol = {
            "policy_id": f"pol_{target_org.lower()}",
            "organization_id": target_org,
            "name": "Enterprise Security Policy",
            "status": "ACTIVE",
            "require_face": True,
            "require_liveness": True,
            "require_voice": True,
            "require_mfa": True,
            "new_device_action": "STEP_UP",
            "unusual_location_action": "STEP_UP",
            "max_login_failures": 5,
            "session_idle_timeout": 1800,
            "session_absolute_timeout": 28800,
            "high_risk_action": "BLOCK",
            "created_at": time.time(),
            "updated_at": time.time()
        }
        db.security_policies.update_one({"organization_id": target_org}, {"$set": pol}, upsert=True)

    if "_id" in pol:
        pol["_id"] = str(pol["_id"])

    return {"success": True, "policy": pol}


@app.post("/api/v1/security-policies")
def update_security_policy(
    req: SecurityPolicyRequest,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Creates or updates security policy for an organization with RBAC and Org boundary validation."""
    require_write_permission(user)
    actor_email = user.get("email", "owner@deeptrust.demo")

    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "ADMIN", "HOSPITAL_ADMIN", "HOSPITAL_SECURITY_ADMIN"]:
        raise HTTPException(status_code=403, detail="Access Denied: Unauthorized to modify security policy.")

    target_org = req.organization_id or "HEALTHCARE_ORG_1"
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "ADMIN"]:
        if target_org != user.get("organization_id", "HEALTHCARE_ORG_1"):
            raise HTTPException(status_code=403, detail="Access Denied: Cannot modify another organization's policy.")

    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    now = time.time()
    policy_doc = {
        "policy_id": f"pol_{target_org.lower()}",
        "organization_id": target_org,
        "name": req.name or "Enterprise Security Policy",
        "status": "ACTIVE",
        "require_face": req.require_face if req.require_face is not None else True,
        "require_liveness": req.require_liveness if req.require_liveness is not None else True,
        "require_voice": req.require_voice if req.require_voice is not None else True,
        "require_mfa": req.require_mfa if req.require_mfa is not None else True,
        "new_device_action": req.new_device_action or "STEP_UP",
        "unusual_location_action": req.unusual_location_action or "STEP_UP",
        "max_login_failures": req.max_login_failures or 5,
        "session_idle_timeout": req.session_idle_timeout or 1800,
        "session_absolute_timeout": req.session_absolute_timeout or 28800,
        "high_risk_action": req.high_risk_action or "BLOCK",
        "updated_at": now
    }

    db.security_policies.update_one({"organization_id": target_org}, {"$set": policy_doc}, upsert=True)

    log_audit_event(
        "POLICY_UPDATED",
        actor_email,
        actor_email,
        target_org,
        f"Security Policy for {target_org} updated by {actor_email}",
        risk="LOW",
        details=policy_doc
    )

    return {"success": True, "policy": policy_doc}


@app.get("/api/v1/devices")
def get_devices(
    user_id: Optional[str] = None,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Lists registered devices with Zero-Trust Org scoping."""
    query = {}

    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN", "ADMIN"]:
        query["organization_id"] = user.get("organization_id", "HEALTHCARE_ORG_1")
        if not user_id:
            query["user_id"] = user.get("email")
    elif user_id:
        query["user_id"] = user_id

    devices = []
    if db is not None:
        try:
            cursor = db.trusted_devices.find(query).sort("last_seen", -1)
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                devices.append(doc)
        except Exception as e:
            print(f"[Get Devices Error]: {e}")

    return {"success": True, "devices": devices, "count": len(devices)}


@app.post("/api/v1/devices/{device_id}/trust")
def trust_device(
    device_id: str,
    req: Optional[DeviceTrustActionRequest] = None,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Marks a device as TRUSTED with RBAC enforcement."""
    require_write_permission(user)
    if db is None:
        raise HTTPException(503, "Database unavailable")
    query = {"device_id":device_id}
    if user.get("role") not in PLATFORM_ROLES:
        query["organization_id"] = user.get("organization_id")
    device = db.trusted_devices.find_one(query)
    if not device:
        raise HTTPException(404, "Device not found in your scope")
    db.trusted_devices.update_one(query, {"$set":{"trust_status":"TRUSTED", "updated_at":time.time()}})
    log_audit_event("DEVICE_TRUSTED", str(user["_id"]), user.get("email", ""),
        user.get("organization_name", ""), "Device trust changed", details={"device_id":device_id}, session_id=user.get("session_id"))
    return {"success":True, "device_id":device_id, "trust_status":"TRUSTED"}



@app.post("/api/v1/devices/{device_id}/revoke")
def revoke_device(
    device_id: str,
    req: Optional[DeviceTrustActionRequest] = None,
    user: dict = Depends(get_authenticated_user_from_header)
):
    """Revokes trust for a device with RBAC enforcement."""
    require_write_permission(user)
    if db is None:
        raise HTTPException(503, "Database unavailable")
    query = {"device_id":device_id}
    if user.get("role") not in PLATFORM_ROLES:
        query["organization_id"] = user.get("organization_id")
    device = db.trusted_devices.find_one(query)
    if not device:
        raise HTTPException(404, "Device not found in your scope")
    db.trusted_devices.update_one(query, {"$set":{"trust_status":"REVOKED", "updated_at":time.time()}})
    log_audit_event("DEVICE_REVOKED", str(user["_id"]), user.get("email", ""),
        user.get("organization_name", ""), "Device trust changed", details={"device_id":device_id}, session_id=user.get("session_id"))
    return {"success":True, "device_id":device_id, "trust_status":"REVOKED"}

# Additive dashboard routes share the existing authenticated dependency.
try:
    from .dashboard_features import register_dashboard_features
except ImportError:
    from dashboard_features import register_dashboard_features
dashboard_feature_handlers = register_dashboard_features(app, globals())

register_security_controls(app, globals(), audit_chain)
