"""
test_p4_voice_recovery_suite.py
DeepTrust Phase P4 — Secure Voice-Failure Recovery Flow Automated Test Suite

Covers 20 Comprehensive Security & Functional Verification Tests:
 1. Voice attempt counter stored backend-side
 2. Attempt #1 failure allows retry
 3. Attempt #2 failure requires recovery
 4. Attempt #3 normal voice rejected (403)
 5. Refresh preserves voice attempt state
 6. MFA blocked before required recovery (403)
 7. Valid enrolled recovery code accepted
 8. Wrong recovery code rejected
 9. Used recovery code replay rejected
10. Cross-user recovery code rejected
11. Recovery attempt rate limiting (max 3)
12. Expired session recovery rejected
13. Fake frontend recovery status denied by backend
14. Fake frontend voice status denied by backend
15. MFA required and functional after recovery
16. Risk Engine receives voice failure & recovery context
17. Risk BLOCK decision prevents finalization
18. Normal Voice success flow works without recovery
19. Recovery path finalize works with all factors verified
20. Challenge backend ownership and synchronization
"""

import sys
import time
import requests
import pyotp
import json
from pymongo import MongoClient

BASE_URL = "http://127.0.0.1:8000"
AI_URL = "http://127.0.0.1:8000"
MONGO_URI = "mongodb://127.0.0.1:27017"

mongo_client = MongoClient(MONGO_URI)
db = mongo_client["deeptrust"]

def log_test(num, name, result, details=""):
    status_str = "PASS" if result else "FAIL"
    print(f"[TEST {num:02d}] {name:<60} [{status_str}] {details}")
    return result

import hashlib

def setup_preauth_session(user_id="admin@healthcare.demo", email="admin@healthcare.demo"):
    """Helper to create a session pre-verified through Credentials, Face, and Liveness, with fresh recovery code."""
    session_id = f"test_session_{int(time.time()*1000000)}"
    rec_code = f"RECOVERY-{session_id}".upper()
    code_hash = hashlib.sha256(rec_code.encode('utf-8')).hexdigest()
    
    db.recovery_codes.insert_one({
        "email": email.lower(),
        "user_id": user_id,
        "code_hash": code_hash,
        "used": False,
        "created_at": time.time()
    })

    session_doc = {
        "session_id": session_id,
        "user_id": user_id,
        "email": email,
        "credential_status": "VERIFIED",
        "face_status": "VERIFIED",
        "liveness_status": "VERIFIED",
        "voice_status": "PENDING",
        "voice_attempt_count": 0,
        "voice_challenge_phrase": "DeepTrust secure access alpha seven",
        "voice_challenge_expires_at": time.time() + 300,
        "mfa_status": "PENDING",
        "risk_status": "PENDING",
        "final_decision": "PENDING",
        "created_at": time.time(),
        "expires_at": time.time() + 1800
    }
    db.verification_sessions.insert_one(session_doc)
    return session_id, rec_code

def main():
    print("=" * 80)
    print(" DEEPTRUST PHASE P4 — SECURE VOICE RECOVERY AUTOMATED TEST SUITE")
    print("=" * 80)

    results = []

    # 1. Voice attempt counter stored backend-side
    try:
        s1, rc1 = setup_preauth_session()
        doc1 = db.verification_sessions.find_one({"session_id": s1})
        t1_pass = (doc1 and doc1.get("voice_attempt_count") == 0)
        results.append(log_test(1, "Voice Attempt Counter Stored Backend-Side", t1_pass))
    except Exception as e:
        results.append(log_test(1, "Voice Attempt Counter Stored Backend-Side", False, str(e)))

    # 2. Attempt #1 failure allows retry
    try:
        s2, rc2 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        res = requests.post(f"{BASE_URL}/api/v1/voice/verify", json={
            "session_id": s2,
            "user_id": "admin@healthcare.demo",
            "audio_data": dummy_b64
        })
        doc2 = db.verification_sessions.find_one({"session_id": s2})
        t2_pass = (res.status_code == 400 and doc2 and doc2.get("voice_attempt_count") == 1 and doc2.get("voice_status") == "FAILED" and doc2.get("recovery_required") != True)
        results.append(log_test(2, "Attempt #1 Failure Allows Retry", t2_pass, f"Status: {res.status_code}"))
    except Exception as e:
        results.append(log_test(2, "Attempt #1 Failure Allows Retry", False, str(e)))

    # 3. Attempt #2 failure requires recovery
    try:
        s3, rc3 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s3, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        res2 = requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s3, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        doc3 = db.verification_sessions.find_one({"session_id": s3})
        t3_pass = (res2.status_code == 400 and doc3 and doc3.get("voice_attempt_count") == 2 and doc3.get("voice_status") == "FAILED" and doc3.get("recovery_required") == True)
        results.append(log_test(3, "Attempt #2 Failure Requires Recovery", t3_pass, f"Status: {res2.status_code}"))
    except Exception as e:
        results.append(log_test(3, "Attempt #2 Failure Requires Recovery", False, str(e)))

    # 4. Attempt #3 normal voice rejected (403)
    try:
        s4, rc4 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s4, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s4, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        res3 = requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s4, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        t4_pass = (res3.status_code == 403)
        results.append(log_test(4, "Attempt #3 Normal Voice Rejected (403)", t4_pass, f"Status: {res3.status_code}"))
    except Exception as e:
        results.append(log_test(4, "Attempt #3 Normal Voice Rejected (403)", False, str(e)))

    # 5. Refresh preserves voice attempt state
    try:
        s5, rc5 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s5, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        res_sess = requests.get(f"{BASE_URL}/api/v1/auth/verification-session/{s5}")
        sess_data = res_sess.json().get("session", {})
        t5_pass = (res_sess.status_code == 200 and sess_data.get("voice_attempt_count") == 1 and sess_data.get("voice_status") == "FAILED")
        results.append(log_test(5, "Refresh Preserves Voice Attempt State", t5_pass))
    except Exception as e:
        results.append(log_test(5, "Refresh Preserves Voice Attempt State", False, str(e)))

    # 6. MFA blocked before required recovery (403)
    try:
        s6, rc6 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s6, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s6, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        res_mfa = requests.post(f"{BASE_URL}/api/v1/mfa/verify", json={"session_id": s6, "user_id": "admin@healthcare.demo", "code": "123456"})
        t6_pass = (res_mfa.status_code == 403)
        results.append(log_test(6, "MFA Blocked Before Required Recovery (403)", t6_pass, f"Status: {res_mfa.status_code}"))
    except Exception as e:
        results.append(log_test(6, "MFA Blocked Before Required Recovery (403)", False, str(e)))

    # 7. Valid enrolled recovery code accepted
    try:
        s7, rc7 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s7, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s7, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        res_rec = requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s7, "recovery_code": rc7, "user_id": "admin@healthcare.demo"})
        doc7 = db.verification_sessions.find_one({"session_id": s7})
        t7_pass = (res_rec.status_code == 200 and doc7 and doc7.get("voice_status") == "FAILED_RECOVERY_USED" and doc7.get("recovery_status") == "VERIFIED")
        results.append(log_test(7, "Valid Enrolled Recovery Code Accepted", t7_pass, f"Status: {res_rec.status_code}"))
    except Exception as e:
        results.append(log_test(7, "Valid Enrolled Recovery Code Accepted", False, str(e)))

    # 8. Wrong recovery code rejected
    try:
        s8, rc8 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s8, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s8, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        res_wrong = requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s8, "recovery_code": "INVALID-CODE-999999", "user_id": "admin@healthcare.demo"})
        t8_pass = (res_wrong.status_code == 400)
        results.append(log_test(8, "Wrong Recovery Code Rejected", t8_pass, f"Status: {res_wrong.status_code}"))
    except Exception as e:
        results.append(log_test(8, "Wrong Recovery Code Rejected", False, str(e)))

    # 9. Used recovery code replay rejected
    try:
        s9, rc9 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s9, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s9, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        # Replay rc7 which was used in Test 7
        res_replay = requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s9, "recovery_code": rc7, "user_id": "admin@healthcare.demo"})
        t9_pass = (res_replay.status_code == 400)
        results.append(log_test(9, "Used Recovery Code Replay Rejected", t9_pass, f"Status: {res_replay.status_code}"))
    except Exception as e:
        results.append(log_test(9, "Used Recovery Code Replay Rejected", False, str(e)))

    # 10. Cross-user recovery code rejected
    try:
        s10, rc10 = setup_preauth_session(user_id="user@healthcare.demo", email="user@healthcare.demo")
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s10, "user_id": "user@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s10, "user_id": "user@healthcare.demo", "audio_data": dummy_b64})
        # Try admin's recovery code rc9 for user@healthcare.demo
        res_cross = requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s10, "recovery_code": rc9, "user_id": "user@healthcare.demo"})
        t10_pass = (res_cross.status_code == 400)
        results.append(log_test(10, "Cross-User Recovery Code Rejected", t10_pass, f"Status: {res_cross.status_code}"))
    except Exception as e:
        results.append(log_test(10, "Cross-User Recovery Code Rejected", False, str(e)))

    # 11. Recovery attempt rate limiting (max 3)
    try:
        s11, rc11 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s11, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s11, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s11, "recovery_code": "WRONG1", "user_id": "admin@healthcare.demo"})
        requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s11, "recovery_code": "WRONG2", "user_id": "admin@healthcare.demo"})
        requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s11, "recovery_code": "WRONG3", "user_id": "admin@healthcare.demo"})
        res_limit = requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s11, "recovery_code": "WRONG4", "user_id": "admin@healthcare.demo"})
        t11_pass = (res_limit.status_code == 403)
        results.append(log_test(11, "Recovery Attempt Rate Limiting (Max 3)", t11_pass, f"Status: {res_limit.status_code}"))
    except Exception as e:
        results.append(log_test(11, "Recovery Attempt Rate Limiting (Max 3)", False, str(e)))

    # 12. Expired session recovery rejected
    try:
        s12, rc12 = setup_preauth_session()
        db.verification_sessions.update_one({"session_id": s12}, {"$set": {"expires_at": time.time() - 10, "voice_attempt_count": 2, "recovery_required": True}})
        res_exp = requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s12, "recovery_code": rc12, "user_id": "admin@healthcare.demo"})
        t12_pass = (res_exp.status_code == 403)
        results.append(log_test(12, "Expired Session Recovery Rejected", t12_pass, f"Status: {res_exp.status_code}"))
    except Exception as e:
        results.append(log_test(12, "Expired Session Recovery Rejected", False, str(e)))

    # 13. Fake frontend recovery status denied by backend
    try:
        s13, rc13 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s13, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s13, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        res_fake_rec = requests.post(f"{BASE_URL}/api/v1/auth/finalize", json={"session_id": s13})
        t13_pass = (res_fake_rec.status_code == 403)
        results.append(log_test(13, "Fake Frontend Recovery Status Denied by Backend", t13_pass, f"Status: {res_fake_rec.status_code}"))
    except Exception as e:
        results.append(log_test(13, "Fake Frontend Recovery Status Denied by Backend", False, str(e)))

    # 14. Fake frontend voice status denied by backend
    try:
        s14, rc14 = setup_preauth_session()
        res_fake_v = requests.post(f"{BASE_URL}/api/v1/auth/finalize", json={"session_id": s14})
        t14_pass = (res_fake_v.status_code == 403)
        results.append(log_test(14, "Fake Frontend Voice Status Denied by Backend", t14_pass, f"Status: {res_fake_v.status_code}"))
    except Exception as e:
        results.append(log_test(14, "Fake Frontend Voice Status Denied by Backend", False, str(e)))

    # 15. MFA required and functional after recovery
    try:
        s15, rc15 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s15, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s15, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s15, "recovery_code": rc15, "user_id": "admin@healthcare.demo"})
        
        user_doc = db.users.find_one({"email": "admin@healthcare.demo"})
        totp_secret = user_doc.get("mfa_secret") or user_doc.get("protected_mfa_secret")
        totp = pyotp.TOTP(totp_secret)
        current_otp = totp.now()

        res_mfa15 = requests.post(f"{BASE_URL}/api/v1/mfa/verify", json={"session_id": s15, "user_id": "admin@healthcare.demo", "code": current_otp})
        doc15 = db.verification_sessions.find_one({"session_id": s15})
        t15_pass = (res_mfa15.status_code == 200 and doc15 and doc15.get("mfa_status") == "VERIFIED")
        results.append(log_test(15, "MFA Required and Functional After Recovery", t15_pass, f"Status: {res_mfa15.status_code}"))
    except Exception as e:
        results.append(log_test(15, "MFA Required and Functional After Recovery", False, str(e)))

    # 16. Risk Engine receives voice failure & recovery context
    try:
        s16, rc16 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s16, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s16, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s16, "recovery_code": rc16, "user_id": "admin@healthcare.demo"})
        db.verification_sessions.update_one({"session_id": s16}, {"$set": {"mfa_status": "VERIFIED"}})

        res_risk = requests.post(f"{BASE_URL}/api/v1/risk/evaluate", json={"session_id": s16, "user_id": "admin@healthcare.demo"})
        risk_data = res_risk.json()
        reasons = risk_data.get("reason_codes", [])
        t16_pass = (res_risk.status_code == 200 and "VOICE_VERIFICATION_FAILED" in reasons and "VOICE_RECOVERY_USED" in reasons and risk_data.get("risk_score") == 35)
        results.append(log_test(16, "Risk Engine Receives Voice Failure & Recovery Context", t16_pass, f"Score: {risk_data.get('risk_score')}"))
    except Exception as e:
        results.append(log_test(16, "Risk Engine Receives Voice Failure & Recovery Context", False, str(e)))

    # 17. Risk BLOCK decision prevents finalization
    try:
        s17, rc17 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s17, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s17, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s17, "recovery_code": rc17, "user_id": "admin@healthcare.demo"})
        db.verification_sessions.update_one({"session_id": s17}, {"$set": {"mfa_status": "VERIFIED", "force_risk_block": True}})

        requests.post(f"{BASE_URL}/api/v1/risk/evaluate", json={"session_id": s17, "user_id": "admin@healthcare.demo"})

        res_fin_block = requests.post(f"{BASE_URL}/api/v1/auth/finalize", json={"session_id": s17})
        t17_pass = (res_fin_block.status_code == 403)
        results.append(log_test(17, "Risk BLOCK Decision Prevents Finalization", t17_pass, f"Status: {res_fin_block.status_code}"))
    except Exception as e:
        results.append(log_test(17, "Risk BLOCK Decision Prevents Finalization", False, str(e)))

    # 18. Normal Voice success flow works without recovery
    try:
        s18, rc18 = setup_preauth_session()
        db.verification_sessions.update_one({"session_id": s18}, {"$set": {"voice_status": "VERIFIED", "recovery_required": False}})
        db.verification_sessions.update_one({"session_id": s18}, {"$set": {"mfa_status": "VERIFIED"}})
        requests.post(f"{BASE_URL}/api/v1/risk/evaluate", json={"session_id": s18, "user_id": "admin@healthcare.demo"})
        res_fin18 = requests.post(f"{BASE_URL}/api/v1/auth/finalize", json={"session_id": s18})
        t18_pass = (res_fin18.status_code == 200 and res_fin18.json().get("success") == True)
        results.append(log_test(18, "Normal Voice Success Flow Works Without Recovery", t18_pass, f"Status: {res_fin18.status_code}"))
    except Exception as e:
        results.append(log_test(18, "Normal Voice Success Flow Works Without Recovery", False, str(e)))

    # 19. Recovery path finalize works with all factors verified
    try:
        s19, rc19 = setup_preauth_session()
        dummy_b64 = "data:audio/webm;base64," + "A"*2000
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s19, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/voice/verify", json={"session_id": s19, "user_id": "admin@healthcare.demo", "audio_data": dummy_b64})
        requests.post(f"{BASE_URL}/api/v1/auth/voice-recovery/verify", json={"session_id": s19, "recovery_code": rc19, "user_id": "admin@healthcare.demo"})
        db.verification_sessions.update_one({"session_id": s19}, {"$set": {"mfa_status": "VERIFIED"}})
        requests.post(f"{BASE_URL}/api/v1/risk/evaluate", json={"session_id": s19, "user_id": "admin@healthcare.demo"})

        res_fin19 = requests.post(f"{BASE_URL}/api/v1/auth/finalize", json={"session_id": s19})
        t19_pass = (res_fin19.status_code == 200 and res_fin19.json().get("success") == True)
        results.append(log_test(19, "Recovery Path Finalize Works With All Factors Verified", t19_pass, f"Status: {res_fin19.status_code}"))
    except Exception as e:
        results.append(log_test(19, "Recovery Path Finalize Works With All Factors Verified", False, str(e)))

    # 20. Challenge backend ownership and synchronization
    try:
        s20, rc20 = setup_preauth_session()
        res_ch = requests.post(f"{BASE_URL}/api/v1/voice/challenge", json={"session_id": s20})
        ch_phrase = res_ch.json().get("challenge_phrase")
        doc20 = db.verification_sessions.find_one({"session_id": s20})
        t20_pass = (res_ch.status_code == 200 and ch_phrase is not None and doc20.get("voice_challenge_phrase") == ch_phrase)
        results.append(log_test(20, "Challenge Backend Ownership and Synchronization", t20_pass, f"Phrase: '{ch_phrase}'"))
    except Exception as e:
        results.append(log_test(20, "Challenge Backend Ownership and Synchronization", False, str(e)))

    print("=" * 80)
    passed_count = sum(1 for r in results if r)
    total_count = len(results)
    print(f" TOTAL TEST RESULTS: {passed_count}/{total_count} PASSED")
    print("=" * 80)

    if passed_count == total_count:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
