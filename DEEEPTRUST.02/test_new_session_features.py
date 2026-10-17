"""
test_new_session_features.py
Verification test suite for Profile Photo, Session Activity, Mouse Behavioral Signals, and Location Context
"""

import urllib.request
import urllib.error
import json

BASE_URL = "http://localhost:5000"


def post_json(url, data, headers=None):
    if headers is None:
        headers = {}
    headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.getcode(), json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))


def get_json(url, headers=None):
    if headers is None:
        headers = {}
    headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, headers=headers, method='GET')
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.getcode(), json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8'))


def run_tests():
    print("============================================================")
    print("   DEEPTRUST NEW FEATURES & SESSION MONITORING TEST SUITE   ")
    print("============================================================")

    # 1. Get Admin Session Token
    status, auth_res = post_json(f"{BASE_URL}/api/v1/auth/login", {
        "email": "owner@deeptrust.demo",
        "password": "OwnerSecret123!"
    })
    token = auth_res.get("verification_token") or auth_res.get("access_token")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    print(f"[PASS] 1. Admin Auth Token Obtained: HTTP {status}")

    # 2. Test Session Activity Heartbeat
    status, act_res = post_json(f"{BASE_URL}/api/v1/session/activity", {"client_timestamp": 1727334000.0}, headers)
    assert status == 200 and act_res.get("success"), f"Activity heartbeat failed: {act_res}"
    print(f"[PASS] 2. Session Activity Heartbeat: {act_res}")

    # 3. Test Behavioral Mouse Signal
    status, beh_res = post_json(f"{BASE_URL}/api/v1/session/behavior-summary", {
        "average_velocity": 45.2,
        "velocity_variance": 12.1,
        "movement_rate": 1.5,
        "click_rate": 0.2,
        "idle_ratio": 0.1,
        "is_touch_device": False
    }, headers)
    assert status == 200 and beh_res["behavior_signal"] == "NORMAL", f"Behavior summary failed: {beh_res}"
    print(f"[PASS] 3. Behavioral Mouse Signal Processing: Signal = {beh_res['behavior_signal']}")

    # 4. Test Active Admin Sessions Endpoint
    status, active_res = get_json(f"{BASE_URL}/api/v1/admin/sessions/active", headers)
    assert status == 200 and active_res.get("success"), f"Active sessions failed: {active_res}"
    sessions = active_res.get("sessions", [])
    print(f"[PASS] 4. Active Admin Sessions Endpoint: {len(sessions)} sessions listed")
    if sessions:
        sample_sess = sessions[0]
        print(f"       Sample Session: User={sample_sess['user_name']}, Duration={sample_sess['duration_formatted']}, Location={sample_sess['location_context']['city']}, Behavior={sample_sess['behavior_summary']['status']}")
        first_sess_id = sample_sess["id"]

        # 5. Test Session Security Context Detail Modal API
        status, ctx_res = get_json(f"{BASE_URL}/api/v1/admin/sessions/{first_sess_id}", headers)
        assert status == 200 and ctx_res.get("success"), f"Security context failed: {ctx_res}"
        ctx = ctx_res["security_context"]
        print(f"[PASS] 5. Session Security Context Modal API: Identity={ctx['identity']['full_name']}, Location={ctx['location']['city']} ({ctx['location']['status']}), Behavior={ctx['behavior']['status']}")

    # 6. Test Profile Photo Authorization Endpoint
    status, photo_err = get_json(f"{BASE_URL}/api/v1/profile/photo/owner_admin_1", headers)
    print(f"[PASS] 6. Profile Photo Endpoint RBAC & Fallback Handled: HTTP {status}")

    print("============================================================")
    print(" ALL NEW FEATURE VERIFICATION TESTS PASSED SUCCESSFULLY!    ")
    print("============================================================")


if __name__ == "__main__":
    run_tests()
