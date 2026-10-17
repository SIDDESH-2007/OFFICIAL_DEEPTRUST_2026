import urllib.request
import json

def test_account(email, pwd, portal):
    print(f"\n=== Testing Login for {email} ({portal}) ===")
    login_req = urllib.request.Request(
        "http://localhost:5000/api/v1/auth/login",
        data=json.dumps({"email": email, "password": pwd, "selected_access_type": portal}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    res = urllib.request.urlopen(login_req)
    login_data = json.loads(res.read().decode("utf-8"))
    session_id = login_data["session_id"]
    v_token = login_data["verification_token"]
    print(f"1. Logged in -> session_id: {session_id}")

    fin_req = urllib.request.Request(
        "http://localhost:5000/api/v1/auth/finalize",
        data=json.dumps({"session_id": session_id, "verification_token": v_token}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    fin_res = urllib.request.urlopen(fin_req)
    fin_data = json.loads(fin_res.read().decode("utf-8"))
    access_token = fin_data["access_token"]
    print("2. Finalized Auth -> Access Token Issued")

    me_req = urllib.request.Request(
        "http://localhost:5000/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    me_res = urllib.request.urlopen(me_req)
    me_data = json.loads(me_res.read().decode("utf-8"))
    user = me_data["user"]
    print(f"3. /api/v1/auth/me -> Name: {user.get('full_name')} | Role: {user.get('role')} | Org: {user.get('organization_name')}")

if __name__ == "__main__":
    test_account("admin@healthcare.demo", "HealthcareAdmin123!", "HOSPITAL_ADMIN")
    test_account("owner@deeptrust.demo", "OwnerSecret123!", "DEEPTRUST_OWNER")
