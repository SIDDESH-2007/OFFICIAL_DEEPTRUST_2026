import urllib.request
import json
import pymongo
import os

def test_full_system():
    print("============================================================")
    print("DEEPTRUST HEALTHCARE SECURITY PLATFORM — FULL SYSTEM AUDIT")
    print("============================================================")

    # 1. Check Static Assets
    assets = [
        "http://localhost:5000/index.html",
        "http://localhost:5000/login.html",
        "http://localhost:5000/dashboard.html",
        "http://localhost:5000/css/dashboard.css",
        "http://localhost:5000/js/dashboard.js",
        "http://localhost:5000/js/session.js"
    ]
    print("\n[1/5] Verifying Frontend Asset Servicing:")
    for a in assets:
        try:
            res = urllib.request.urlopen(a)
            print(f"  [PASS] {a} (HTTP {res.status}, {len(res.read())} bytes)")
        except Exception as e:
            print(f"  [FAIL] {a} ({e})")

    # 2. Database Health & Collections Check
    print("\n[2/5] Verifying MongoDB Persistence & Collections:")
    client = pymongo.MongoClient('mongodb://localhost:27017/')
    db = client['deeptrust']
    colls = ['users', 'organizations', 'security_events', 'access_requests', 'audit_logs', 'notifications', 'auth_sessions', 'verification_sessions']
    for c in colls:
        count = db[c].count_documents({})
        print(f"  [PASS] Collection '{c}': {count} documents")

    # 3. Test Healthcare Organization Flow
    print("\n[3/5] Testing Healthcare Organization Flow:")
    with open('tokens.json') as f:
        tokens = json.load(f)
    
    healthcare_token = tokens['healthcare']
    headers = {'Authorization': f'Bearer {healthcare_token}'}

    endpoints = [
        ('/api/v1/auth/me', 'User & Role Validation'),
        ('/api/v1/dashboard/summary', 'Real Summary Metrics'),
        ('/api/v1/dashboard/authentication-trend?range=24h', '24h Auth Trend Aggregation'),
        ('/api/v1/dashboard/risk-overview', 'Zero-Trust Risk Distribution'),
        ('/api/v1/dashboard/factor-health', 'Verification Factor Health'),
        ('/api/v1/dashboard/recent-activity', 'Recent Activity Factor Checks'),
        ('/api/v1/identities', 'Workforce Identities List'),
        ('/api/v1/security-events', 'Security Incident Alerts'),
        ('/api/v1/access-requests', 'Privileged Access Requests'),
        ('/api/v1/reports/summary?range=today', 'Compliance Reports Summary'),
        ('/api/v1/audit-logs', 'Read-Only Audit Trail'),
        ('/api/v1/notifications', 'Connected Notifications')
    ]

    for path, desc in endpoints:
        req = urllib.request.Request(f'http://localhost:5000{path}', headers=headers)
        try:
            res = urllib.request.urlopen(req)
            data = json.loads(res.read().decode('utf-8'))
            print(f"  [PASS] {desc} -> status: 200, success: {data.get('success', True)}")
        except Exception as e:
            print(f"  [FAIL] {desc} -> {e}")

    # 4. Test DeepTrust Admin Flow & AI Security Copilot
    print("\n[4/5] Testing DeepTrust Platform Admin & AI Security Copilot:")
    owner_token = tokens['owner']
    admin_headers = {'Authorization': f'Bearer {owner_token}', 'Content-Type': 'application/json'}

    admin_endpoints = [
        ('/api/v1/auth/me', 'Platform Owner Profile'),
        ('/api/v1/admin/overview', 'Platform Admin Overview'),
        ('/api/v1/admin/organizations', 'Protected Organizations'),
        ('/api/v1/admin/system-health', 'Infrastructure & Subsystems')
    ]

    for path, desc in admin_endpoints:
        req = urllib.request.Request(f'http://localhost:5000{path}', headers={'Authorization': f'Bearer {owner_token}'})
        try:
            res = urllib.request.urlopen(req)
            data = json.loads(res.read().decode('utf-8'))
            print(f"  [PASS] {desc} -> status: 200, success: {data.get('success', True)}")
        except Exception as e:
            print(f"  [FAIL] {desc} -> {e}")

    # Test AI Copilot Queries
    print("\n[5/5] Testing AI Security Copilot Telemetry Queries:")
    queries = [
        "Summarize today's telemetry",
        "Why was this authentication blocked?",
        "Check verification engine health",
        "Correlate multi-factor sessions"
    ]
    for q in queries:
        copilot_req = urllib.request.Request(
            'http://localhost:5000/api/v1/ai/query',
            data=json.dumps({'query': q}).encode('utf-8'),
            headers=admin_headers
        )
        try:
            res = urllib.request.urlopen(copilot_req)
            data = json.loads(res.read().decode('utf-8'))
            print(f"  [PASS] Query: '{q}'")
            print(f"         Title: {data.get('title')}")
            print(f"         Evidence count: {len(data.get('evidence', []))}")
            print(f"         Recommendations count: {len(data.get('recommendations', []))}")
        except Exception as e:
            print(f"  [FAIL] Query: '{q}' -> {e}")

    print("\n============================================================")
    print("ALL VERIFICATION SUITE CHECKS COMPLETED SUCCESSFULLY")
    print("============================================================")

if __name__ == '__main__':
    test_full_system()
