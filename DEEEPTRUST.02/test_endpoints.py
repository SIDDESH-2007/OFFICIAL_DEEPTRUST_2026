import urllib.request
import json
import sys

endpoints = [
    'http://localhost:5000/api/v1/health',
    'http://localhost:5000/api/v1/dashboard/summary',
    'http://localhost:5000/api/v1/admin/overview',
    'http://localhost:5000/api/v1/admin/organizations',
    'http://localhost:5000/api/v1/admin/identity-security',
    'http://localhost:5000/api/v1/security-events',
    'http://localhost:5000/api/v1/admin/risk-evaluations',
    'http://localhost:5000/api/v1/admin/system-health',
    'http://localhost:5000/api/v1/audit-logs',
    'http://localhost:5000/api/v1/admin/integrations',
    'http://localhost:5000/api/v1/notifications/unread-count'
]

all_pass = True
for ep in endpoints:
    try:
        req = urllib.request.Request(ep)
        res = urllib.request.urlopen(req, timeout=3)
        data = json.loads(res.read().decode())
        print(f"PASS: {ep} -> success={data.get('success', True)}")
    except Exception as e:
        print(f"FAIL: {ep} -> {e}")
        all_pass = False

# Test AI Copilot endpoint
try:
    ai_req = urllib.request.Request(
        'http://localhost:5000/api/v1/ai/query',
        data=json.dumps({"query": "Summarize today's authentication activity"}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    ai_res = urllib.request.urlopen(ai_req, timeout=3)
    ai_data = json.loads(ai_res.read().decode())
    print(f"PASS: http://localhost:5000/api/v1/ai/query -> title={ai_data.get('title')}")
except Exception as e:
    print(f"FAIL: AI Query -> {e}")
    all_pass = False

sys.exit(0 if all_pass else 1)
