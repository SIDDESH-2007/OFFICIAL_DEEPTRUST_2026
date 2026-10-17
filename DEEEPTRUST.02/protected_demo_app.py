"""
Protected Healthcare Demo App
=============================
Standalone demonstration application for DeepTrust Identity & Access Security Platform Integration.
Runs on port 5050.
"""

import http.server
import socketserver
import json
import urllib.request
import urllib.error
import sys

PORT = 5050
DEEPTRUST_API_URL = "http://127.0.0.1:8000"  # Core FastAPI gateway

CLIENT_ID = "client_demo_healthcare_app_001"
CLIENT_SECRET = "demo_client_secret_99887766554433221100"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Protected Healthcare Demo App - Demo Healthcare Organization</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --accent: #38bdf8;
            --text: #f8fafc;
            --muted: #94a3b8;
            --danger: #ef4444;
            --success: #22c55e;
            --warning: #f59e0b;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg-color);
            color: var(--text);
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }
        .container {
            width: 100%;
            max-width: 640px;
            background: var(--card-bg);
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            border: 1px solid #334155;
        }
        .header {
            border-bottom: 1px solid #334155;
            padding-bottom: 20px;
            margin-bottom: 24px;
        }
        .header h1 {
            margin: 0 0 6px 0;
            font-size: 22px;
            color: var(--accent);
        }
        .header p {
            margin: 0;
            font-size: 14px;
            color: var(--muted);
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            background: #334155;
            color: var(--muted);
            margin-top: 10px;
        }
        .badge.active { background: rgba(34, 197, 94, 0.2); color: var(--success); }
        .badge.blocked { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
        
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-size: 13px;
            color: var(--muted);
        }
        input[type="text"] {
            width: 100%;
            padding: 12px;
            border-radius: 6px;
            border: 1px solid #475569;
            background: #0f172a;
            color: #fff;
            box-sizing: border-box;
            font-family: monospace;
        }
        button {
            width: 100%;
            padding: 14px;
            border-radius: 6px;
            border: none;
            background: var(--accent);
            color: #0f172a;
            font-weight: 700;
            font-size: 15px;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        button:hover { opacity: 0.9; }
        
        .message-box {
            margin-top: 24px;
            padding: 16px;
            border-radius: 8px;
            display: none;
            font-size: 14px;
        }
        .message-box.danger { display: block; background: rgba(239, 68, 68, 0.15); border: 1px solid var(--danger); color: var(--danger); }
        .message-box.warning { display: block; background: rgba(245, 158, 11, 0.15); border: 1px solid var(--warning); color: var(--warning); }
        
        .resource-card {
            margin-top: 24px;
            background: #0f172a;
            border-radius: 8px;
            border: 1px solid var(--success);
            padding: 20px;
            display: none;
        }
        .resource-card h3 {
            margin-top: 0;
            color: var(--success);
        }
        .resource-row {
            margin-bottom: 10px;
            font-size: 14px;
        }
        .resource-row strong { color: var(--muted); display: inline-block; width: 120px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Protected Healthcare Portal</h1>
            <p>Protected Healthcare Demo App — Demo Healthcare Organization</p>
            <div id="status-badge" class="badge">DeepTrust Protection Active</div>
        </div>

        <div class="form-group">
            <label for="session-token">DeepTrust Final Session ID / Token</label>
            <input type="text" id="session-token" placeholder="Paste active DeepTrust session_id (or login via DeepTrust dashboard)">
        </div>

        <button id="btn-access" onclick="requestAccess()">Access Protected Resource</button>

        <div id="message-box" class="message-box"></div>

        <div id="protected-content" class="resource-card">
            <h3>Synthetic Patient Medical Record</h3>
            <div class="resource-row"><strong>Patient:</strong> <span id="patient-name">Demo Patient 001</span></div>
            <div class="resource-row"><strong>Record ID:</strong> <span id="record-id">SYN-90210-ICU</span></div>
            <div class="resource-row"><strong>Vital Signs:</strong> <span id="vitals">BP 120/80 mmHg, HR 72 bpm, SpO2 99%</span></div>
            <div class="resource-row"><strong>Demonstration:</strong> <span id="demo-text">Synthetic healthcare demonstration data. Access authorized by DeepTrust Zero-Trust Policy Engine.</span></div>
        </div>
    </div>

    <script>
        async function requestAccess() {
            const token = document.getElementById('session-token').value.trim();
            const msgBox = document.getElementById('message-box');
            const resCard = document.getElementById('protected-content');
            const badge = document.getElementById('status-badge');

            msgBox.className = 'message-box';
            msgBox.style.display = 'none';
            resCard.style.display = 'none';

            try {
                const res = await fetch('/api/access-resource', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ auth_session_id: token })
                });

                const data = await res.json();

                if (data.success && data.decision === 'ALLOW') {
                    badge.className = 'badge active';
                    badge.innerText = 'ACCESS ALLOWED BY DEEPTRUST';
                    resCard.style.display = 'block';
                } else if (data.decision === 'STEP_UP') {
                    badge.className = 'badge warning';
                    badge.innerText = 'STEP-UP REQUIRED';
                    msgBox.className = 'message-box warning';
                    msgBox.innerText = 'Step-up authentication required by DeepTrust security policy.';
                } else {
                    badge.className = 'badge blocked';
                    badge.innerText = 'ACCESS DENIED';
                    msgBox.className = 'message-box danger';
                    msgBox.innerText = data.message || 'Access denied by DeepTrust security policy.';
                }
            } catch (err) {
                badge.className = 'badge blocked';
                badge.innerText = 'SERVICE UNAVAILABLE';
                msgBox.className = 'message-box danger';
                msgBox.innerText = 'ACCESS UNAVAILABLE / DENIED — DeepTrust Security Gateway Offline';
            }
        }
    </script>
</body>
</html>
"""


class DemoAppHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ["/", "/index.html"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "OK", "app": "Protected Healthcare Demo App"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/access-resource":
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length)
            
            try:
                payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except Exception:
                payload = {}

            session_id = payload.get("auth_session_id", "")

            # Server-to-Server Request to DeepTrust API Gateway
            req_data = json.dumps({
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_session_id": session_id,
                "requested_resource": "medical-record-demo",
                "requested_action": "VIEW"
            }).encode("utf-8")

            try:
                dt_req = urllib.request.Request(
                    f"{DEEPTRUST_API_URL}/api/v1/access/request",
                    data=req_data,
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(dt_req, timeout=4) as response:
                    dt_res = json.loads(response.read().decode("utf-8"))

                if dt_res.get("success") and dt_res.get("decision") == "ALLOW":
                    authz_token = dt_res.get("authorization_token")
                    
                    # Verify Authorization Artifact
                    verify_data = json.dumps({
                        "client_id": CLIENT_ID,
                        "client_secret": CLIENT_SECRET,
                        "authorization_token": authz_token,
                        "requested_resource": "medical-record-demo",
                        "requested_action": "VIEW"
                    }).encode("utf-8")

                    v_req = urllib.request.Request(
                        f"{DEEPTRUST_API_URL}/api/v1/access/verify",
                        data=verify_data,
                        headers={"Content-Type": "application/json"}
                    )
                    with urllib.request.urlopen(v_req, timeout=4) as v_response:
                        v_res = json.loads(v_response.read().decode("utf-8"))

                    if v_res.get("success") and v_res.get("decision") == "ALLOW":
                        out = {
                            "success": True,
                            "decision": "ALLOW",
                            "patient_record": {
                                "patient_id": "Demo Patient 001",
                                "record": "Synthetic healthcare demonstration data.",
                                "authorized_by": "DeepTrust Security Platform"
                            }
                        }
                    else:
                        out = {"success": False, "decision": "BLOCK", "message": "Access denied by DeepTrust security policy."}
                elif dt_res.get("decision") == "STEP_UP":
                    out = {"success": False, "decision": "STEP_UP", "message": "Step-up authentication required by DeepTrust security policy."}
                else:
                    out = {"success": False, "decision": "BLOCK", "message": "Access denied by DeepTrust security policy."}

            except urllib.error.HTTPError as http_err:
                try:
                    err_body = json.loads(http_err.read().decode("utf-8"))
                    dec = err_body.get("decision", "BLOCK")
                    detail = err_body.get("detail", "Access denied by DeepTrust security policy.")
                    out = {"success": False, "decision": dec, "message": detail}
                except Exception:
                    out = {"success": False, "decision": "BLOCK", "message": "Access denied by DeepTrust security policy."}
            except Exception as e:
                # FAIL CLOSED!
                out = {
                    "success": False,
                    "decision": "UNAVAILABLE",
                    "message": "ACCESS UNAVAILABLE / DENIED — DeepTrust Security Gateway Offline"
                }

            self.send_response(200 if out["success"] else 403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(out).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default HTTP logging to stdout for clean test runs


if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", PORT), DemoAppHandler) as httpd:
        print(f"[Protected Healthcare Demo App] Running on http://127.0.0.1:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down Protected Healthcare Demo App.")
            sys.exit(0)
