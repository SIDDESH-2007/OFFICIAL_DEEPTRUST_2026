"""
mobile_monitor.py — Terminal QR Code Generator for DeepTrust Mobile Admin Security Monitor
==========================================================================================
Generates a single-use, 5-minute QR pairing session rendered in terminal.
Provides live status updates as the administrator completes pairing and MFA on their phone.
"""

import os
import sys
import time
import socket
import urllib.request
import urllib.error
import json

try:
    import qrcode
except ImportError:
    print("[Error] 'qrcode' module is not installed. Please run: pip install qrcode")
    sys.exit(1)

# Ensure UTF-8 output encoding for Windows terminal QR display
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


def get_lan_ip() -> str:
    """Detect local network IP address of the laptop for phone access."""
    env_host = os.getenv("MOBILE_MONITOR_HOST")
    if env_host:
        return env_host

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def make_post_request(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode('utf-8'))


def make_get_request(url: str) -> dict:
    req = urllib.request.Request(url, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode('utf-8'))


def main():
    backend_url = os.getenv("DEEPTRUST_GATEWAY", "http://localhost:5000")
    frontend_port = int(os.getenv("MOBILE_MONITOR_FRONTEND_PORT", "5000"))
    lan_ip = get_lan_ip()

    print("\n[DeepTrust Mobile Monitor] Initializing secure pairing session...")

    try:
        create_res = make_post_request(f"{backend_url}/api/v1/mobile/pair/create", {
            "lan_host": lan_ip,
            "frontend_port": frontend_port
        })
    except Exception as e:
        print(f"[Error] Failed to connect to DeepTrust server at {backend_url}. Make sure DeepTrust is running!")
        print(f"Details: {e}")
        sys.exit(1)

    raw_token = create_res.get("raw_token")
    pairing_id = create_res.get("pairing_id", "DTM-XXXXXX")

    mobile_pair_url = f"http://{lan_ip}:{frontend_port}/mobile/pair?token={raw_token}"

    os.system('cls' if os.name == 'nt' else 'clear')

    print("============================================================")
    print("                    DEEPTRUST                               ")
    print("             MOBILE ADMIN MONITOR                           ")
    print("============================================================")
    print("\nScan this QR using the authorized DeepTrust Administrator")
    print("mobile device.\n")

    qr = qrcode.QRCode(box_size=1, border=2)
    qr.add_data(mobile_pair_url)
    qr.print_ascii(invert=True)

    print("\n------------------------------------------------------------")
    print(f" Pairing Session:  {pairing_id}")
    print(" Expires in:       5 minutes")
    print(f" Direct Mobile Link: {mobile_pair_url}")
    print(" Status:           WAITING FOR ADMIN VERIFICATION")
    print("============================================================\n")

    print("[DeepTrust Mobile Monitor] Pairing session created.")
    print("Waiting for QR scan...\n")

    last_status = "PENDING"
    while True:
        time.sleep(2)
        try:
            status_res = make_get_request(f"{backend_url}/api/v1/mobile/pair/{raw_token}/status")
            status = status_res.get("status", "PENDING")
            verified_admin = status_res.get("verified_admin_email")

            if status != last_status:
                last_status = status
                if status == "SCANNED":
                    print("[Status Update] Mobile device connected.")
                    print("Waiting for administrator verification...\n")
                elif status == "CREDENTIALS_VERIFIED":
                    print("[Status Update] Administrator credentials verified.")
                    print("Waiting for Google Authenticator TOTP...\n")
                elif status == "CONSUMED":
                    print("============================================================")
                    print(" Administrator MFA verified.")
                    print(" Mobile Monitor authorized successfully.\n")
                    if verified_admin:
                        print(f" Authenticated Admin: {verified_admin}")
                    print(" Session: ACTIVE")
                    print("============================================================\n")
                    break
                elif status in ["EXPIRED", "REVOKED"]:
                    print("\n[Status Update] Pairing Session Expired or Revoked.")
                    print("Please generate a new QR from the DeepTrust Admin system.\n")
                    break

        except urllib.error.HTTPError as e:
            if e.code in [400, 404]:
                print("\n[Status Update] Session expired or invalid.")
                break
        except Exception:
            pass


if __name__ == "__main__":
    main()
