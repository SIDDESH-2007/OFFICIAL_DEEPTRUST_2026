"""Confirm the running backend loaded Session Control enhancements."""
import json
import sys
import time
import urllib.request
def main():
    deadline=time.monotonic()+(45 if '--wait' in sys.argv else 0)
    while True:
        try:
            with urllib.request.urlopen('http://127.0.0.1:8000/api/v1/face/health',timeout=3) as response:info=json.load(response)
            if info.get('session_monitor_version')=='2026-10-06.1' and info.get('dashboard_features_version')=='2026-10-06.2' and info.get('security_controls_version')=='2026-10-06.1' and info.get('status')=='ONLINE':
                print('Security controls, dashboard features and session monitoring are loaded; face engines remain ready.')
                return 0
        except Exception: pass
        if time.monotonic()>=deadline:
            print('Updated Session Control backend is not loaded yet. Restart DeepTrust and retry.')
            return 1
        time.sleep(1)
if __name__=='__main__':sys.exit(main())
