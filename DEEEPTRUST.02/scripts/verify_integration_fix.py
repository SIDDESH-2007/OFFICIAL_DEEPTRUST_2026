import json,time,urllib.request
for attempt in range(30):
    try:
        health=[json.load(urllib.request.urlopen(f'http://localhost:{port}/api/v1/staff-sso/health',timeout=2)) for port in (5000,8000)]
        face=[json.load(urllib.request.urlopen(f'http://localhost:{port}/api/v1/face/health',timeout=2)) for port in (5000,8000)]
        if all(h.get('version')=='2026-10-08.hospital1' for h in health) and all(h.get('face_setup_version')=='2026-10-08.staff-setup1' for h in face):
            print('CONFIRMED: gateway and AI serve hospital1 + staff-setup1. NovaCare one-time face/voice setup is ready. Reload DeepTrust and restart staff sign-in from localhost:5176.')
            raise SystemExit(0)
    except (OSError,ValueError):pass
    time.sleep(2)
print('NOT UPDATED: one-time setup backend is not loaded. Check logs/restart_integration_fix.log.')
raise SystemExit(1)
