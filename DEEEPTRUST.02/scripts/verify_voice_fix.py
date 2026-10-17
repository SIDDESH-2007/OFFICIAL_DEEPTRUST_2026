import json,time,urllib.request
for attempt in range(30):
    try:
        health=[json.load(urllib.request.urlopen(f'http://localhost:{port}/api/v1/voice/health',timeout=2)) for port in (5000,8000)]
        if all(h.get('voice_security_version')=='2026-10-08.voice5' for h in health):
            print('CONFIRMED: gateway and AI both serve 2026-10-08.voice5. Refresh login with Ctrl+F5.')
            raise SystemExit(0)
    except (OSError,ValueError): pass
    time.sleep(2)
print('NOT UPDATED: running voice backend is still old or unavailable. Check logs/restart_voice_fix.log.')
raise SystemExit(1)
