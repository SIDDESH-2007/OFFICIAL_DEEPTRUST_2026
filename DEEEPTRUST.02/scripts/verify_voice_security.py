import json,time,urllib.request,sys
deadline=time.time()+60
while time.time()<deadline:
    try:
        data=json.load(urllib.request.urlopen('http://localhost:8000/api/v1/voice/health',timeout=3))
        if data.get('voice_security_version')=='2026-10-07.voice2':
            print('New secure voice pipeline loaded. Models are lazily probed on first recording.')
            sys.exit(0)
    except Exception:pass
    time.sleep(2)
print('Voice backend update not loaded. Restart the DeepTrust backend and retry.')
sys.exit(1)
