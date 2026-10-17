"""Confirm both the AI engine and the public gateway serve the corrected face pipeline."""
import json
import sys
import time
import urllib.error
import urllib.request

EXPECTED = "2026-10-06.7"
ROOTS = ("http://127.0.0.1:8000", "http://127.0.0.1:5000")


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=3) as response:
        return json.load(response)


def main():
    deadline = time.monotonic() + (60 if "--wait" in sys.argv else 0)
    last_error = None
    while True:
        try:
            for root in ROOTS:
                info = fetch_json(root + "/api/v1/face/health")
                if info.get("face_pipeline_version") != EXPECTED:
                    raise RuntimeError(f"{root} still serves the old face backend: {info}")
                if info.get("status") != "ONLINE" or info.get("phone_detector") != "OpenCV NanoDet" or info.get("passive_pad") != "MiniFASNet ensemble":
                    raise RuntimeError(f"{root} face models are not ready: {info}")
            voice = fetch_json(ROOTS[1] + "/api/v1/voice/health")
            if not voice:
                raise RuntimeError("Voice health endpoint returned no data")
            print(f"Confirmed: AI and gateway both serve face pipeline {EXPECTED}; voice endpoint responds.")
            return 0
        except (OSError, urllib.error.HTTPError, ValueError, RuntimeError) as error:
            last_error = error
        if time.monotonic() >= deadline:
            print("DeepTrust restart did not load the corrected backend:", last_error)
            return 1
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
