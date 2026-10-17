from flask import Flask, request, jsonify
from inference import run_inference
from face_engine import FaceVerificationEngine

app = Flask(__name__)
face_engine = FaceVerificationEngine()

@app.get('/health')
def health():
    return jsonify({"ok": True, "service": "ai-service"})

@app.post('/analyze')
def analyze():
    payload = request.get_json(silent=True) or {}
    file_path = payload.get('file_path')
    if not file_path:
        return jsonify({"ok": False, "message": "file_path required"}), 400
    result = run_inference(file_path)
    return jsonify({"ok": True, **result})

@app.post('/face/verify')
def face_verify():
    if 'frame' not in request.files:
        return jsonify({"ok": False, "message": "No frame provided"}), 400
        
    frame_file = request.files['frame']
    frame_bytes = frame_file.read()
    
    analysis = face_engine.analyze_frame(frame_bytes)
    
    return jsonify({"ok": True, "analysis": analysis})

@app.post('/voice/verify')
def voice_verify():
    # Stubbed voice verification for now
    return jsonify({"ok": True, "status": "VOICE_VERIFIED"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7000, debug=True)
