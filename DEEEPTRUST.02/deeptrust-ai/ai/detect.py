import hashlib
import os
import random
from typing import Dict


def _seed_from_text(value: str) -> int:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return int(digest[:12], 16)


def analyze_video(video_path: str) -> Dict[str, float]:
    """
    Simulated deepfake analysis entry point.
    This function is intentionally modular so a real TensorFlow/PyTorch model
    can replace this logic without changing route handlers.
    """
    source = f"{video_path}:{os.path.getsize(video_path) if os.path.exists(video_path) else 0}"
    rng = random.Random(_seed_from_text(source))

    deepfake_probability = round(rng.uniform(8.0, 88.0), 2)
    authenticity_score = round(100.0 - deepfake_probability, 2)

    return {
        "deepfake_probability": deepfake_probability,
        "authenticity_score": authenticity_score,
    }


def analyze_media(file_path: str, media_type: str) -> Dict[str, float | str | int]:
    """
    Simulated deepfake detector for image/video/audio uploads.
    Designed as a stable interface for future CNN / transformer model inference.
    """
    source = f"{media_type}:{file_path}:{os.path.getsize(file_path) if os.path.exists(file_path) else 0}"
    rng = random.Random(_seed_from_text(source))

    deepfake_probability = round(rng.uniform(5.0, 96.0), 2)
    authenticity_score = round(100.0 - deepfake_probability, 2)
    confidence = round(rng.uniform(78.0, 98.0), 2)

    if deepfake_probability > 70:
        risk_level = "HIGH"
        status = "deepfake_detected"
    elif deepfake_probability >= 40:
        risk_level = "MEDIUM"
        status = "suspicious"
    else:
        risk_level = "LOW"
        status = "authentic"

    frames_analyzed = 0
    if media_type == "video":
        frames_analyzed = rng.randint(16, 90)

    return {
        "deepfake_probability": deepfake_probability,
        "authenticity_score": authenticity_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "status": status,
        "frames_analyzed": frames_analyzed,
    }


def generate_face_signature(file_path: str) -> str:
    """
    Simulated face embedding/signature generation from image/frame bytes.
    """
    if not os.path.exists(file_path):
        return "no-face-signature"

    with open(file_path, "rb") as file_obj:
        payload = file_obj.read()

    return hashlib.sha256(payload).hexdigest()


def compare_face(stored_signature: str, live_frame: str) -> float:
    """
    Simulated face match score (0-100, higher means better match).
    Accepts stored signature and current live frame path.
    """
    live_signature = generate_face_signature(live_frame)
    merged = f"{stored_signature}:{live_signature}"
    rng = random.Random(_seed_from_text(merged))

    baseline = 92.0 if stored_signature[:8] == live_signature[:8] else 58.0
    jitter = rng.uniform(-22.0, 22.0)
    return round(max(0.0, min(100.0, baseline + jitter)), 2)


def calculate_risk(deepfake_prob: float, face_mismatch: float, device_score: float) -> float:
    """
    Risk formula:
    Risk = (DeepfakeProbability * 0.5) + (FaceMismatch * 0.3) + (DeviceAnomaly * 0.2)
    """
    raw_risk = (deepfake_prob * 0.5) + (face_mismatch * 0.3) + (device_score * 0.2)
    return round(max(0.0, min(100.0, raw_risk)), 2)
