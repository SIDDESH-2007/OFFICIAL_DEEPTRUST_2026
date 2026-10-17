import random


def load_model():
    return {"name": "xception-prototype", "version": "0.1"}


def predict_deepfake(model, file_path: str):
    random.seed(file_path)
    deepfake_probability = round(random.uniform(0.1, 0.95), 2)
    authenticity_score = round(1 - deepfake_probability, 2)

    if deepfake_probability >= 0.7:
        risk_level = "HIGH"
    elif deepfake_probability >= 0.4:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
      "authenticity_score": authenticity_score,
      "deepfake_probability": deepfake_probability,
      "risk_level": risk_level,
      "confidence": round(random.uniform(0.8, 0.98), 2),
      "model_version": model["version"],
    }
