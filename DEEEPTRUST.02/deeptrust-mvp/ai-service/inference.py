from model import load_model, predict_deepfake

model = load_model()


def run_inference(file_path: str):
    return predict_deepfake(model, file_path)
