"""Phone object detection using the official OpenCV Zoo NanoDet model.

This detects visible phones, not every presentation attack. Preserve NanoDet's
Apache-2.0 license beside its vendored inference implementation.
"""
from pathlib import Path
import cv2
import numpy as np

try:
    from .nanodet import NanoDet
except ImportError:
    from nanodet import NanoDet


class PhoneGuard:
    def __init__(self, model_path):
        self.model = NanoDet(str(model_path), prob_threshold=.35)

    def detect(self, frame):
        h, w = frame.shape[:2]
        scale = min(416 / w, 416 / h)
        nw, nh = max(1, int(w * scale)), max(1, int(h * scale))
        left, top = (416 - nw) // 2, (416 - nh) // 2
        image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        image = cv2.resize(image, (nw, nh), interpolation=cv2.INTER_AREA)
        image = cv2.copyMakeBorder(image, top, 416 - nh - top, left, 416 - nw - left, cv2.BORDER_CONSTANT, value=0)
        rows = self.model.infer(image)
        phones = []
        for row in rows:
            if int(row[5]) != 67 or float(row[4]) < .65:
                continue
            box = np.array([(row[0] - left) / nw, (row[1] - top) / nh,
                            (row[2] - left) / nw, (row[3] - top) / nh])
            x1, y1, x2, y2 = np.clip(box, 0, 1).tolist()
            if x2 <= x1 or y2 <= y1:
                continue
            phones.append({'confidence': round(float(row[4]), 3), 'bounding_box': [x1, y1, x2 - x1, y2 - y1]})
        return phones


def load_phone_guard(model_dir):
    path = Path(model_dir) / 'object_detection_nanodet_2022nov.onnx'
    return PhoneGuard(path) if path.is_file() else None
