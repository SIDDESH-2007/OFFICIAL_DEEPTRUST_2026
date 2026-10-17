import cv2
import numpy as np

class FaceVerificationEngine:
    def __init__(self):
        # Using Haar Cascade for simplicity and speed in MVP
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        self.eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
    
    def analyze_frame(self, frame_bytes):
        """
        Analyze a single frame for faces and basic liveness signals.
        Takes raw image bytes (e.g. from a POST request).
        """
        np_arr = np.frombuffer(frame_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if img is None:
            return {"error": "Invalid image data"}
            
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Detect faces
        faces = self.face_cascade.detectMultiScale(gray, 1.3, 5)
        
        if len(faces) == 0:
            return {"status": "NO_FACE_DETECTED", "faces": 0}
            
        if len(faces) > 1:
            return {"status": "MULTIPLE_FACES_DETECTED", "faces": len(faces)}
            
        # Single face detected
        (x, y, w, h) = faces[0]
        roi_gray = gray[y:y+h, x:x+w]
        
        # Look for eyes as a basic liveness/structure check
        eyes = self.eye_cascade.detectMultiScale(roi_gray)
        has_eyes = len(eyes) >= 1
        
        return {
            "status": "FACE_DETECTED",
            "faces": 1,
            "bounding_box": [int(x), int(y), int(w), int(h)],
            "liveness_signals": {
                "eyes_detected": has_eyes
            }
        }
