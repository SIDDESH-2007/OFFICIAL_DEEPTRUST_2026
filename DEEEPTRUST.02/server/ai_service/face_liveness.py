"""Active motion checks for YuNet's five landmarks.

This is a challenge policy, not a trained presentation-attack detector.
It rejects static/translated/scaled/rotated photos, but needs camera evaluation
and a dedicated PAD model to measure resistance to video/projective replay.
"""
import math


def geometry(face):
    """Express nose and mouth positions in an eye-relative coordinate frame."""
    points = [(float(face[i]), float(face[i + 1])) for i in range(4, 14, 2)]
    if not all(math.isfinite(v) for p in points for v in p):
        raise ValueError("Invalid landmarks")
    eye1, eye2, nose, mouth1, mouth2 = points
    dx, dy = eye2[0] - eye1[0], eye2[1] - eye1[1]
    span = math.hypot(dx, dy)
    if span < 12:
        raise ValueError("Face is too small")
    center = ((eye1[0] + eye2[0]) / 2, (eye1[1] + eye2[1]) / 2)
    mouth = ((mouth1[0] + mouth2[0]) / 2, (mouth1[1] + mouth2[1]) / 2)
    def project(point):
        x, y = point[0] - center[0], point[1] - center[1]
        return ((x * dx + y * dy) / span**2,
                (-x * dy + y * dx) / span**2)
    nx, ny = project(nose)
    mx, my = project(mouth)
    return (nx, nx - mx, ny, my)


INSTRUCTIONS = {
    "CENTER": "Look straight at the camera and hold still briefly",
    "TURN_LEFT": "Turn your head to your left, keep both eyes visible, and hold until the instruction changes",
    "TURN_RIGHT": "Turn your head to your right, keep both eyes visible, and hold until the instruction changes",
    "RETURN": "Return to looking straight at the camera and hold briefly",
}


class MotionChallenge:
    def __init__(self, first_turn, now):
        other = "TURN_RIGHT" if first_turn == "TURN_LEFT" else "TURN_LEFT"
        self.steps = ["CENTER", first_turn, "RETURN", other, "RETURN"]
        self.started = now
        self.last_frame = None
        self.index = 0
        self.baseline = None
        self.samples = []
        self.hold_started = None
        self.passed = False
        self.failed = False
        self.failure_reason = None
        self.pose_valid = False
        self.turn_shift = None
        self.turn_relief = None

    @property
    def instruction(self):
        return INSTRUCTIONS[self.steps[min(self.index, len(self.steps) - 1)]]

    def observe(self, face, now):
        if self.failed:
            return "LIVENESS_FAILED"
        if now - self.started > 60:
            self.failed = True
            self.failure_reason = "CHALLENGE_TIMEOUT"
            return "LIVENESS_FAILED"
        if self.passed:
            return "LIVENESS_PASSED"
        if self.last_frame is not None:
            if now - self.last_frame < 0.12:
                return "IN_PROGRESS"
            if now - self.last_frame > 3:
                self.failure_reason = "CAMERA_INTERRUPTED"
                self.failed = True
                return "LIVENESS_FAILED"
        self.last_frame = now
        self.pose_valid = False
        if face is None:
            self.samples = []
            self.hold_started = None
            return "IN_PROGRESS"
        try:
            value = geometry(face)
        except ValueError:
            self.samples = []
            self.hold_started = None
            return "IN_PROGRESS"
        step = self.steps[self.index]
        if step == "CENTER":
            valid = abs(value[0]) < 0.18 and abs(value[1]) < 0.15
            if self.samples:
                valid = valid and max(abs(a - b) for a, b in zip(value, self.samples[0])) < 0.05
        else:
            shift = value[0] - self.baseline[0]
            relief = value[1] - self.baseline[1]
            self.turn_shift = shift
            self.turn_relief = relief
            if step == "RETURN":
                valid = abs(shift) < 0.06 and abs(relief) < 0.05
            else:
                # Unmirrored camera coordinates: the user's left moves right.
                direction = 1 if step == "TURN_LEFT" else -1
                valid = direction * shift > 0.13 and direction * relief > 0.06
            valid = valid and abs(value[2] - self.baseline[2]) < 0.20 and abs(value[3] - self.baseline[3]) < 0.25
        self.pose_valid = bool(valid)
        if not valid:
            self.samples = []
            self.hold_started = None
            return "IN_PROGRESS"
        if self.hold_started is None:
            self.hold_started = now
        self.samples.append(value)
        if len(self.samples) < 3 or now - self.hold_started < 0.4:
            return "IN_PROGRESS"
        if self.baseline is None:
            self.baseline = tuple(sum(v[j] for v in self.samples) / len(self.samples) for j in range(4))
        self.samples = []
        self.hold_started = None
        self.index += 1
        if self.index == len(self.steps):
            self.passed = True
            return "LIVENESS_PASSED"
        return "IN_PROGRESS"
