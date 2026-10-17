"""Passive PAD using pinned upstream MiniFASNet weights (Apache-2.0).
No head-turn prompts. Model scores require physical camera validation.
"""
from pathlib import Path
import hashlib
import json
import numpy as np
import torch
try:
    from .minifasnet import MiniFASNetV2, MiniFASNetV1SE
    from .pad_crop import CropImage
except ImportError:
    from minifasnet import MiniFASNetV2, MiniFASNetV1SE
    from pad_crop import CropImage

class PassivePAD:
    def __init__(self, model_dir):
        folder=Path(model_dir)
        manifest=json.loads((folder/'passive_pad_manifest.json').read_text())
        self.models=[]
        # CPU inference on small crops; avoid oversubscribing the face engine.
        torch.set_num_threads(2)
        for filename, scale, factory in [
            ('2.7_80x80_MiniFASNetV2.pth',2.7,MiniFASNetV2),
            ('4_0_0_80x80_MiniFASNetV1SE.pth',4.0,MiniFASNetV1SE)]:
            path=folder/filename
            if hashlib.sha256(path.read_bytes()).hexdigest()!=manifest['files']['models/'+filename]:
                raise ValueError('PAD model checksum mismatch')
            model=factory(conv6_kernel=(5,5))
            state=torch.load(path,map_location='cpu',weights_only=True)
            state={k.removeprefix('module.'):v for k,v in state.items()}
            model.load_state_dict(state)
            self.models.append((scale,model.eval()))
        self.cropper=CropImage()

    def predict(self, frame, face):
        scores=[]
        with torch.inference_mode():
            for scale,model in self.models:
                patch=self.cropper.crop(frame,[float(x) for x in face[:4]],scale,80,80)
                # Upstream uses BGR CHW float values 0..255 (no /255).
                tensor=torch.from_numpy(np.ascontiguousarray(patch.transpose(2,0,1))).float().unsqueeze(0)
                prob=torch.softmax(model(tensor),dim=1).numpy()[0]
                if prob.shape!=(3,) or not np.isfinite(prob).all():
                    raise ValueError('Invalid PAD output')
                scores.append(float(prob[1]))
        return {'live_score':sum(scores)/len(scores),'model_scores':scores}

class PassiveChallenge:
    def __init__(self, first_turn, now):
        self.started=now;self.last_frame=None;self.index=0
        self.steps=['STRAIGHT_FACE'];self.samples=[];self.hold_started=None
        self.passed=False;self.failed=False;self.failure_reason=None
        self.spoof_frames=0;self.spoof_started=None
    @property
    def instruction(self): return 'Look straight at the camera. Keep your face visible while we verify it.'
    def observe(self, face, now, pad=None):
        if self.failed: return 'LIVENESS_FAILED'
        if now-self.started>30:
            self.failed=True;self.failure_reason='CHALLENGE_TIMEOUT';return 'LIVENESS_FAILED'
        if self.last_frame is not None:
            if now-self.last_frame<.12: return 'IN_PROGRESS'
            if now-self.last_frame>3:
                self.samples=[];self.hold_started=None
        self.last_frame=now
        valid=face is not None and pad is not None and pad['live_score']>=.8 and min(pad['model_scores'])>=.5
        if not valid:
            self.samples=[];self.hold_started=None;self.passed=False
            if pad is not None and pad['live_score']<.2:
                self.spoof_frames+=1
                if self.spoof_started is None:self.spoof_started=now
                if self.spoof_frames>=3 and now-self.spoof_started>=.5:
                    self.failed=True;self.failure_reason='SPOOF_DETECTED';return 'LIVENESS_FAILED'
            else:self.spoof_frames=0;self.spoof_started=None
            return 'IN_PROGRESS'
        self.spoof_frames=0;self.spoof_started=None
        if self.hold_started is None:self.hold_started=now
        self.samples.append(pad['live_score'])
        if len(self.samples)>=5 and now-self.hold_started>=1.2:
            self.passed=True;return 'LIVENESS_PASSED'
        return 'IN_PROGRESS'
