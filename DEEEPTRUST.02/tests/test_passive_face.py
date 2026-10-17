"""Offline policy tests: real route extraction, fake vision scores; no live DB."""
import ast
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server/ai_service'))
from passive_pad import PassiveChallenge

LIVE={'live_score':.95,'model_scores':[.95,.95]}
class PassiveTests(unittest.TestCase):
    def test_straight_live_face_passes_without_turns(self):
        c=PassiveChallenge(None,0)
        for n in range(6):status=c.observe([1],n*.25,LIVE)
        self.assertEqual(status,'LIVENESS_PASSED')
        self.assertEqual(c.steps,['STRAIGHT_FACE'])
    def test_missing_pad_or_face_never_passes(self):
        for face,score in [(None,LIVE),([1],None)]:
            c=PassiveChallenge(None,0)
            for n in range(30):self.assertNotEqual(c.observe(face,n*.25,score),'LIVENESS_PASSED')
    def test_screen_scores_are_rejected_and_failure_sticks(self):
        c=PassiveChallenge(None,0)
        for n in range(3):status=c.observe([1],n*.25,{'live_score':.05,'model_scores':[.05,.05]})
        self.assertEqual(status,'LIVENESS_FAILED')
        self.assertEqual(c.observe([1],1,LIVE),'LIVENESS_FAILED')
    def test_borderline_or_disagreeing_models_cannot_pass(self):
        for pad in [{'live_score':.6,'model_scores':[.6,.6]},{'live_score':.8,'model_scores':[.99,.4]}]:
            c=PassiveChallenge(None,0)
            for n in range(20):self.assertNotEqual(c.observe([1],n*.25,pad),'LIVENESS_PASSED')
    def test_request_burst_cannot_pass(self):
        c=PassiveChallenge(None,0)
        for n in range(100):self.assertNotEqual(c.observe([1],n*.001,LIVE),'LIVENESS_PASSED')
    def test_tracking_gap_resets_live_hold(self):
        c=PassiveChallenge(None,0)
        for n in range(4):c.observe([1],n*.25,LIVE)
        self.assertEqual(c.observe([1],5,LIVE),'IN_PROGRESS')
        self.assertEqual(len(c.samples),1)

class PhoneTemporalTests(unittest.TestCase):
    def setUp(self):
        tree=ast.parse((ROOT/'server/ai_service/face_service.py').read_text(encoding='utf-8'))
        node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='check_phone_presentation')
        self.now=0;self.phones=[{'confidence':.9,'bounding_box':[.2,.2,.3,.5]}]
        self.ns={'phone_guard':SimpleNamespace(detect=lambda _:self.phones),'time':SimpleNamespace(time=lambda:self.now),'PHONE_OBSERVATIONS':{}}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<phone helper>','exec'),self.ns)
    def check(self,sid='a'):return self.ns['check_phone_presentation'](None,sid)
    def test_single_false_detection_is_not_reported_as_phone(self):
        self.assertIsNone(self.check());self.now=.25;self.phones=[];self.assertIsNone(self.check())
    def test_repeated_phone_is_reported(self):
        self.assertIsNone(self.check());self.now=.25;self.assertIsNone(self.check());self.now=.5
        self.assertEqual(self.check()['status'],'PHONE_DETECTED')
    def test_burst_and_different_sessions_cannot_confirm_phone(self):
        self.check()
        for n in range(20):self.now=n*.001;self.assertIsNone(self.check())
        self.now=.5;self.assertIsNone(self.check('b'))

if __name__=='__main__':unittest.main()
