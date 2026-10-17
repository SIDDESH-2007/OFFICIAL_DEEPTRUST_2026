"""Offline regressions. No imports of the production app or writes to MongoDB.

The route functions are extracted from the real source to avoid its startup
seeding side effects. Vision outputs are controlled; these tests do not measure
real camera accuracy or presentation-attack detection rates.
Run: python -m unittest discover -s tests -p test_face_security.py -v
"""
import ast
import base64
import math
from pathlib import Path
import secrets
import sys
from types import SimpleNamespace
import unittest
import uuid

import cv2
import numpy as np
from bson import ObjectId
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'server' / 'ai_service'))
from face_liveness import MotionChallenge, geometry
from passive_pad import PassiveChallenge
from phone_guard import PhoneGuard


class PhoneGuardTests(unittest.TestCase):
    def test_phone_class_returns_normalized_box(self):
        guard = object.__new__(PhoneGuard)
        guard.model = SimpleNamespace(infer=lambda _: np.array([[104, 104, 312, 312, .8, 67]], dtype=float))
        result = guard.detect(np.zeros((416, 416, 3), dtype=np.uint8))
        self.assertEqual(result[0]['bounding_box'], [.25, .25, .5, .5])
        self.assertEqual(result[0]['confidence'], .8)

    def test_other_objects_are_not_called_phones(self):
        guard = object.__new__(PhoneGuard)
        guard.model = SimpleNamespace(infer=lambda _: np.array([[104, 104, 312, 312, .9, 0]], dtype=float))
        self.assertEqual(guard.detect(np.zeros((416, 416, 3), dtype=np.uint8)), [])

    def test_low_confidence_phone_does_not_produce_false_label(self):
        guard = object.__new__(PhoneGuard)
        guard.model = SimpleNamespace(infer=lambda _: np.array([[104, 104, 312, 312, .1, 67]], dtype=float))
        self.assertEqual(guard.detect(np.zeros((416, 416, 3), dtype=np.uint8)), [])


def face(yaw=0, tx=0, ty=0, scale=1, roll=0):
    points = np.array([[100, 100], [200, 100], [150 + yaw * 100, 145],
                       [125 + yaw * 35, 190], [175 + yaw * 35, 190]], dtype=float)
    rotation = np.array([[math.cos(roll), -math.sin(roll)],
                         [math.sin(roll), math.cos(roll)]])
    points = points @ rotation.T * scale + [tx, ty]
    return np.array([40, 40, 250, 250, *points.flatten(), .99], dtype=np.float32)


class MotionTests(unittest.TestCase):
    def test_static_photo_never_passes(self):
        for first in ['TURN_LEFT', 'TURN_RIGHT']:
            motion = MotionChallenge(first, 0)
            for n in range(260):
                result = motion.observe(face(), n * .25)
                self.assertNotEqual(result, 'LIVENESS_PASSED')
            self.assertTrue(motion.failed)

    def test_moving_rotating_scaling_photo_never_passes(self):
        motion = MotionChallenge('TURN_LEFT', 0)
        for n in range(260):
            frame = face(tx=n * 2, ty=n, scale=1 + n * .003, roll=n * .007)
            self.assertNotEqual(motion.observe(frame, n * .25), 'LIVENESS_PASSED')

    def test_geometry_is_invariant_to_photo_movement(self):
        np.testing.assert_allclose(geometry(face()), geometry(face(tx=140, ty=55, scale=1.4, roll=.7)), atol=1e-6)

    def test_both_random_orders_pass_complete_motion(self):
        for first, yaws in [('TURN_LEFT', [0, .22, 0, -.22, 0]),
                            ('TURN_RIGHT', [0, -.22, 0, .22, 0])]:
            motion = MotionChallenge(first, 0)
            now = 0
            for yaw in yaws:
                for _ in range(3):
                    result = motion.observe(face(yaw), now)
                    now += .25
            self.assertEqual(result, 'LIVENESS_PASSED')

    def test_wrong_direction_cannot_advance(self):
        motion = MotionChallenge('TURN_LEFT', 0)
        for n in range(3):
            motion.observe(face(), n * .25)
        for n in range(3, 30):
            self.assertEqual(motion.observe(face(-.25), n * .25), 'IN_PROGRESS')
        self.assertEqual(motion.index, 1)

    def test_failed_challenge_stays_failed(self):
        motion = MotionChallenge('TURN_LEFT', 0)
        self.assertEqual(motion.observe(face(), 61), 'LIVENESS_FAILED')
        self.assertEqual(motion.observe(face(.3), 62), 'LIVENESS_FAILED')

    def test_burst_requests_cannot_satisfy_hold(self):
        motion = MotionChallenge('TURN_LEFT', 0)
        for n in range(100):
            motion.observe(face(), n * .001)
        self.assertEqual(motion.index, 0)

    def test_lost_camera_continuity_fails(self):
        motion = MotionChallenge('TURN_LEFT', 0)
        motion.observe(face(), 0)
        self.assertEqual(motion.observe(face(), 4), 'LIVENESS_FAILED')


def matches(doc, query):
    return all(any(matches(doc, branch) for branch in value) if key == '$or'
               else doc.get(key) == value for key, value in query.items())


class Collection:
    def __init__(self, docs=()):
        self.docs = list(docs)
    def find_one(self, query):
        return next((doc for doc in self.docs if matches(doc, query)), None)
    def update_one(self, query, update, upsert=False):
        doc = self.find_one(query)
        if doc is not None:
            doc.update(update.get('$set', {}))
            return SimpleNamespace(upserted_id=None)
        if upsert:
            self.docs.append(dict(update.get('$setOnInsert', {})))
            return SimpleNamespace(upserted_id='new-profile')
        return SimpleNamespace(upserted_id=None)
    def insert_one(self, doc):
        self.docs.append(doc)


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.clock = SimpleNamespace(time=lambda: self.now)
        self.now = 100.
        self.vector = np.zeros(128, dtype=np.float32)
        self.vector[0] = 1
        self.frame = face()
        self.db = SimpleNamespace(
            verification_sessions=Collection([dict(session_id='s', user_id='alice', email='alice@example.test',
                credential_status='VERIFIED', face_status='VERIFIED', liveness_status='PENDING', expires_at=1000)]),
            face_profiles=Collection([dict(user_id='alice', status='ACTIVE', embedding=self.vector.tolist())]),
            users=Collection(), security_events=Collection())
        detector = SimpleNamespace(setInputSize=lambda _: None, detect=lambda _: (None, self.frames()))
        recognizer = SimpleNamespace(alignCrop=lambda img, f: img, feature=lambda _: self.vector,
            match=lambda a, b, _: float(np.dot(a.flatten(), b.flatten())))
        self.ns = dict(np=np, cv2=cv2, ObjectId=ObjectId, HTTPException=HTTPException, JSONResponse=JSONResponse,
            BaseModel=BaseModel, Optional=Optional, List=List,
            db=self.db, time=self.clock, detector=detector, recognizer=recognizer,
            LIVENESS_SESSIONS={}, FACE_MATCH_REFERENCES={'s': {'user_id': 'alice', 'template': self.vector.copy(), 'feature': self.vector.copy(), 'created_at': 100.}}, MotionChallenge=MotionChallenge, PassiveChallenge=PassiveChallenge,
            passive_pad=SimpleNamespace(predict=lambda *_: {"live_score": .95, "model_scores": [.95,.95]}), secrets=secrets, uuid=uuid,
            check_phone_presentation=lambda *args: None,
            FACE_DETECTION_THRESHOLD=.6,
            log_audit_event=lambda *args, **kw: None,
            decode_image=lambda _: np.full((400, 400, 3), 120, dtype=np.uint8))
        wanted = {'require_face_session', 'face_profile_query', 'normalized_face_template', 'active_face_template', 'face_similarity',
                  'match_face', 'enroll_face', 'create_liveness_challenge', 'verify_liveness'}
        tree = ast.parse((ROOT / 'server/ai_service/face_service.py').read_text(encoding='utf-8'))
        schemas = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name in
                   {'MatchFaceRequest', 'EnrollFaceRequest', 'LivenessChallengeRequest', 'LivenessVerifyRequest'}]
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
        for fn in functions:
            fn.decorator_list = []
        module = ast.Module(body=schemas + functions, type_ignores=[])
        exec(compile(module, 'face_routes_under_test', 'exec'), self.ns)

    def test_sface_input_normalization_cannot_change_identity_reference(self):
        def mutating_match(a, b, metric):
            score = float(np.dot(a.flatten(), b.flatten()))
            a[0, 0] += np.float32(1e-7)
            b[0, 0] += np.float32(1e-7)
            return score
        self.ns['recognizer'].match = mutating_match
        self.call('match_face', user_id='alice', session_id='s', image='frame')
        np.testing.assert_array_equal(self.ns['FACE_MATCH_REFERENCES']['s']['template'], self.vector)
        np.testing.assert_array_equal(self.ns['FACE_MATCH_REFERENCES']['s']['feature'], self.vector)
        self.challenge()
        for _ in range(8):
            self.verify()
            self.now += .25
            np.testing.assert_array_equal(self.ns['LIVENESS_SESSIONS']['s']['template'], self.vector)
            np.testing.assert_array_equal(self.ns['LIVENESS_SESSIONS']['s']['reference'], self.vector)

    def test_pending_setup_template_is_bound_to_authorized_session_identity(self):
        session = self.db.verification_sessions.docs[0]
        session['face_pending_template'] = {'user_id': 'alice', 'status': 'ACTIVE', 'embedding': self.vector.tolist()}
        with self.assertRaises(ValueError):
            self.ns['active_face_template'](session)
        session['face_setup_authorized'] = True
        np.testing.assert_array_equal(self.ns['active_face_template'](session), self.vector)
        session['face_pending_template']['user_id'] = 'other'
        with self.assertRaises(ValueError):
            self.ns['active_face_template'](session)

    def test_challenge_retry_keeps_original_scan_and_deadline(self):
        first = self.challenge()
        entry = self.ns['LIVENESS_SESSIONS']['s']
        self.now += 2
        second = self.challenge()
        self.assertIs(self.ns['LIVENESS_SESSIONS']['s'], entry)
        self.assertEqual(first['timestamp'], second['timestamp'])
        self.assertEqual(entry['motion'].started, 100)

    def test_challenge_retry_cannot_revive_failed_or_expired_scan(self):
        for expired in (False, True):
            self.setUp()
            self.challenge()
            if expired:
                self.now += 31
            else:
                self.ns['LIVENESS_SESSIONS']['s']['motion'].failed = True
            with self.assertRaises(HTTPException):
                self.challenge()
            self.assertNotIn('s', self.ns['LIVENESS_SESSIONS'])

    def test_challenge_retry_rejects_changed_account_or_template(self):
        for change in ('account', 'template'):
            self.setUp()
            self.challenge()
            entry = self.ns['LIVENESS_SESSIONS']['s']
            if change == 'account':
                entry['user_id'] = 'other'
            else:
                entry['template'] = np.roll(self.vector, 1)
            with self.assertRaises(HTTPException):
                self.challenge()

    def frames(self):
        return None if self.frame is None else np.asarray([self.frame]) if self.frame.ndim == 1 else self.frame
    def call(self, name, **kw):
        return self.ns[name](SimpleNamespace(**kw))
    def challenge(self):
        return self.call('create_liveness_challenge', session_id='s', user_id='alice')
    def verify(self):
        result = self.call('verify_liveness', session_id='s', image='frame')
        self.now += .25
        return result
    def session(self):
        return self.db.verification_sessions.docs[0]

    def test_static_photo_is_not_marked_live(self):
        self.ns["passive_pad"] = SimpleNamespace(predict=lambda *_: {"live_score": .05, "model_scores": [.05,.05]})
        self.challenge()
        for _ in range(245):
            self.assertNotEqual(self.verify()['status'], 'LIVENESS_PASSED')
        self.assertEqual(self.session()['liveness_status'], 'FAILED')

    def test_face_swap_during_challenge_fails(self):
        self.challenge()
        self.verify()
        self.vector = np.roll(self.vector, 1)
        self.assertEqual(self.verify()['status'], 'IN_PROGRESS')
        self.assertEqual(self.verify()['status'], 'IN_PROGRESS')
        self.assertEqual(self.verify()['status'], 'LIVENESS_FAILED')
        self.assertEqual(self.session()['face_status'], 'MISMATCH')

    def test_multiple_faces_fail(self):
        self.challenge()
        self.frame = np.asarray([face(), face(tx=300)])
        self.assertEqual(self.verify()['status'], 'LIVENESS_FAILED')

    def test_missing_challenge_cannot_auto_create(self):
        self.assertEqual(self.verify()['status'], 'LIVENESS_REQUIRED')
        self.assertEqual(self.session()['liveness_status'], 'PENDING')

    def test_failure_never_turns_into_pass_on_retry(self):
        self.challenge()
        self.now += 61
        self.assertEqual(self.verify()['status'], 'LIVENESS_FAILED')
        self.assertEqual(self.verify()['status'], 'LIVENESS_FAILED')

    def test_identity_match_requires_liveness_separately(self):
        self.session()['liveness_status'] = 'VERIFIED'
        result = self.call('match_face', session_id='s', user_id='alice@example.test', image='frame')
        self.assertTrue(result['matched'])
        self.assertEqual(self.session()['liveness_status'], 'PENDING')

    def test_other_accounts_face_does_not_match(self):
        self.vector = np.roll(self.vector, 1)
        result = self.call('match_face', session_id='s', user_id='alice', image='frame')
        self.assertFalse(result['matched'])
        self.assertEqual(self.session()['face_status'], 'MISMATCH')

    def test_template_cannot_be_replaced_from_login(self):
        result = self.call('enroll_face', session_id='s', user_id='alice')
        self.assertEqual(result.status_code, 409)
        np.testing.assert_array_equal(self.db.face_profiles.docs[0]['embedding'], self.vector)

    def test_user_session_binding(self):
        with self.assertRaises(HTTPException) as raised:
            self.call('match_face', session_id='s', user_id='bob', image='frame')
        self.assertEqual(raised.exception.status_code, 403)

    def test_expired_session_rejected(self):
        self.session()['expires_at'] = 99
        with self.assertRaises(HTTPException):
            self.challenge()

    def test_database_absent_fails_closed(self):
        self.ns['db'] = None
        with self.assertRaises(HTTPException) as raised:
            self.challenge()
        self.assertEqual(raised.exception.status_code, 503)

    def test_malformed_template_fails_closed(self):
        self.db.face_profiles.docs[0]['embedding'] = [float('nan')] * 128
        result = self.call('match_face', session_id='s', user_id='alice', image='frame')
        self.assertFalse(result['matched'])

    def test_full_sequence_sets_liveness_verified(self):
        self.challenge()
        motion = self.ns['LIVENESS_SESSIONS']['s']['motion']
        for step in motion.steps:
            self.frame = face(.22 if step == 'TURN_LEFT' else -.22 if step == 'TURN_RIGHT' else 0)
            for _ in range(6):
                result = self.verify()
        self.assertEqual(result['status'], 'LIVENESS_PASSED')
        self.assertEqual(self.session()['liveness_status'], 'VERIFIED')

    def test_changed_template_invalidates_challenge(self):
        self.challenge()
        self.db.face_profiles.docs[0]['embedding'] = np.roll(self.vector, 1).tolist()
        self.assertEqual(self.verify()['status'], 'LIVENESS_FAILED')

    def test_phone_blocks_matching_before_identity_acceptance(self):
        self.ns['check_phone_presentation'] = lambda *args: {'status': 'PHONE_DETECTED', 'matched': False, 'message': 'Phone detected'}
        result = self.call('match_face', session_id='s', user_id='alice', image='phone')
        self.assertEqual(result['status'], 'PHONE_DETECTED')
        self.assertFalse(result['matched'])
        self.assertNotEqual(self.session()['face_status'], 'VERIFIED')

    def test_phone_blocks_liveness(self):
        self.challenge()
        self.ns['check_phone_presentation'] = lambda *args: {'status': 'PHONE_DETECTED', 'matched': False, 'message': 'Phone detected'}
        self.assertEqual(self.verify()['status'], 'PHONE_DETECTED')
        self.assertEqual(self.session()['liveness_status'], 'FAILED')

    def test_bad_frame_cannot_advance_and_good_face_recovers(self):
        self.challenge()
        known = self.vector.copy()
        self.vector = np.roll(self.vector, 1)
        self.assertEqual(self.verify()['status'], 'IN_PROGRESS')
        self.assertEqual(self.ns['LIVENESS_SESSIONS']['s']['motion'].index, 0)
        self.vector = known
        self.assertEqual(self.verify()['status'], 'IN_PROGRESS')
        self.assertEqual(self.ns['LIVENESS_SESSIONS']['s']['mismatch_frames'], 0)

    def test_saved_profile_invalid_does_not_request_reenrollment(self):
        self.db.face_profiles.docs[0]['embedding'] = []
        result = self.call('match_face', session_id='s', user_id='alice', image='frame')
        self.assertEqual(result['status'], 'FACE_PROFILE_UNAVAILABLE')

    def test_email_login_uses_existing_objectid_profile(self):
        uid = '6ab71dfa174ac6fd0b256d41'
        self.session()['user_id'] = uid
        self.db.face_profiles.docs[0]['user_id'] = ObjectId(uid)
        result = self.call('match_face', session_id='s', user_id='alice@example.test', image='frame')
        self.assertTrue(result['matched'])

    def test_head_turn_uses_verified_reference_and_returns_to_enrollment(self):
        self.vector = np.zeros(128, dtype=np.float32)
        self.vector[0], self.vector[1] = .6, .8
        self.assertTrue(self.call('match_face', session_id='s', user_id='alice', image='frame')['matched'])
        self.challenge()
        motion = self.ns['LIVENESS_SESSIONS']['s']['motion']
        for step in motion.steps:
            self.vector = np.zeros(128, dtype=np.float32)
            self.vector[0] = .25 if step in ['TURN_LEFT', 'TURN_RIGHT'] else .6
            self.vector[1] = np.sqrt(1 - self.vector[0]**2)
            self.frame = face(.22 if step == 'TURN_LEFT' else -.22 if step == 'TURN_RIGHT' else 0)
            for _ in range(6):
                result = self.verify()
        self.assertEqual(result['status'], 'LIVENESS_PASSED')
        self.assertEqual(self.session()['liveness_status'], 'VERIFIED')

    def test_initial_matched_reference_covers_center_and_return_score_dip(self):
        self.vector = np.zeros(128, dtype=np.float32)
        self.vector[0], self.vector[1] = .49, np.sqrt(1 - .49**2)
        self.assertTrue(self.call('match_face', session_id='s', user_id='alice', image='frame')['matched'])
        self.challenge()
        anchor = self.ns['LIVENESS_SESSIONS']['s']['reference'].copy()
        motion = self.ns['LIVENESS_SESSIONS']['s']['motion']
        # Same live identity remains similar to the proven match frame, even
        # when a fresh comparison against old enrollment drops below 0.38.
        self.vector[0], self.vector[1] = .30, np.sqrt(1 - .30**2)
        for step in motion.steps:
            self.frame = face(.22 if step == 'TURN_LEFT' else -.22 if step == 'TURN_RIGHT' else 0)
            for _ in range(6):
                result = self.verify()
        self.assertEqual(result['status'], 'LIVENESS_PASSED')
        np.testing.assert_array_equal(self.ns['LIVENESS_SESSIONS']['s']['reference'], anchor)

    def test_no_fresh_matched_reference_cannot_start_liveness(self):
        self.ns['FACE_MATCH_REFERENCES'].clear()
        with self.assertRaises(HTTPException):
            self.challenge()

    def test_cached_reference_is_bound_to_the_account(self):
        self.ns['FACE_MATCH_REFERENCES']['s']['user_id'] = 'bob'
        with self.assertRaises(HTTPException):
            self.challenge()

    def test_borderline_frames_do_not_pass_or_claim_wrong_face(self):
        self.challenge()
        self.vector = np.zeros(128, dtype=np.float32)
        self.vector[0], self.vector[1] = .30, np.sqrt(1 - .30**2)
        for _ in range(10):
            result = self.verify()
            self.assertEqual(result['status'], 'IN_PROGRESS')
            self.assertNotIn('Wrong face', result['message'])
        self.assertEqual(self.ns['LIVENESS_SESSIONS']['s']['motion'].index, 0)
        self.assertNotEqual(self.session()['liveness_status'], 'VERIFIED')

    def test_detected_face_confidence_is_consistent_in_liveness(self):
        self.challenge()
        motion = self.ns['LIVENESS_SESSIONS']['s']['motion']
        for step in motion.steps:
            self.frame = face(.22 if step == 'TURN_LEFT' else -.22 if step == 'TURN_RIGHT' else 0)
            self.frame[-1] = .7  # Accepted by YuNet at the configured .6 threshold.
            for _ in range(6):
                result = self.verify()
        self.assertEqual(result['status'], 'LIVENESS_PASSED')

    def test_no_face_frames_keep_capture_heartbeat_without_passing(self):
        self.challenge()
        self.frame = None
        for _ in range(20):
            self.assertEqual(self.verify()['status'], 'IN_PROGRESS')
        self.assertFalse(self.ns['LIVENESS_SESSIONS']['s']['motion'].failed)
        self.assertEqual(self.ns['LIVENESS_SESSIONS']['s']['motion'].index, 0)
        self.assertNotEqual(self.session()['liveness_status'], 'VERIFIED')

    def test_request_model_missing_session_is_rejected(self):
        req = self.ns['MatchFaceRequest'](user_id='alice', image='frame')
        with self.assertRaises(HTTPException) as raised:
            self.ns['match_face'](req)
        self.assertEqual(raised.exception.status_code, 400)

    def test_client_liveness_flag_cannot_overwrite_face(self):
        req = self.ns['EnrollFaceRequest'](user_id='alice', session_id='s', image='frame', liveness_verified=True)
        response = self.ns['enroll_face'](req)
        self.assertEqual(response.status_code, 409)

    def test_request_models_static_photo_cannot_pass(self):
        self.ns["passive_pad"] = SimpleNamespace(predict=lambda *_: {"live_score": .05, "model_scores": [.05,.05]})
        response = self.ns['create_liveness_challenge'](self.ns['LivenessChallengeRequest'](session_id='s'))
        self.assertEqual(response['challenge'], 'PASSIVE_FACE_SCAN')
        for _ in range(245):
            response = self.ns['verify_liveness'](self.ns['LivenessVerifyRequest'](session_id='s', image='frame'))
            self.assertNotEqual(response['status'], 'LIVENESS_PASSED')
            self.now += .25
        self.assertEqual(self.session()['liveness_status'], 'FAILED')

    def test_legacy_unenrolled_template_is_rejected(self):
        self.db.face_profiles.docs[0].pop('status')
        result = self.call('match_face', session_id='s', user_id='alice', image='frame')
        self.assertFalse(result['matched'])


if __name__ == '__main__':
    unittest.main()
