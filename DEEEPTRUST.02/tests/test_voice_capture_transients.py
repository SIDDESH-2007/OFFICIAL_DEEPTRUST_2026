"""Capture-boundary regression; never uses or changes stored biometric profiles."""
import sys
import unittest
from pathlib import Path
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server/ai_service'))
from voice_engine import quality, sustained_speech_frames, speaker_matches, VoiceError, SR


class CaptureTransientTests(unittest.TestCase):
    def recording(self):
        y = np.random.default_rng(4).normal(0, .001, 6 * SR).astype(np.float32)
        y[SR:SR + 40000] += .04 * np.sin(np.arange(40000) * .15)
        return y

    def test_startup_click_does_not_change_speech_crop_or_gain(self):
        audio = self.recording()
        reference, expected = quality(audio)
        audio[:1280] += .4  # 80ms startup burst, separated from real speech.
        actual, metrics = quality(audio)
        self.assertEqual(metrics['speech_start_sample'], expected['speech_start_sample'])
        self.assertEqual(metrics['speech_end_sample'], expected['speech_end_sample'])
        # A burst can slightly shift the full-recording DC median. Crop/gain
        # must be stable; don't require an identical irrelevant DC offset.
        np.testing.assert_allclose(actual - actual.mean(), reference - reference.mean(), atol=2e-5)
        self.assertAlmostEqual(float(np.std(actual) / np.std(reference)), 1., places=4)
        self.assertEqual(metrics['ignored_transient_frames'], 4)

    def test_finish_click_does_not_extend_speaker_crop(self):
        audio = self.recording()
        reference, expected = quality(audio)
        audio[-1280:] += .4
        actual, metrics = quality(audio)
        self.assertEqual(metrics['speech_end_sample'], expected['speech_end_sample'])
        np.testing.assert_allclose(actual - actual.mean(), reference - reference.mean(), atol=2e-5)
        self.assertAlmostEqual(float(np.std(actual) / np.std(reference)), 1., places=4)

    def test_short_phonemes_separated_by_brief_gaps_are_retained(self):
        powers = np.ones(100) * 1e-6
        for start in (10, 16, 22, 28):
            powers[start:start + 4] = .01
        keep, ignored = sustained_speech_frames(powers, 1e-6)
        self.assertEqual(keep.sum(), 16)
        self.assertTrue(keep[10] and keep[31])
        self.assertEqual(ignored, 0)

    def test_repeated_isolated_clicks_are_not_clear_speech(self):
        audio = np.random.default_rng(4).normal(0, .001, 6 * SR).astype(np.float32)
        for start in range(0, len(audio) - 1000, 5000):
            audio[start:start + 960] += .2
        with self.assertRaises(VoiceError) as error:
            quality(audio)
        self.assertEqual(error.exception.code, 'NO_CLEAR_SPEECH')
        self.assertTrue(error.exception.retryable)

    def test_all_sustained_regions_kept_including_other_speech(self):
        powers = np.ones(150) * 1e-6
        powers[10:40] = .01
        powers[90:120] = .02
        keep, _ = sustained_speech_frames(powers, 1e-6)
        self.assertEqual(keep.sum(), 60)
        self.assertTrue(keep[10:40].all() and keep[90:120].all())

    def test_identity_and_mixed_speaker_gates_remain_strict(self):
        enrolled = np.eye(1, 256, 0, dtype=np.float32)[0]
        wrong = np.eye(1, 256, 1, dtype=np.float32)[0]
        borderline = .79 * enrolled + np.sqrt(1 - .79 ** 2) * wrong
        for mean, windows in ((wrong, [wrong] * 3),
                              (borderline, [borderline] * 3),
                              (enrolled, [enrolled, wrong, wrong])):
            with self.assertRaises(VoiceError) as error:
                speaker_matches(enrolled, mean, np.asarray(windows))
            self.assertEqual(error.exception.code, 'SPEAKER_MISMATCH')


if __name__ == '__main__':
    unittest.main()
