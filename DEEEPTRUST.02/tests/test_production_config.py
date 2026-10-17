import sys,unittest,tempfile
from pathlib import Path
from fastapi import HTTPException
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'server/ai_service'))
from production_config import validate_production_config
class ProductionConfigTests(unittest.TestCase):
 def test_local_unmodified(self):validate_production_config({})
 def test_missing_production_dependencies_fail_closed(self):
  with self.assertRaises(RuntimeError):validate_production_config({'NODE_ENV':'production'})
 def test_valid_configuration_and_missing_artifact(self):
  scratch=ROOT/'tests'/'production_test_temp';scratch.mkdir(exist_ok=True)
  with tempfile.TemporaryDirectory(dir=scratch) as tmp:
   p=Path(tmp);(p/'whisper').mkdir()
   for f in ['face_detection_yunet.onnx','face_recognition_sface.onnx','object_detection_nanodet_2022nov.onnx','2.7_80x80_MiniFASNetV2.pth','4_0_0_80x80_MiniFASNetV1SE.pth','passive_pad_manifest.json','speaker.pt','replay_pa.pt','whisper/base.en.pt']:(p/f).touch()
   env={'NODE_ENV':'production','JWT_SECRET':'j'*48,'AUDIT_SIGNING_KEY':'a'*48,'MONGODB_URI':'mongodb+srv://fixture','MONGODB_DATABASE':'fixture','AUDIT_CHECKPOINT_PATH':str(p/'checkpoint.json'),'DEEPTRUST_MODEL_DIR':tmp,'DEEPTRUST_VOICE_MODEL_DIR':tmp,'FASTAPI_CORS_ORIGINS':'https://fixture.vercel.app'}
   validate_production_config(env)
   for patch in [{'ENABLE_DEMO_SEEDING':'true'},{'FASTAPI_CORS_ORIGINS':'*'},{'AUDIT_SIGNING_KEY':'j'*48}]:
    with self.assertRaises(RuntimeError):validate_production_config({**env,**patch})
   (p/'speaker.pt').unlink()
   with self.assertRaises(RuntimeError):validate_production_config(env)
if __name__=='__main__':unittest.main()
