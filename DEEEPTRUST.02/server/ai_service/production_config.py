"""Validate production configuration without changing enrolments or secrets."""
from pathlib import Path
from urllib.parse import urlsplit

def validate_production_config(env):
    if env.get('NODE_ENV') != 'production': return
    errors=[]
    for key in ('MONGODB_URI','MONGODB_DATABASE','AUDIT_CHECKPOINT_PATH','DEEPTRUST_MODEL_DIR','DEEPTRUST_VOICE_MODEL_DIR'):
        if not env.get(key):errors.append(key+' is required')
    secret=env.get('JWT_SECRET','');audit=env.get('AUDIT_SIGNING_KEY','')
    if len(secret)<32:errors.append('JWT_SECRET must contain at least 32 characters')
    if len(audit)<32 or audit==secret:errors.append('Set a separate AUDIT_SIGNING_KEY of at least 32 characters')
    if env.get('ENABLE_DEMO_SEEDING','').lower()=='true':errors.append('Demo seeding is forbidden in production')
    origins=[o.strip() for o in env.get('FASTAPI_CORS_ORIGINS','').split(',') if o.strip()]
    if not origins or any(urlsplit(o).scheme!='https' or not urlsplit(o).netloc or urlsplit(o).path or urlsplit(o).query or urlsplit(o).fragment for o in origins):
        errors.append('FASTAPI_CORS_ORIGINS must contain exact HTTPS origins')
    model=Path(env.get('DEEPTRUST_MODEL_DIR',''))
    voice=Path(env.get('DEEPTRUST_VOICE_MODEL_DIR',''))
    for file in ('face_detection_yunet.onnx','face_recognition_sface.onnx','object_detection_nanodet_2022nov.onnx','2.7_80x80_MiniFASNetV2.pth','4_0_0_80x80_MiniFASNetV1SE.pth','passive_pad_manifest.json'):
        if not (model/file).is_file():errors.append('Required face model artifact missing: '+file)
    for file in ('speaker.pt','replay_pa.pt','whisper/base.en.pt'):
        if not (voice/file).is_file():errors.append('Required voice model artifact missing: '+file)
    if errors:raise RuntimeError('Production configuration rejected: '+'; '.join(errors))
