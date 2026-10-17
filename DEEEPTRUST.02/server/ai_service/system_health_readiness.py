"""Read-only service readiness checks. No account or biometric database writes."""
import time


def voice_readiness(engine):
    cached = getattr(engine, '_system_health_readiness', None)
    if cached and time.monotonic() - cached[0] < 30:
        return dict(cached[1])
    if not engine.lock.acquire(timeout=1):
        return {'status': 'Busy', 'mode': 'Voice verification is processing; refresh shortly.'}
    try:
        # Strict checkpoint loading checks architecture and runtime compatibility.
        # Reuse the existing instance; never inspect or alter enrolled profiles.
        engine.models()
        if engine.whisper is None:
            if not (engine.directory / 'whisper' / 'base.en.pt').is_file():
                raise RuntimeError('Local speech checkpoint missing')
            import whisper
            engine.whisper = whisper.load_model('base.en', device='cpu',
                download_root=str(engine.directory / 'whisper'))
        if any(model is None for model in (engine.speaker, engine.replay, engine.whisper)):
            raise RuntimeError('Voice model initialization incomplete')
        result = {'status': 'Operational',
            'mode': 'Speaker, replay and speech models loaded; live identity verification runs at sign-in.',
            'probe': 'MODEL_READINESS', 'checked_at': time.time()}
    except Exception:
        result = {'status': 'Unavailable',
            'mode': 'Voice model readiness check failed. Check the voice runtime and model files.',
            'probe': 'MODEL_READINESS', 'checked_at': time.time()}
    finally:
        engine.lock.release()
    engine._system_health_readiness = (time.monotonic(), result)
    return dict(result)


def mfa_readiness():
    try:
        import pyotp
        # Public RFC 6238 test fixture, not an enrolled account's secret/code.
        totp = pyotp.TOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', digits=8)
        if totp.at(59) != '94287082' or not totp.verify('94287082', for_time=59):
            raise RuntimeError('TOTP known-answer check failed')
        if totp.verify('00000000', for_time=59):
            raise RuntimeError('TOTP rejected-code check failed')
        return {'status': 'Operational', 'standard': 'RFC 6238 TOTP',
            'mode': 'TOTP reference self-check passed; enrolled accounts unchanged.',
            'probe': 'RFC6238_SELF_CHECK', 'checked_at': time.time()}
    except Exception:
        return {'status': 'Unavailable', 'standard': 'RFC 6238 TOTP',
            'mode': 'TOTP self-check failed. Check the Authenticator runtime.',
            'probe': 'RFC6238_SELF_CHECK', 'checked_at': time.time()}
