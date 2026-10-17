"""Local audio quality, speaker embeddings and physical replay countermeasure.

Official Resemblyzer GE2E and ASVspoof 2021 PA LFCC-LCNN checkpoints.
Scores require microphone-specific validation; missing models never pass verification.
"""
import base64
import hashlib
import logging
import os
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace
import numpy as np

VERSION='2026-10-11.voice11'
MODEL_ID='resemblyzer-ge2e-256-v1'
SR=16000

def mel_frames(y):
    """Resemblyzer's 40-band Slaney mel power frontend, without JIT compilation."""
    n_fft=400
    padded=np.pad(np.asarray(y,dtype=np.float32),(n_fft//2,n_fft//2))
    frames=np.lib.stride_tricks.sliding_window_view(padded,n_fft)[::160]
    window=np.hanning(n_fft+1)[:-1]
    power=np.abs(np.fft.rfft(frames*window,axis=1))**2
    # Slaney scale used by the official librosa frontend: linear below 1 kHz.
    logstep=np.log(6.4)/27
    maxmel=15+np.log(8000/1000)/logstep
    mels=np.linspace(0,maxmel,42)
    hz=mels*(200/3)
    above=mels>=15
    hz[above]=1000*np.exp(logstep*(mels[above]-15))
    bins=np.fft.rfftfreq(n_fft,1/SR)
    lower=(bins[None,:]-hz[:-2,None])/(hz[1:-1]-hz[:-2])[:,None]
    upper=(hz[2:,None]-bins[None,:])/(hz[2:]-hz[1:-1])[:,None]
    bank=np.maximum(0,np.minimum(lower,upper))*(2/(hz[2:]-hz[:-2]))[:,None]
    return (power@bank.T).astype(np.float32)

class VoiceError(ValueError):
    def __init__(self,code,message,retryable=False,metrics=None):
        super().__init__(message);self.code=code;self.retryable=retryable
        self.metrics=metrics or {}

def normal_vector(vector,size=256):
    v=np.asarray(vector,dtype=np.float32)
    if v.shape!=(size,) or not np.isfinite(v).all() or np.linalg.norm(v)<1e-6:
        raise VoiceError('INVALID_VOICE_PROFILE','Saved voice profile is invalid. Secure enrollment is required.')
    return v/np.linalg.norm(v)

def sustained_speech_frames(powers, noise):
    """Exclude isolated sub-160ms energy bursts before crop and gain estimation.

    Bridge <=120ms gaps for consonants/brief pauses, retaining their original
    samples. Selection depends only on audio energy, never the enrolled identity.
    This is an energy gate, not speaker or human-speech classification.
    """
    active = powers > max(noise * 3.5, 1e-10)
    indices = np.flatnonzero(active)
    keep = np.zeros_like(active)
    if not len(indices):
        return keep, 0
    groups = np.split(indices, np.flatnonzero(np.diff(indices) > 7) + 1)
    for group in groups:
        if len(group) >= 8:
            keep[group] = True
    return keep, int(np.sum(active & ~keep))

def quality(wave):
    y=np.asarray(wave,dtype=np.float32)
    if y.ndim!=1 or not np.isfinite(y).all() or not 3*SR<=len(y)<=14*SR:
        raise VoiceError('AUDIO_DURATION','Record 3-14 seconds of clear speech.',True)
    if np.mean(np.abs(y)>=.995)>.005:
        raise VoiceError('AUDIO_CLIPPING','Audio is too loud or distorted. Move slightly away from the microphone.',True)
    # Robust frame-level baseline tolerates microphone startup transients and
    # early speech. Relative energy works across microphone gain settings.
    # DC-biased microphones must not make clear speech look like background noise.
    y=y-np.median(y)
    frames=y[:len(y)//320*320].reshape(-1,320)
    powers=np.mean(frames**2,axis=1)
    noise=max(min(float(np.median(powers[:35])),float(np.percentile(powers,20))),1e-12)
    speech,ignored_transient_frames=sustained_speech_frames(powers,noise)
    if np.sum(speech)*.02<1.0:
        raise VoiceError('NO_CLEAR_SPEECH','No clear voice command captured. Check the selected microphone and read the complete command.',True)
    signal=float(np.mean(powers[speech]))
    snr=float(10*np.log10(max(signal-noise,1e-12)/noise))
    if snr<12:
        raise VoiceError('BACKGROUND_TOO_LOUD','Background noise is too loud. Move to a quieter place and retry.',True,{'snr_db':round(snr,1)})
    # Preserve the complete command and its pauses, including early speech.
    active=np.flatnonzero(speech)
    start=max(0,int(active[0]*320)-1600)
    end=min(len(y),int((active[-1]+1)*320)+1600)
    clean=y[start:end]
    rms=np.sqrt(max(signal,1e-12))
    clean=np.asarray(np.clip(clean*(.1/rms),-.99,.99),dtype=np.float32)
    return clean,{'snr_db':round(snr,1),'speech_seconds':round(float(np.sum(speech)*.02),2),'speech_start_sample':start,'speech_end_sample':end,'recording_seconds':round(len(y)/SR,2),'clean_seconds':round(len(clean)/SR,2),'ignored_transient_frames':ignored_transient_frames,'noise_policy':'Sustained energy with robust quiet-frame baseline; low background noise permitted'}

class VoiceEngine:
    def __init__(self,model_dir=None):
        self.directory=Path(model_dir or os.getenv('DEEPTRUST_VOICE_MODEL_DIR') or Path(__file__).parent/'voice_models')
        self.lock=threading.RLock();self.speaker=None;self.replay=None;self.whisper=None

    def decode(self,audio):
        if not isinstance(audio,str) or len(audio)>4*1024*1024+256:
            raise VoiceError('AUDIO_SIZE','Audio upload is missing or too large.',True)
        try:
            raw=base64.b64decode(str(audio).split(',')[-1],validate=True)
        except Exception:raise VoiceError('AUDIO_INVALID','Invalid audio upload.',True)
        if not 1000<=len(raw)<=3*1024*1024:
            raise VoiceError('AUDIO_SIZE','Audio upload is missing or too large.',True)
        # Accept microphone containers, never playlists or external media references.
        supported=(raw.startswith(b'\x1a\x45\xdf\xa3') or raw.startswith(b'OggS')
            or (raw.startswith(b'RIFF') and raw[8:12]==b'WAVE') or raw[4:8]==b'ftyp')
        if not supported:raise VoiceError('AUDIO_INVALID','Unsupported microphone recording format.',True)
        import imageio_ffmpeg
        try:
            decoded=subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(),'-v','error','-protocol_whitelist','pipe','-i','pipe:0','-t','15','-ac','1','-ar',str(SR),'-f','f32le','pipe:1'],
                input=raw,capture_output=True,timeout=15,check=True)
            y=np.frombuffer(decoded.stdout,dtype='<f4').copy()
        except Exception:raise VoiceError('AUDIO_DECODE_FAILED','Could not decode microphone audio. Retry the recording.',True)
        return y,hashlib.sha256(raw).hexdigest(),hashlib.sha256(np.round(y,4).astype('<f4').tobytes()).hexdigest()

    def models(self):
        if self.speaker is not None and self.replay is not None:return
        import torch
        from torch import nn
        try:
            from .voice_models.pa_model import Model
        except ImportError:
            from voice_models.pa_model import Model
        if not (self.directory/'speaker.pt').exists() or not (self.directory/'replay_pa.pt').exists():
            raise VoiceError('VOICE_ENGINE_UNAVAILABLE','Voice security models are unavailable. Contact the administrator.')
        class Encoder(nn.Module):
            def __init__(self):
                super().__init__();self.lstm=nn.LSTM(40,256,3,batch_first=True);self.linear=nn.Linear(256,256)
            def forward(self,x):
                _,(hidden,_)=self.lstm(x);v=torch.relu(self.linear(hidden[-1]));return torch.nn.functional.normalize(v,dim=1)
        try:
            torch.set_num_threads(min(torch.get_num_threads(),4))
            encoder=Encoder()
            state=torch.load(self.directory/'speaker.pt',map_location='cpu',weights_only=True)['model_state']
            state={k:v for k,v in state.items() if k not in {'similarity_weight','similarity_bias'}}
            encoder.load_state_dict(state,strict=True);encoder.eval()
            replay=Model(1,1,SimpleNamespace(),SimpleNamespace(optional_argument=[str(self.directory/'no_protocol')]))
            replay.load_state_dict(torch.load(self.directory/'replay_pa.pt',map_location='cpu',weights_only=True),strict=True);replay.eval()
        except Exception as error:
            raise VoiceError('VOICE_ENGINE_UNAVAILABLE','Voice security model initialization failed.') from error
        self.speaker=encoder;self.replay=replay

    def embeddings(self,y):
        import torch
        mel=mel_frames(y)
        starts=list(range(0,max(1,len(mel)-159),80))
        batches=[np.pad(mel[start:start+160],((0,max(0,160-len(mel[start:start+160]))),(0,0))) for start in starts]
        # Native LSTM avoids a slow oneDNN first-run kernel build on Windows CPUs.
        with torch.inference_mode(), torch.backends.mkldnn.flags(enabled=False):
            vectors=self.speaker(torch.tensor(np.asarray(batches),dtype=torch.float32)).cpu().numpy()
        if not np.isfinite(vectors).all():raise VoiceError('VOICE_ENGINE_UNAVAILABLE','Could not extract speaker identity.')
        return normal_vector(vectors.mean(axis=0)),vectors

    def analyze(self,wave,phrase):
        clean,measurements=quality(wave)
        if not self.lock.acquire(timeout=5):
            raise VoiceError('VOICE_BUSY','Voice service is busy. Retry in a few seconds.',True)
        try:
            self.models()
            import torch
            # Physical-access model uses the original, unfiltered microphone waveform.
            raw=np.asarray(wave[measurements['speech_start_sample']:measurements['speech_end_sample']],dtype=np.float32)
            with torch.inference_mode():score=float(self.replay._compute_embedding(torch.tensor(raw).reshape(1,-1,1),[len(raw)]).item())
            if not np.isfinite(score) or score<float(os.getenv('VOICE_REPLAY_MIN_LOGIT','0')):
                raise VoiceError('REPLAY_SUSPECTED','Recorded or playback-like audio detected. Speak live into the microphone.')
            try:
                if self.whisper is None:
                    import whisper
                    self.whisper=whisper.load_model('base.en',download_root=str(self.directory/'whisper'))
                # Brand vocabulary only: never supply the expected full command to the decoder.
                result=self.whisper.transcribe(clean,fp16=False,language='en',condition_on_previous_text=False,
                    initial_prompt='DeepTrust is the name of the security platform.',temperature=0)
                transcript=result.get('text','')
                if not phrase_matches(transcript,phrase):
                    # Short commands and unfamiliar brand names can lose words in
                    # greedy decoding. Re-decode the same sample with beam search;
                    # keep strict phrase matching and never prompt the answer.
                    padded=np.pad(clean,(SR//4,SR//4))
                    result=self.whisper.transcribe(padded,fp16=False,language='en',
                        condition_on_previous_text=False,
                        initial_prompt='DeepTrust is the name of the security platform.',
                        temperature=0,beam_size=5,patience=1.0)
                    transcript=result.get('text','')
            except Exception as error:
                logging.getLogger(__name__).exception('Voice speech recognition failed; verify the local Whisper model and runtime')
                raise VoiceError('VOICE_ENGINE_UNAVAILABLE','Speech recognition is temporarily unavailable.') from error
            if not phrase_matches(transcript,phrase):
                raise VoiceError('PHRASE_MISMATCH','Voice command was not recognized correctly. Say the complete displayed command in your natural voice.',
                    metrics={**measurements,'replay_logit':round(score,3),'recognized_command':str(transcript).strip()[:120]})
            mean,windows=self.embeddings(clean)
            measurements['speaker_window_count']=len(windows)
        finally:
            self.lock.release()
        return mean,windows,{**measurements,'replay_logit':round(score,3),'model_id':MODEL_ID}

def phrase_matches(actual,expected):
    import re
    def words(text):
        tokens=re.sub(r'[^a-z0-9 ]',' ',str(text).lower()).split()
        tokens=['four' if token=='4' else token for token in tokens]
        if len(tokens)>=2 and tokens[0:2]==['deep','trust']:
            tokens=['deeptrust',*tokens[2:]]
        return tokens
    actual_words,expected_words=words(actual),words(expected)
    # ASR cannot distinguish spoken Four from its homophones. Limit this rule
    # to the final token of the fixed command, preserving every other word.
    if expected_words==['deeptrust','identity','bravo','four'] and len(actual_words)==4:
        if actual_words[-1] in ('for','fore'):
            actual_words[-1]='four'
    return actual_words==expected_words

def speaker_matches(template,mean,windows,threshold=.80):
    baseline=normal_vector(template)
    score=float(np.dot(baseline,normal_vector(mean)))
    values=np.asarray(windows)@baseline
    if not np.isfinite(values).all() or not len(values):raise VoiceError('VOICE_ENGINE_UNAVAILABLE','Speaker measurements are unavailable.')
    dominant=float(np.mean(values>=.72))
    if score<threshold or dominant<.80:
        raise VoiceError('SPEAKER_MISMATCH','Voice does not match your enrolled profile, or another voice is too loud. Speak alone and retry.',
            metrics={'speaker_score':round(score,3),'matching_window_ratio':round(dominant,3),'required_speaker_score':threshold})
    return {'speaker_score':round(score,3),'matching_window_ratio':round(dominant,3)}
