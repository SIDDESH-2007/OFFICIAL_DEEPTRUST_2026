import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import client from '../api/client';
import LoginForm from '../components/LoginForm';
import SecurityInfo from '../components/SecurityInfo';
import StatsPanel from '../components/StatsPanel';

function getFingerprint() {
  return [navigator.userAgent, navigator.language, navigator.platform, window.screen.width].join('|');
}

export default function Login() {
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [attempts, setAttempts] = useState(Number(localStorage.getItem('deeptrust_attempts') || 0));
  
  // Stages: 1=Credentials, 2=Face, 3=Voice, 4=Security Decision
  const [stage, setStage] = useState(1);
  const [tempToken, setTempToken] = useState(null);
  
  const navigate = useNavigate();

  const handleCredentialSubmit = async (form, emailValid) => {
    if (!emailValid) {
      setMessage('Enter a valid email address domain based on role.');
      return;
    }

    try {
      setLoading(true);
      setMessage('');

      const { data } = await client.post('/auth/login', {
        email: form.email,
        password: form.password,
        role: form.role,
        rememberMe: form.rememberMe,
        deviceFingerprint: getFingerprint(),
      });

      if (data.status === 'pending_verification') {
        setTempToken(data.tempToken);
        setStage(2);
        setAttempts(0);
        localStorage.setItem('deeptrust_attempts', '0');
        return;
      }
    } catch (error) {
      const nextAttempts = attempts + 1;
      setAttempts(nextAttempts);
      localStorage.setItem('deeptrust_attempts', String(nextAttempts));
      setMessage(error.response?.data?.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };
  
  const proceedToVoice = () => {
    setStage(3);
  };
  
  const handleFinalDecision = (finalToken) => {
    localStorage.setItem('deeptrust_token', finalToken);
    navigate('/dashboard');
  };

  return (
    <main className="grid-bg min-h-screen px-4 py-8">
      <div className="mx-auto grid max-w-6xl grid-cols-1 overflow-hidden glass-panel md:grid-cols-5">
        <section className="space-y-4 bg-[#08101E] border-r border-cyan-900/30 p-6 md:col-span-2 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-600 to-blue-600"></div>
          <h1 className="text-3xl font-bold tracking-tight text-white">
            DeepTrust <span className="text-cyan-400">AI</span>
          </h1>
          <p className="text-cyan-200 text-sm font-medium tracking-widest uppercase mb-6">Enterprise Identity & Threat Intelligence</p>
          
          {/* Progress Indicators */}
          <div className="mt-8 space-y-4">
             <div className={`flex items-center gap-3 ${stage >= 1 ? 'text-cyan-400' : 'text-slate-600'}`}>
                <div className={`w-6 h-6 rounded-full flex items-center justify-center border ${stage > 1 ? 'border-emerald-500 bg-emerald-500/20 text-emerald-400' : 'border-cyan-400'}`}>
                  {stage > 1 ? '✓' : '1'}
                </div>
                <span className="font-medium">Credential Verification</span>
             </div>
             
             <div className={`flex items-center gap-3 ${stage >= 2 ? 'text-cyan-400' : 'text-slate-600'}`}>
                <div className={`w-6 h-6 rounded-full flex items-center justify-center border ${stage > 2 ? 'border-emerald-500 bg-emerald-500/20 text-emerald-400' : stage === 2 ? 'border-cyan-400' : 'border-slate-600'}`}>
                  {stage > 2 ? '✓' : '2'}
                </div>
                <span className="font-medium">Face Verification</span>
             </div>
             
             <div className={`flex items-center gap-3 ${stage >= 3 ? 'text-cyan-400' : 'text-slate-600'}`}>
                <div className={`w-6 h-6 rounded-full flex items-center justify-center border ${stage > 3 ? 'border-emerald-500 bg-emerald-500/20 text-emerald-400' : stage === 3 ? 'border-cyan-400' : 'border-slate-600'}`}>
                  {stage > 3 ? '✓' : '3'}
                </div>
                <span className="font-medium">Voice Verification</span>
             </div>
          </div>
          
          <div className="pt-8">
            <SecurityInfo />
          </div>
        </section>

        <section className="p-8 md:col-span-3 flex flex-col justify-center">
          {stage === 1 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-2xl font-semibold text-white">Secure Account Access</h2>
                <p className="text-sm text-slate-400 mt-1">Enter your credentials to access AI forensic dashboard.</p>
              </div>
              {message && <div className="p-3 bg-rose-500/10 border border-rose-500/40 rounded-lg text-sm text-rose-200">{message}</div>}
              <LoginForm onSubmit={handleCredentialSubmit} loading={loading} attempts={attempts} />
            </div>
          )}
          
          {stage === 2 && (
             <div className="space-y-6 text-center">
               <h2 className="text-2xl font-semibold text-white">Stage 2: Real-Time Face Verification</h2>
               <div className="aspect-video bg-black rounded-lg border border-cyan-900/50 flex items-center justify-center relative overflow-hidden">
                  {/* Fake camera stream UI for now, actual implementation later */}
                  <div className="absolute top-2 left-2 flex items-center gap-2 bg-black/50 px-2 py-1 rounded text-xs">
                     <div className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></div>
                     LIVE CAMERA
                  </div>
                  <p className="text-slate-500">Camera initialization...</p>
               </div>
               
               <div className="grid grid-cols-2 gap-4 text-left text-sm">
                 <div className="bg-[#050B14] p-3 rounded-lg border border-cyan-900/30">
                    <p className="text-slate-400">Face Detection</p>
                    <p className="text-emerald-400 font-mono">DETECTED</p>
                 </div>
                 <div className="bg-[#050B14] p-3 rounded-lg border border-cyan-900/30">
                    <p className="text-slate-400">Liveness</p>
                    <p className="text-emerald-400 font-mono">PASSED</p>
                 </div>
               </div>
               
               <button onClick={proceedToVoice} className="btn-primary">
                 Acknowledge Face & Continue
               </button>
             </div>
          )}
          
          {stage === 3 && (
             <div className="space-y-6 text-center">
               <h2 className="text-2xl font-semibold text-white">Stage 3: Voice Verification</h2>
               <div className="p-8 bg-black/50 rounded-lg border border-cyan-900/50">
                  <p className="text-cyan-400 font-mono text-lg select-all">"Verify my identity for DeepTrust AI"</p>
                  <p className="text-sm text-slate-400 mt-4">Please speak the phrase above.</p>
               </div>
               
               <button onClick={() => handleFinalDecision("mock-token-for-now")} className="btn-primary">
                 Complete Authentication
               </button>
             </div>
          )}
        </section>
      </div>
    </main>
  );
}
