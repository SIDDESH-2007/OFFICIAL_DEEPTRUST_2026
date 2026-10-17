import React from 'react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import client from '../api/client';

export default function FaceAuth() {
  const [status, setStatus] = useState('Start face verification to continue');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleComplete = async () => {
    const email = sessionStorage.getItem('deeptrust_pending_email');
    const deviceFingerprint = sessionStorage.getItem('deeptrust_pending_fp');
    if (!email) {
      setStatus('No pending authentication. Return to login.');
      return;
    }

    try {
      setLoading(true);
      const { data } = await client.post('/auth/face-auth', {
        email,
        deviceFingerprint,
      });

      localStorage.setItem('deeptrust_token', data.token);
      localStorage.setItem('deeptrust_user_name', data.user.fullName);
      localStorage.setItem('deeptrust_user_role', data.user.role);
      navigate('/dashboard');
    } catch (error) {
      setStatus(error.response?.data?.message || 'Face verification failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="grid-bg flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-xl rounded-2xl border border-cyan-500/30 bg-slate-900/80 p-6">
        <h1 className="text-2xl font-bold">Face Authentication</h1>
        <p className="mt-2 text-sm text-slate-300">Risk score exceeded threshold. Additional verification required.</p>

        <div className="mt-4 rounded-lg border border-slate-700 bg-slate-950/70 p-8 text-center text-slate-400">
          Webcam placeholder for MVP
        </div>

        <button
          className="mt-4 w-full rounded-lg bg-cyan-500 py-2 font-semibold text-slate-950 disabled:opacity-50"
          onClick={handleComplete}
          disabled={loading}
        >
          {loading ? 'Verifying...' : 'Complete Face Verification'}
        </button>
        <p className="mt-3 text-sm text-amber-300">{status}</p>
      </div>
    </main>
  );
}
