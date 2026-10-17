import React, { useState, useMemo } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import client from '../api/client';

export default function Register() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    fullName: '',
    organization: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: 'USER',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [successId, setSuccessId] = useState(null);

  const strength = useMemo(() => {
    let score = 0;
    if (form.password.length >= 8) score += 25;
    if (/[A-Z]/.test(form.password)) score += 25;
    if (/[0-9]/.test(form.password)) score += 25;
    if (/[^A-Za-z0-9]/.test(form.password)) score += 25;
    return score;
  }, [form.password]);

  const strengthColor = strength >= 75 ? 'bg-emerald-500' : strength >= 50 ? 'bg-amber-500' : 'bg-rose-500';
  const emailValid = useMemo(() => {
    if (form.role === 'ADMIN') return form.email.endsWith('@deeptrust.com');
    return form.email.endsWith('@gmail.com');
  }, [form.email, form.role]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!emailValid) {
      setError(`Invalid email domain for role ${form.role}`);
      return;
    }
    if (form.password !== form.confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (strength < 100) {
      setError('Password is not strong enough');
      return;
    }

    setLoading(true);
    setError('');
    
    try {
      const { data } = await client.post('/auth/register', form);
      setSuccessId(data.deepTrustId);
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  if (successId) {
    return (
      <div className="grid-bg min-h-screen flex items-center justify-center p-4">
        <div className="glass-panel p-8 max-w-md w-full space-y-6 text-center">
          <h2 className="text-2xl font-bold text-emerald-400">Account Created</h2>
          <div className="bg-[#050B14] p-4 rounded-lg border border-cyan-900/50 space-y-2">
            <p className="text-sm text-slate-400">This is your DeepTrust Security Identity.</p>
            <p className="text-xl font-mono text-cyan-300 select-all">{successId}</p>
          </div>
          <button
            onClick={() => navigate('/login')}
            className="btn-primary"
          >
            Proceed to Login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="grid-bg min-h-screen flex items-center justify-center p-4">
      <div className="glass-panel p-8 max-w-md w-full space-y-6">
        <div className="text-center">
          <h2 className="text-2xl font-bold">Create Account</h2>
          <p className="text-sm text-slate-400 mt-1">Enroll your identity in DeepTrust AI</p>
        </div>

        {error && <div className="p-3 bg-rose-500/10 border border-rose-500/40 rounded-lg text-sm text-rose-200">{error}</div>}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm text-slate-300 mb-1">Full Name</label>
            <input
              type="text"
              required
              className="input-field"
              value={form.fullName}
              onChange={(e) => setForm({...form, fullName: e.target.value})}
            />
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-1">Organization</label>
            <input
              type="text"
              required
              className="input-field"
              value={form.organization}
              onChange={(e) => setForm({...form, organization: e.target.value})}
            />
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-1">Role</label>
            <select
              className="input-field"
              value={form.role}
              onChange={(e) => setForm({...form, role: e.target.value})}
            >
              <option value="USER">USER</option>
              <option value="ADMIN">ADMIN</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-1">Email Address</label>
            <input
              type="email"
              required
              className="input-field"
              value={form.email}
              onChange={(e) => setForm({...form, email: e.target.value})}
            />
            <p className={`text-xs mt-1 ${form.email && !emailValid ? 'text-rose-400' : 'text-slate-400'}`}>
              {form.role === 'ADMIN' ? 'Must end with @deeptrust.com' : 'Must end with @gmail.com'}
            </p>
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-1">Password</label>
            <input
              type="password"
              required
              className="input-field"
              value={form.password}
              onChange={(e) => setForm({...form, password: e.target.value})}
            />
            <div className="mt-2 h-1.5 rounded-full bg-[#050B14]">
              <div className={`h-1.5 rounded-full transition-all ${strengthColor}`} style={{ width: `${strength}%` }} />
            </div>
            <div className="mt-1 text-xs text-slate-400 grid grid-cols-2 gap-1">
              <span className={form.password.length >= 8 ? 'text-emerald-400' : ''}>✓ Min 8 chars</span>
              <span className={/[A-Z]/.test(form.password) ? 'text-emerald-400' : ''}>✓ Uppercase</span>
              <span className={/[0-9]/.test(form.password) ? 'text-emerald-400' : ''}>✓ Number</span>
              <span className={/[^A-Za-z0-9]/.test(form.password) ? 'text-emerald-400' : ''}>✓ Special</span>
            </div>
          </div>
          <div>
            <label className="block text-sm text-slate-300 mb-1">Confirm Password</label>
            <input
              type="password"
              required
              className="input-field"
              value={form.confirmPassword}
              onChange={(e) => setForm({...form, confirmPassword: e.target.value})}
            />
          </div>
          
          <button type="submit" disabled={loading} className="btn-primary mt-6">
            {loading ? 'Creating...' : 'Enroll Account'}
          </button>
          
          <div className="text-center text-sm">
            <Link to="/login" className="text-cyan-400 hover:text-cyan-300">
              Already have an account? Login
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
