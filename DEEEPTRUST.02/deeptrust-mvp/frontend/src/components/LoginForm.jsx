import React from 'react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

export default function LoginForm({ onSubmit, loading, attempts }) {
  const [form, setForm] = useState({
    email: '',
    password: '',
    role: 'USER',
    rememberMe: false,
  });
  const [showPassword, setShowPassword] = useState(false);

  const emailValid = useMemo(() => /[^\s@]+@[^\s@]+\.[^\s@]+/.test(form.email), [form.email]);

  const strength = useMemo(() => {
    let score = 0;
    if (form.password.length >= 8) score += 25;
    if (/[A-Z]/.test(form.password)) score += 25;
    if (/[0-9]/.test(form.password)) score += 25;
    if (/[^A-Za-z0-9]/.test(form.password)) score += 25;
    return score;
  }, [form.password]);

  const strengthColor = strength >= 75 ? 'bg-emerald-500' : strength >= 50 ? 'bg-amber-500' : 'bg-rose-500';

  return (
    <form
      className="space-y-3"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(form, emailValid);
      }}
    >
      <div>
        <label className="text-sm text-slate-300">Email Address</label>
        <input
          className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2"
          type="email"
          value={form.email}
          onChange={(event) => setForm((prev) => ({ ...prev, email: event.target.value }))}
          required
        />
        <p className={`text-xs ${emailValid || !form.email ? 'text-slate-400' : 'text-rose-400'}`}>
          {form.email && !emailValid ? 'Invalid email format' : 'Real-time email validation active'}
        </p>
      </div>

      <div>
        <label className="text-sm text-slate-300">Password</label>
        <div className="mt-1 flex gap-2">
          <input
            className="w-full rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2"
            type={showPassword ? 'text' : 'password'}
            value={form.password}
            onChange={(event) => setForm((prev) => ({ ...prev, password: event.target.value }))}
            required
          />
          <button
            type="button"
            className="rounded-lg border border-slate-600 px-3 text-sm"
            onClick={() => setShowPassword((value) => !value)}
          >
            {showPassword ? 'Hide' : 'Show'}
          </button>
        </div>
        <div className="mt-2 h-2 rounded-full bg-slate-800">
          <div className={`h-2 rounded-full ${strengthColor}`} style={{ width: `${strength}%` }} />
        </div>
        <p className="text-xs text-slate-400">Password strength check enabled</p>
      </div>

      <div className="flex items-center justify-between text-sm">
        <label className="flex items-center gap-2 text-slate-300">
          <input
            type="checkbox"
            checked={form.rememberMe}
            onChange={(event) => setForm((prev) => ({ ...prev, rememberMe: event.target.checked }))}
          />
          Remember Me
        </label>
        <span className="text-cyan-300">Forgot Password</span>
      </div>

      <div>
        <label className="text-sm text-slate-300">Role Selector</label>
        <select
          className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2"
          value={form.role}
          onChange={(event) => setForm((prev) => ({ ...prev, role: event.target.value }))}
        >
          <option value="USER">USER</option>
          <option value="ADMIN">ADMIN</option>
        </select>
      </div>

      <p className="text-xs text-slate-400">Login attempt counter: {attempts}</p>

      <button
        className="w-full rounded-lg bg-cyan-500 px-4 py-2 font-semibold text-slate-950 transition hover:shadow-[0_0_20px_rgba(34,211,238,.45)] disabled:opacity-50"
        type="submit"
        disabled={loading}
      >
        {loading ? 'Authenticating...' : 'Authenticate Securely'}
      </button>

      <div className="relative py-2 text-center text-xs text-slate-400">
        <span className="bg-slate-900 px-3">OR</span>
      </div>
      <Link to="/register" className="block text-center w-full rounded-lg border border-slate-600 hover:border-cyan-500 py-2 text-sm transition-colors text-slate-300 hover:text-cyan-400">
        Create New Account
      </Link>

      <p className="text-xs text-slate-400">
        This system uses AI-driven risk analysis to detect suspicious login attempts.
      </p>
    </form>
  );
}
