import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import client from '../api/client';

function Card({ title, value }) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
      <p className="text-sm text-slate-400">{title}</p>
      <p className="mt-1 text-2xl font-bold">{value}</p>
    </div>
  );
}

export default function Dashboard() {
  const [overview, setOverview] = useState({ totalMediaScanned: 0, authenticMediaCount: 0, deepfakesDetected: 0, highRiskAlerts: 0 });
  const [history, setHistory] = useState([]);
  const [analytics, setAnalytics] = useState({ labels: [], trend: [] });
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [statusMessage, setStatusMessage] = useState('');

  const username = localStorage.getItem('deeptrust_user_name') || 'User';

  const maxTrend = useMemo(() => Math.max(1, ...analytics.trend), [analytics]);

  const loadOverview = async () => {
    const { data } = await client.get('/dashboard/overview');
    setOverview(data.overview);
    setHistory(data.history || []);
    setAnalytics(data.analytics || { labels: [], trend: [] });
  };

  useEffect(() => {
    loadOverview().catch(() => setStatusMessage('Failed to load dashboard data'));
  }, []);

  const handleUpload = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('mediaFile', file);

    try {
      setUploading(true);
      setUploadProgress(0);
      setStatusMessage('Uploading file...');

      await client.post('/uploads', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: (progress) => {
          const pct = Math.round((progress.loaded * 100) / Math.max(progress.total || 1, 1));
          setUploadProgress(pct);
        },
      });

      setStatusMessage('File uploaded. Status: Processing');
      await loadOverview();
    } catch (error) {
      setStatusMessage(error.response?.data?.message || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('deeptrust_token');
    window.location.href = '/login';
  };

  return (
    <main className="min-h-screen bg-slate-950 p-4 text-slate-100">
      <div className="mx-auto max-w-6xl space-y-4">
        <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div>
            <h1 className="text-2xl font-bold">Welcome, {username.toUpperCase()}</h1>
            <p className="text-sm text-slate-400">Last Login: 24 Feb 2026 · Account Risk Level: Low</p>
          </div>
          <button className="rounded-lg border border-slate-700 px-4 py-2" onClick={logout}>Logout</button>
        </div>

        <section>
          <h2 className="mb-2 text-lg font-semibold">Overview Cards</h2>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <Card title="Total Media Scanned" value={overview.totalMediaScanned} />
            <Card title="Authentic Media Count" value={overview.authenticMediaCount} />
            <Card title="Deepfake Detected" value={overview.deepfakesDetected} />
            <Card title="High Risk Alerts" value={overview.highRiskAlerts} />
          </div>
        </section>

        <section className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <h2 className="mb-3 text-lg font-semibold">Upload Media Section</h2>
          <input type="file" onChange={handleUpload} className="block w-full text-sm" />
          {uploading && (
            <div className="mt-3 h-2 rounded-full bg-slate-800">
              <div className="h-2 rounded-full bg-cyan-500" style={{ width: `${uploadProgress}%` }} />
            </div>
          )}
          {statusMessage && <p className="mt-2 text-sm text-cyan-300">{statusMessage}</p>}
        </section>

        <section className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <h2 className="mb-3 text-lg font-semibold">Detection History Table</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-400">
                  <th className="pb-2">File Name</th>
                  <th className="pb-2">Upload Date</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2">Authenticity</th>
                  <th className="pb-2">Risk</th>
                </tr>
              </thead>
              <tbody>
                {history.map((row) => (
                  <tr key={row._id} className="border-t border-slate-800">
                    <td className="py-2">{row.fileName}</td>
                    <td className="py-2">{new Date(row.createdAt).toLocaleString()}</td>
                    <td className="py-2">{row.status}</td>
                    <td className="py-2">{row.authenticityScore ?? '--'}</td>
                    <td className={`py-2 ${row.riskLevel === 'HIGH' ? 'text-rose-400' : row.riskLevel === 'MEDIUM' ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {row.riskLevel ?? '--'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <h2 className="mb-3 text-lg font-semibold">Analytics Chart</h2>
          <div className="space-y-2">
            {analytics.labels.map((label, index) => (
              <div key={label} className="flex items-center gap-3">
                <span className="w-10 text-xs text-slate-400">{label}</span>
                <div className="h-3 flex-1 rounded-full bg-slate-800">
                  <div className="h-3 rounded-full bg-cyan-500" style={{ width: `${(analytics.trend[index] / maxTrend) * 100}%` }} />
                </div>
                <span className="w-8 text-right text-xs">{analytics.trend[index]}</span>
              </div>
            ))}
          </div>
        </section>
      </div>
    </main>
  );
}
