import React from 'react';
export default function StatsPanel() {
  const stats = [
    ['12,540', 'Media Files Verified'],
    ['1,243', 'Deepfakes Detected'],
    ['96.4%', 'Detection Accuracy'],
    ['18', 'Partner Institutions'],
  ];

  return (
    <div className="grid grid-cols-2 gap-3">
      {stats.map(([value, label]) => (
        <div key={label} className="rounded-xl border border-blue-500/30 bg-slate-900/70 p-3">
          <p className="text-xl font-bold text-white">{value}</p>
          <p className="text-xs text-slate-300">{label}</p>
        </div>
      ))}
    </div>
  );
}
