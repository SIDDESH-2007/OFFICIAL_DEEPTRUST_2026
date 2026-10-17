import React from 'react';
export default function SecurityInfo() {
  return (
    <div className="rounded-xl border border-cyan-500/30 bg-slate-900/70 p-4 text-sm text-cyan-100">
      <p className="font-semibold">Security Assurance</p>
      <ul className="mt-2 space-y-1 text-cyan-200/90">
        <li>• AES-256 Encryption</li>
        <li>• JWT Secure Authentication</li>
        <li>• Cloud Hosted</li>
        <li>• AI-Powered Detection</li>
      </ul>
    </div>
  );
}
