import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export default function Startup() {
  const [progress, setProgress] = useState(0);
  const navigate = useNavigate();

  useEffect(() => {
    let current = 0;
    const interval = setInterval(() => {
      current += 20;
      if (current <= 100) {
        setProgress(current);
      }
      if (current >= 100) {
        clearInterval(interval);
        setTimeout(() => {
          navigate('/login');
        }, 500);
      }
    }, 400);

    return () => clearInterval(interval);
  }, [navigate]);

  return (
    <div className="grid-bg min-h-screen flex flex-col items-center justify-center p-4">
      <div className="glass-panel p-10 flex flex-col items-center max-w-md w-full space-y-8">
        <div className="text-center space-y-2">
          <h1 className="text-4xl font-bold tracking-tight text-white">
            DeepTrust <span className="text-cyan-400">AI</span>
          </h1>
          <p className="text-sm text-cyan-200/70 font-medium tracking-widest uppercase">
            Identity & Threat Intelligence Platform
          </p>
        </div>

        <div className="w-full space-y-2">
          <div className="flex justify-between text-xs font-mono text-cyan-400">
            <span>SYSTEM INITIALIZATION</span>
            <span>{progress}%</span>
          </div>
          <div className="h-2 w-full bg-[#050B14] rounded-full overflow-hidden border border-cyan-900/30">
            <div 
              className="h-full bg-cyan-500 shadow-[0_0_10px_rgba(6,182,212,0.5)] transition-all duration-300 ease-out"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        <div className="text-center">
          <p className="text-xs font-mono text-slate-500 animate-pulse">
            Establishing secure connection...
          </p>
        </div>
      </div>
    </div>
  );
}
