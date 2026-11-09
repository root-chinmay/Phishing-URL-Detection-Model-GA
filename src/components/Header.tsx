import React from 'react';
import { Shield, Smartphone } from 'lucide-react';

interface HeaderProps {
  onOpenMobileSim: () => void;
  activeTab: 'scanner' | 'benchmarks' | 'adversarial';
  setActiveTab: (tab: 'scanner' | 'benchmarks' | 'adversarial') => void;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenMobileSim,
  activeTab,
  setActiveTab
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Title */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 text-white">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg text-white tracking-tight">URL Threat Detection</span>
                <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  v1.0.0 Research Edition
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Explainable, Calibrated & Adversarially Robust Mobile Malicious URL Detection
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="hidden md:flex items-center space-x-1 bg-slate-900/80 border border-slate-800 p-1 rounded-xl">
            <button
              onClick={() => setActiveTab('scanner')}
              className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'scanner'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Live Detection Engine
            </button>
            <button
              onClick={() => setActiveTab('adversarial')}
              className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'adversarial'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Adversarial Sandbox
            </button>
            <button
              onClick={() => setActiveTab('benchmarks')}
              className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'benchmarks'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Research Benchmarks & Gaps
            </button>
          </div>

          {/* Actions */}
          <div className="flex items-center space-x-2">
            <button
              onClick={onOpenMobileSim}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-all cursor-pointer"
              title="Launch Android Kivy Mobile Frame"
            >
              <Smartphone className="w-3.5 h-3.5" />
              <span>Mobile App Preview</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
