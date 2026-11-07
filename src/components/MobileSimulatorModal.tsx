import React, { useState } from 'react';
import { 
  X, Shield, Smartphone, QrCode, History, Settings, FileText, ArrowLeft,
  Search, ShieldCheck, AlertTriangle, AlertOctagon, CheckCircle2, ChevronRight, Lock
} from 'lucide-react';
import { analyzeUrlClient, DetectionResult } from '../engine/urlDetector';

interface MobileSimulatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialUrl?: string;
}

export const MobileSimulatorModal: React.FC<MobileSimulatorModalProps> = ({
  isOpen,
  onClose,
  initialUrl = "http://paypa1-account-verification-alert.com/login.php?cmd=verify"
}) => {
  const [activeScreen, setActiveScreen] = useState<'home' | 'analysis' | 'assessment' | 'details' | 'history' | 'settings'>('home');
  const [mobileUrl, setMobileUrl] = useState(initialUrl);
  const [currentResult, setCurrentResult] = useState<DetectionResult>(() => analyzeUrlClient(initialUrl));
  const [historyList, setHistoryList] = useState<DetectionResult[]>([analyzeUrlClient(initialUrl)]);
  const [offlineMode, setOfflineMode] = useState(true);
  const [saveHistoryOptIn, setSaveHistoryOptIn] = useState(true);

  if (!isOpen) return null;

  const triggerMobileScan = (targetUrl?: string) => {
    const u = targetUrl || mobileUrl;
    if (!u.trim()) return;
    setActiveScreen('analysis');
    setTimeout(() => {
      const res = analyzeUrlClient(u);
      setCurrentResult(res);
      if (saveHistoryOptIn) {
        setHistoryList(prev => [res, ...prev.slice(0, 9)]);
      }
      setActiveScreen('assessment');
    }, 600);
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/85 backdrop-blur-md flex flex-col items-center justify-center p-4 overflow-y-auto">
      {/* Close Button Top Bar */}
      <div className="w-[360px] flex justify-end mb-2">
        <button
          onClick={onClose}
          className="text-slate-300 hover:text-white flex items-center space-x-1.5 px-3 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-medium cursor-pointer shadow-md"
        >
          <span>Close Simulator</span>
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="relative">
        {/* Mobile Phone Mockup Frame (360 x 700) */}
        <div className="w-[360px] h-[680px] bg-slate-950 border-[8px] border-slate-800 rounded-[40px] shadow-2xl overflow-hidden flex flex-col relative ring-1 ring-slate-800">
          {/* Top Notch / Speaker Bar */}
          <div className="h-6 bg-slate-950 flex items-center justify-center relative shrink-0 z-20">
            <div className="w-24 h-4 bg-slate-900 rounded-full flex items-center justify-center">
              <div className="w-2.5 h-2.5 rounded-full bg-slate-800 mr-2" />
              <div className="w-8 h-1 rounded-full bg-slate-800" />
            </div>
          </div>

          {/* App Header Bar inside Phone */}
          <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between shrink-0">
            <div className="flex items-center space-x-2">
              {activeScreen !== 'home' ? (
                <button
                  onClick={() => setActiveScreen('home')}
                  className="text-slate-400 hover:text-white"
                >
                  <ArrowLeft className="w-4 h-4" />
                </button>
              ) : (
                <div className="w-5 h-5 rounded-md bg-blue-600 flex items-center justify-center text-white">
                  <Shield className="w-3 h-3" />
                </div>
              )}
              <span className="font-bold text-xs text-white tracking-tight">MobiURL-Guard</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span className="text-[10px] font-mono text-emerald-400">Offline Active</span>
            </div>
          </div>

          {/* Screen Content Body */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs font-sans">
            {/* Screen 1: Home Dashboard */}
            {activeScreen === 'home' && (
              <div className="space-y-4">
                <div className="p-3.5 rounded-2xl bg-gradient-to-br from-blue-900/40 to-slate-900 border border-blue-500/20 text-center">
                  <div className="w-10 h-10 rounded-xl bg-blue-600 mx-auto flex items-center justify-center text-white shadow-lg shadow-blue-500/30 mb-2">
                    <Shield className="w-5 h-5" />
                  </div>
                  <h3 className="text-sm font-bold text-white">On-Device Shield</h3>
                  <p className="text-[11px] text-slate-300 mt-0.5">
                    100% Offline Edge Malicious URL & Phishing Detection
                  </p>
                </div>

                <div className="space-y-2">
                  <label className="text-[11px] font-semibold text-slate-300 block">
                    Inspect Web Link
                  </label>
                  <div className="relative">
                    <input
                      type="text"
                      value={mobileUrl}
                      onChange={(e) => setMobileUrl(e.target.value)}
                      placeholder="Paste suspicious URL..."
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-750 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
                    />
                  </div>
                  <button
                    onClick={() => triggerMobileScan()}
                    className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-bold flex items-center justify-center space-x-1.5 shadow-lg shadow-blue-600/30 cursor-pointer"
                  >
                    <Search className="w-3.5 h-3.5" />
                    <span>Run Mobile Analysis</span>
                  </button>
                </div>

                {/* Quick Shortcuts */}
                <div className="grid grid-cols-2 gap-2 pt-2">
                  <button
                    onClick={() => {
                      setMobileUrl("http://paypa1-account-verification-alert.com/login.php?cmd=verify");
                      triggerMobileScan("http://paypa1-account-verification-alert.com/login.php?cmd=verify");
                    }}
                    className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-left hover:bg-slate-850"
                  >
                    <span className="text-[10px] uppercase font-bold text-rose-400 block">Phishing</span>
                    <span className="text-[11px] text-slate-300 truncate block">PayPal Typosquat</span>
                  </button>
                  <button
                    onClick={() => {
                      setMobileUrl("https://www.google.com");
                      triggerMobileScan("https://www.google.com");
                    }}
                    className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-left hover:bg-slate-850"
                  >
                    <span className="text-[10px] uppercase font-bold text-emerald-400 block">Legitimate</span>
                    <span className="text-[11px] text-slate-300 truncate block">Google Search</span>
                  </button>
                </div>

                {/* Recent Scans preview */}
                <div className="pt-2">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-semibold text-slate-400">Recent On-Device Scans</span>
                    <button
                      onClick={() => setActiveScreen('history')}
                      className="text-[11px] text-blue-400 font-medium"
                    >
                      View All
                    </button>
                  </div>
                  <div className="space-y-1.5">
                    {historyList.slice(0, 2).map((item, idx) => (
                      <div
                        key={idx}
                        onClick={() => { setCurrentResult(item); setActiveScreen('assessment'); }}
                        className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between cursor-pointer"
                      >
                        <span className="font-mono text-[11px] text-slate-300 truncate max-w-[190px]">
                          {item.url}
                        </span>
                        <span className={`text-[10px] font-bold uppercase px-1.5 py-0.2 rounded ${
                          item.classification === 'malicious' ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'
                        }`}>
                          {item.risk_percentage}%
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Screen 2: URL Analysis In-Progress */}
            {activeScreen === 'analysis' && (
              <div className="py-16 text-center space-y-4">
                <div className="w-12 h-12 rounded-full border-4 border-blue-500 border-t-transparent animate-spin mx-auto" />
                <h4 className="text-sm font-bold text-white">Extracting 28 Edge Features</h4>
                <p className="text-[11px] text-slate-400 max-w-[220px] mx-auto">
                  Computing Shannon entropy, confusable homoglyphs, and split conformal bounds...
                </p>
              </div>
            )}

            {/* Screen 3: Risk Assessment */}
            {activeScreen === 'assessment' && currentResult && (
              <div className="space-y-4">
                <div className="text-center p-4 rounded-2xl bg-slate-900 border border-slate-800">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                    Decision Outcome
                  </span>
                  <div className="my-2">
                    <span className={`text-2xl font-extrabold uppercase ${
                      currentResult.classification === 'malicious' ? 'text-rose-400' :
                      currentResult.classification === 'legitimate' ? 'text-emerald-400' : 'text-amber-400'
                    }`}>
                      {currentResult.classification}
                    </span>
                  </div>

                  <div className="flex items-center justify-center space-x-4 text-xs font-mono">
                    <div>
                      <span className="text-slate-400 block text-[10px]">Malicious Risk</span>
                      <span className="text-sm font-bold text-rose-400">{currentResult.risk_percentage}%</span>
                    </div>
                    <div className="w-px h-6 bg-slate-800" />
                    <div>
                      <span className="text-slate-400 block text-[10px]">Benign Prob</span>
                      <span className="text-sm font-bold text-emerald-400">{currentResult.benign_percentage}%</span>
                    </div>
                  </div>
                </div>

                {/* Conformal prediction badge */}
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-400">Conformal Set (95%):</span>
                    <span className="font-mono text-cyan-300 font-semibold">{`{ ${currentResult.conformal_prediction_set.join(', ')} }`}</span>
                  </div>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-slate-400">Model Confidence:</span>
                    <span className="capitalize text-slate-200">{currentResult.prediction_confidence}</span>
                  </div>
                </div>

                {/* Top explainable reasons */}
                <div className="space-y-1.5">
                  <span className="text-[11px] font-semibold text-slate-400 block">Explainable Factors:</span>
                  {currentResult.top_reasons.slice(0, 2).map((r, i) => (
                    <div key={i} className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-[11px] text-slate-200">
                      {r.text}
                    </div>
                  ))}
                </div>

                <button
                  onClick={() => setActiveScreen('details')}
                  className="w-full py-2 bg-slate-800 hover:bg-slate-750 text-slate-200 rounded-xl text-xs font-medium flex items-center justify-center space-x-1"
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Deep Feature Diagnostics</span>
                </button>
              </div>
            )}

            {/* Screen 4: Detailed Analysis */}
            {activeScreen === 'details' && currentResult && (
              <div className="space-y-3">
                <h4 className="font-bold text-white text-xs">Deep Structural Telemetry</h4>
                <div className="space-y-2">
                  <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Shannon Entropy</span>
                    <span className="font-mono text-cyan-300">{currentResult.features.entropy} bits</span>
                  </div>
                  <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Punycode / Homoglyphs</span>
                    <span className="font-mono text-rose-400">{currentResult.features.homoglyphs_count} found</span>
                  </div>
                  <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Impersonated Brand</span>
                    <span className="font-mono text-amber-300">{currentResult.features.impersonated_brand || 'None'}</span>
                  </div>
                  <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 flex justify-between">
                    <span className="text-slate-400">Subdomains</span>
                    <span className="font-mono text-white">{currentResult.features.num_subdomains}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Screen 5: Scan History */}
            {activeScreen === 'history' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="font-bold text-white text-xs">Local Scan History</h4>
                  <button
                    onClick={() => setHistoryList([])}
                    className="text-[11px] text-rose-400 hover:underline"
                  >
                    Clear History
                  </button>
                </div>
                {historyList.length === 0 ? (
                  <p className="text-slate-500 text-center py-8 text-[11px]">No scans recorded.</p>
                ) : (
                  historyList.map((item, idx) => (
                    <div
                      key={idx}
                      onClick={() => { setCurrentResult(item); setActiveScreen('assessment'); }}
                      className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between cursor-pointer"
                    >
                      <div className="max-w-[190px]">
                        <span className="font-mono text-[11px] text-slate-200 block truncate">{item.url}</span>
                        <span className="text-[10px] text-slate-500">{new Date(item.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                        item.classification === 'malicious' ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'
                      }`}>
                        {item.classification}
                      </span>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Screen 6: Settings */}
            {activeScreen === 'settings' && (
              <div className="space-y-4">
                <h4 className="font-bold text-white text-xs">Settings & Privacy</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900 border border-slate-800">
                    <div>
                      <span className="font-semibold text-white block">Offline Edge Mode</span>
                      <span className="text-[10px] text-slate-400">No telemetry or remote lookups</span>
                    </div>
                    <input
                      type="checkbox"
                      checked={offlineMode}
                      onChange={(e) => setOfflineMode(e.target.checked)}
                      className="accent-blue-600 w-4 h-4"
                    />
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900 border border-slate-800">
                    <div>
                      <span className="font-semibold text-white block">Opt-in Scan History</span>
                      <span className="text-[10px] text-slate-400">Stored strictly in local memory</span>
                    </div>
                    <input
                      type="checkbox"
                      checked={saveHistoryOptIn}
                      onChange={(e) => setSaveHistoryOptIn(e.target.checked)}
                      className="accent-blue-600 w-4 h-4"
                    />
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-[11px] space-y-1">
                    <span className="text-slate-400 block font-semibold">Engine Manifest</span>
                    <div className="flex justify-between text-slate-300">
                      <span>Model Version:</span>
                      <span className="font-mono">1.0.0 (Distilled Tree)</span>
                    </div>
                    <div className="flex justify-between text-slate-300">
                      <span>Feature Schema:</span>
                      <span className="font-mono">28 Core Features</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Bottom Navigation Bar */}
          <div className="h-14 bg-slate-900 border-t border-slate-800 grid grid-cols-4 items-center shrink-0 z-20">
            <button
              onClick={() => setActiveScreen('home')}
              className={`flex flex-col items-center justify-center space-y-1 ${
                activeScreen === 'home' ? 'text-blue-400' : 'text-slate-400'
              }`}
            >
              <Shield className="w-4 h-4" />
              <span className="text-[9px] font-medium">Home</span>
            </button>
            <button
              onClick={() => setActiveScreen('details')}
              className={`flex flex-col items-center justify-center space-y-1 ${
                activeScreen === 'details' || activeScreen === 'assessment' ? 'text-blue-400' : 'text-slate-400'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span className="text-[9px] font-medium">Inspect</span>
            </button>
            <button
              onClick={() => setActiveScreen('history')}
              className={`flex flex-col items-center justify-center space-y-1 ${
                activeScreen === 'history' ? 'text-blue-400' : 'text-slate-400'
              }`}
            >
              <History className="w-4 h-4" />
              <span className="text-[9px] font-medium">History</span>
            </button>
            <button
              onClick={() => setActiveScreen('settings')}
              className={`flex flex-col items-center justify-center space-y-1 ${
                activeScreen === 'settings' ? 'text-blue-400' : 'text-slate-400'
              }`}
            >
              <Settings className="w-4 h-4" />
              <span className="text-[9px] font-medium">Settings</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
