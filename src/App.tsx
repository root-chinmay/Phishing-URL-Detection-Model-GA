/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Header } from './components/Header';
import { ScannerPanel } from './components/ScannerPanel';
import { AdversarialLab } from './components/AdversarialLab';
import { BenchmarkReports } from './components/BenchmarkReports';
import { QRQuishingModal } from './components/QRQuishingModal';
import { MobileSimulatorModal } from './components/MobileSimulatorModal';
import { DeploymentModal } from './components/DeploymentModal';
import { Shield, Sparkles, Smartphone, BarChart3, CheckCircle, Github } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'benchmarks' | 'adversarial'>('scanner');
  const [isQRModalOpen, setIsQRModalOpen] = useState(false);
  const [isMobileSimOpen, setIsMobileSimOpen] = useState(false);
  const [isDeployModalOpen, setIsDeployModalOpen] = useState(false);
  const [adversarialTargetUrl, setAdversarialTargetUrl] = useState("http://paypa1-account-verification-alert.com/login.php?cmd=verify");

  const handleSelectUrlForAdversarial = (url: string) => {
    setAdversarialTargetUrl(url);
    setActiveTab('adversarial');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-blue-500/30 selection:text-white">
      {/* Navigation Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenMobileSim={() => setIsMobileSimOpen(true)}
        onOpenDeploy={() => setIsDeployModalOpen(true)}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'scanner' && (
          <ScannerPanel
            onOpenQRScanner={() => setIsQRModalOpen(true)}
            onSelectUrlForAdversarial={handleSelectUrlForAdversarial}
          />
        )}

        {activeTab === 'adversarial' && (
          <AdversarialLab
            initialUrl={adversarialTargetUrl}
            onSendToScanner={(url) => {
              setActiveTab('scanner');
            }}
          />
        )}

        {activeTab === 'benchmarks' && (
          <BenchmarkReports />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/90 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <Shield className="w-4 h-4 text-blue-500" />
            <span className="font-semibold text-slate-400">MobiURL-Guard Research Platform</span>
            <span>&bull;</span>
            <span>Zero-Day Generalization & Conformal Uncertainty</span>
          </div>

          <div className="flex items-center space-x-4">
            <span className="flex items-center space-x-1.5 text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Offline Edge Inference Verified</span>
            </span>
            <button
              onClick={() => setIsDeployModalOpen(true)}
              className="text-slate-400 hover:text-white flex items-center space-x-1 transition-all cursor-pointer"
            >
              <Github className="w-3.5 h-3.5" />
              <span>GitHub / Vercel</span>
            </button>
          </div>
        </div>
      </footer>

      {/* Modals */}
      <QRQuishingModal
        isOpen={isQRModalOpen}
        onClose={() => setIsQRModalOpen(false)}
        onSendToScanner={(url) => {
          setActiveTab('scanner');
        }}
      />

      <MobileSimulatorModal
        isOpen={isMobileSimOpen}
        onClose={() => setIsMobileSimOpen(false)}
      />

      <DeploymentModal
        isOpen={isDeployModalOpen}
        onClose={() => setIsDeployModalOpen(false)}
      />
    </div>
  );
}
