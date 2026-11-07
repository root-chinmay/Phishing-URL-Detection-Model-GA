import React, { useState } from 'react';
import { Sparkles, ArrowRight, ShieldAlert, ShieldCheck, RefreshCw, Zap } from 'lucide-react';
import { analyzeUrlClient, DetectionResult } from '../engine/urlDetector';

interface AdversarialLabProps {
  initialUrl?: string;
  onSendToScanner: (url: string) => void;
}

export const AdversarialLab: React.FC<AdversarialLabProps> = ({
  initialUrl = "http://paypa1-account-verification-alert.com/login.php?cmd=verify",
  onSendToScanner
}) => {
  const [targetUrl, setTargetUrl] = useState(initialUrl);
  const [selectedAttack, setSelectedAttack] = useState<'homoglyph' | 'subdomain' | 'percent' | 'typo' | 'redirect'>('homoglyph');

  // Compute original
  const origResult = analyzeUrlClient(targetUrl);

  // Apply perturbation
  const getPerturbedUrl = () => {
    try {
      const urlObj = new URL(targetUrl.includes('://') ? targetUrl : `http://${targetUrl}`);
      let host = urlObj.hostname;
      let path = urlObj.pathname;

      switch (selectedAttack) {
        case 'homoglyph':
          // Replace 'a' with Cyrillic 'а', 'e' with Cyrillic 'е'
          const mutatedHost = host.replace(/a/g, 'а').replace(/e/g, 'е');
          return targetUrl.replace(host, mutatedHost);
        case 'subdomain':
          return targetUrl.replace(host, `login.google.com.secure.${host}`);
        case 'percent':
          const hexPath = path.replace(/e/g, '%65').replace(/a/g, '%61');
          return targetUrl.replace(path, hexPath || '/%61uth');
        case 'typo':
          const parts = host.split('.');
          if (parts.length >= 2) {
            const core = parts[parts.length - 2];
            if (core.length > 3) {
              const swapped = core.slice(0, 2) + core[3] + core[2] + core.slice(4);
              parts[parts.length - 2] = swapped;
              return targetUrl.replace(host, parts.join('.'));
            }
          }
          return `${targetUrl}-verify`;
        case 'redirect':
          return `https://trusted-portal-gateway.test/redirect?url=${encodeURIComponent(targetUrl)}`;
        default:
          return targetUrl;
      }
    } catch {
      return `${targetUrl}?ref=mutated`;
    }
  };

  const perturbedUrl = getPerturbedUrl();
  const pertResult = analyzeUrlClient(perturbedUrl);

  const getAttackDescription = () => {
    switch (selectedAttack) {
      case 'homoglyph':
        return "Substitutes Latin ASCII characters with visually identical Cyrillic codepoints (Unicode homoglyphs) to fool string-matching systems.";
      case 'subdomain':
        return "Prepends trusted domain names as deep subdomains (e.g. login.google.com.attacker.xyz) to deceive superficial domain token parsers.";
      case 'percent':
        return "Applies URL percent hex encoding (%65 for 'e', %61 for 'a') in the path to mask sensitive phishing keywords.";
      case 'typo':
        return "Transposes adjacent characters in the registered domain to mimic human typos and bypass exact brand blacklists.";
      case 'redirect':
        return "Wraps the destination inside an open-redirect parameter on an external gateway to conceal the malicious landing page.";
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <Sparkles className="w-5 h-5 text-cyan-400" />
              <span>Controlled Adversarial Robustness Sandbox</span>
            </h2>
            <p className="text-xs text-slate-400">
              Evaluate real-time model resilience against evasion mutations and adversarial perturbations.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-xs text-slate-400 font-medium">Attack Mutation:</span>
            <div className="flex flex-wrap gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
              {[
                { id: 'homoglyph', label: 'Homoglyph (Cyrillic)' },
                { id: 'subdomain', label: 'Subdomain Spoofing' },
                { id: 'percent', label: 'Percent Hex Encoding' },
                { id: 'typo', label: 'Typosquatting' },
                { id: 'redirect', label: 'Nested Redirect' },
              ].map(atk => (
                <button
                  key={atk.id}
                  onClick={() => setSelectedAttack(atk.id as any)}
                  className={`px-3 py-1 rounded-lg text-xs font-medium transition-all ${
                    selectedAttack === atk.id
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {atk.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Attack Description Box */}
        <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-300 mb-6">
          <span className="font-semibold text-cyan-400 mr-2">Attack Mechanics:</span>
          {getAttackDescription()}
        </div>

        {/* Side-by-Side Comparison */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Original URL Card */}
          <div className="p-5 rounded-2xl bg-slate-950/80 border border-slate-800 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold uppercase text-slate-400">Original Baseline URL</span>
                <span className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase border ${
                  origResult.classification === 'malicious' ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                }`}>
                  {origResult.classification}
                </span>
              </div>
              <p className="font-mono text-xs text-slate-200 break-all p-3 rounded-lg bg-slate-900 border border-slate-800 mb-4">
                {targetUrl}
              </p>

              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-400">Calibrated Risk:</span>
                  <span className="font-bold text-white">{origResult.risk_percentage}%</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Conformal Prediction Set:</span>
                  <span className="font-mono text-cyan-300 font-semibold">{`{ ${origResult.conformal_prediction_set.join(', ')} }`}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Confidence:</span>
                  <span className="capitalize text-slate-200">{origResult.prediction_confidence}</span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-slate-800 text-[11px] text-slate-400">
              Top Factor: {origResult.top_reasons[0]?.text || 'Normal structural features'}
            </div>
          </div>

          {/* Adversarially Perturbed Card */}
          <div className="p-5 rounded-2xl bg-slate-950/80 border border-purple-500/30 shadow-lg shadow-purple-500/5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold uppercase text-purple-400 flex items-center space-x-1.5">
                  <Zap className="w-3.5 h-3.5" />
                  <span>Perturbed Evasion Sample</span>
                </span>
                <span className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase border ${
                  pertResult.classification === 'malicious' ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' :
                  pertResult.classification === 'uncertain' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                  'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                }`}>
                  {pertResult.classification}
                </span>
              </div>
              <p className="font-mono text-xs text-purple-200 break-all p-3 rounded-lg bg-slate-900 border border-purple-500/20 mb-4">
                {perturbedUrl}
              </p>

              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-400">Calibrated Risk:</span>
                  <span className="font-bold text-white">{pertResult.risk_percentage}%</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Conformal Prediction Set:</span>
                  <span className="font-mono text-cyan-300 font-semibold">{`{ ${pertResult.conformal_prediction_set.join(', ')} }`}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Defense Outcome:</span>
                  <span className="font-bold text-emerald-400">
                    {pertResult.classification === 'malicious' ? 'Attack Thwarted (Still Flagged Malicious)' :
                     pertResult.classification === 'uncertain' ? 'Defended via Uncertainty Set (Cannot Evade)' :
                     'Evasion Succeeded'}
                  </span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-slate-800 flex items-center justify-between">
              <span className="text-[11px] text-slate-400">
                Defense: {pertResult.top_reasons[0]?.text}
              </span>
              <button
                onClick={() => onSendToScanner(perturbedUrl)}
                className="text-xs text-blue-400 hover:text-blue-300 font-medium cursor-pointer"
              >
                Inspect in Scanner &rarr;
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
