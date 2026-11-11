import React, { useState } from 'react';
import { 
  Search, QrCode, ShieldCheck, AlertTriangle, AlertOctagon, HelpCircle, 
  ChevronDown, ChevronUp, Copy, Check, MessageSquare, ExternalLink, RefreshCw, Sparkles, Layers, GitBranch, Loader2
} from 'lucide-react';
import {
  analyzeUrlClient,
  DetectionResult,
  isShortenerOrRedirectUrl,
  resolveUrlViaApi
} from '../engine/urlDetector';

interface ScannerPanelProps {
  onOpenQRScanner: () => void;
  onSelectUrlForAdversarial: (url: string) => void;
}

const PRESET_URLS = [
  {
    label: "Safe Authority (Google)",
    url: "https://www.google.com/search?q=machine+learning+security",
    type: "benign"
  },
  {
    label: "Brand Impersonation (PayPal Typosquat)",
    url: "http://paypa1-account-verification-alert.com/login.php?cmd=verify",
    type: "phishing"
  },
  {
    label: "Cyrillic Homoglyph Attack (xn--)",
    url: "https://xn--pypal-4ve.com/signin/webapps/mpp/home",
    type: "homoglyph"
  },
  {
    label: "Direct IP Address Host",
    url: "http://192.168.1.100/admin/secure_login.php?dest=dashboard",
    type: "ip_host"
  },
  {
    label: "Masked URL Shortener",
    url: "http://bit.ly/3x8AbCd",
    type: "shortener"
  },
  {
    label: "Uncertain / Edge Case Sample",
    url: "https://auth-session-gateway-temp2026.cloud/verify?auth=token",
    type: "uncertain"
  }
];

export const ScannerPanel: React.FC<ScannerPanelProps> = ({
  onOpenQRScanner,
  onSelectUrlForAdversarial
}) => {
  const [inputUrl, setInputUrl] = useState("http://paypa1-account-verification-alert.com/login.php?cmd=verify");
  const [messageContext, setMessageContext] = useState("");
  const [showMessageBox, setShowMessageBox] = useState(false);
  const [showRawFeatures, setShowRawFeatures] = useState(false);
  const [copied, setCopied] = useState(false);
  const [isResolving, setIsResolving] = useState(false);

  // Compute live detection result
  const [result, setResult] = useState<DetectionResult>(() => analyzeUrlClient(inputUrl));

  const handleScan = async (urlToScan?: string) => {
    const target = urlToScan !== undefined ? urlToScan : inputUrl;
    if (!target.trim()) return;

    // Run immediate baseline analysis first for instant UI feedback
    const initialRes = analyzeUrlClient(target, messageContext);
    setResult(initialRes);

    // If URL is a known shortener or contains redirect wrappers, resolve full redirect chain
    if (isShortenerOrRedirectUrl(target)) {
      setIsResolving(true);
      try {
        const redirectInfo = await resolveUrlViaApi(target);
        if (redirectInfo) {
          const updatedRes = analyzeUrlClient(target, messageContext, redirectInfo);
          setResult(updatedRes);
        }
      } finally {
        setIsResolving(false);
      }
    }
  };

  const handleCopyResult = () => {
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getStatusColor = (classification: string) => {
    if (classification === 'malicious') return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
    if (classification === 'legitimate') return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'critical':
        return <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">Critical</span>;
      case 'high':
        return <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-orange-500/20 text-orange-300 border border-orange-500/30">High Risk</span>;
      case 'medium':
        return <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">Medium</span>;
      case 'safe':
        return <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Benign</span>;
      default:
        return <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-slate-500/20 text-slate-300 border border-slate-500/30">Info</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Input Section Card */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <span>Target URL Inspection</span>
            </h2>
            <p className="text-xs text-slate-400">
              Evaluated with calibrated isotonic probability & split conformal uncertainty guarantees.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setShowMessageBox(!showMessageBox)}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                showMessageBox || messageContext
                  ? 'bg-purple-500/20 text-purple-300 border-purple-500/30'
                  : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-750'
              }`}
            >
              <MessageSquare className="w-3.5 h-3.5" />
              <span>SMS / Context {messageContext ? '(Active)' : ''}</span>
            </button>

            <button
              onClick={onOpenQRScanner}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-750 transition-all cursor-pointer"
            >
              <QrCode className="w-3.5 h-3.5" />
              <span>Scan QR / Quishing</span>
            </button>
          </div>
        </div>

        {/* Input Bar */}
        <div className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
              <Search className="w-4 h-4" />
            </div>
            <input
              type="text"
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              placeholder="Paste or enter URL (e.g. https://domain.test/verify)..."
              className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-700 focus:border-blue-500 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono transition-all"
            />
          </div>

          <button
            onClick={() => handleScan()}
            disabled={isResolving}
            className="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-70 text-white rounded-xl text-sm font-semibold flex items-center justify-center space-x-2 shadow-lg shadow-blue-600/30 transition-all cursor-pointer"
          >
            {isResolving ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Resolving Link...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                <span>Analyze URL</span>
              </>
            )}
          </button>
        </div>

        {/* Message Context Box (Optional Context-Aware Smishing Detection) */}
        {showMessageBox && (
          <div className="mt-4 p-4 rounded-xl bg-slate-950/70 border border-purple-500/20 space-y-2">
            <div className="flex items-center justify-between text-xs text-purple-300 font-medium">
              <span className="flex items-center space-x-1.5">
                <MessageSquare className="w-3.5 h-3.5" />
                <span>Message Context Analysis (Smishing / WhatsApp / Email Lure)</span>
              </span>
              <button
                onClick={() => { setMessageContext(""); handleScan(); }}
                className="text-[11px] text-slate-400 hover:text-slate-200"
              >
                Clear Context
              </button>
            </div>
            <textarea
              rows={2}
              value={messageContext}
              onChange={(e) => setMessageContext(e.target.value)}
              placeholder="Paste accompanying message text: e.g. 'URGENT: Your account has been suspended! Verify your credentials within 24 hours to avoid closure.'"
              className="w-full p-2.5 bg-slate-900 border border-slate-750 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 font-sans"
            />
            <p className="text-[11px] text-slate-400">
              * Privacy Safe: Message text is scored locally on device for urgency & credential lures and is never logged or transmitted.
            </p>
          </div>
        )}

        {/* Presets Chips */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-400 font-medium mr-1">Presets:</span>
          {PRESET_URLS.map((p, idx) => (
            <button
              key={idx}
              onClick={() => {
                setInputUrl(p.url);
                handleScan(p.url);
              }}
              className="px-2.5 py-1 rounded-lg text-[11px] font-medium bg-slate-800/60 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-700/60 transition-all cursor-pointer"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Results Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Calibrated Risk Gauge & Status */}
        <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Threat Classification
              </span>
              <span className={`px-2.5 py-1 rounded-full text-xs font-bold uppercase border ${getStatusColor(result.classification)}`}>
                {result.classification}
              </span>
            </div>

            {/* Circular Gauge Representation */}
            <div className="flex flex-col items-center justify-center my-6">
              <div className="relative w-44 h-44 flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                  <circle
                    cx="50"
                    cy="50"
                    r="40"
                    fill="transparent"
                    stroke="#1e293b"
                    strokeWidth="10"
                  />
                  <circle
                    cx="50"
                    cy="50"
                    r="40"
                    fill="transparent"
                    stroke={
                      result.risk_percentage >= 65 ? '#f43f5e' :
                      result.risk_percentage <= 35 ? '#10b981' : '#f59e0b'
                    }
                    strokeWidth="10"
                    strokeDasharray={251.2}
                    strokeDashoffset={251.2 - (251.2 * result.risk_percentage) / 100}
                    strokeLinecap="round"
                    className="transition-all duration-700 ease-out"
                  />
                </svg>
                <div className="absolute flex flex-col items-center text-center">
                  <span className="text-3xl font-extrabold text-white tracking-tight">
                    {result.risk_percentage}%
                  </span>
                  <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wide">
                    Malicious Risk
                  </span>
                </div>
              </div>

              {/* Benign Probability Counterpart */}
              <div className="mt-2 text-center">
                <span className="text-xs text-slate-400">
                  Estimated Benign Probability:{' '}
                  <span className="font-semibold text-emerald-400">{result.benign_percentage}%</span>
                </span>
              </div>
            </div>

            {/* Calibration & Conformal Prediction Badges */}
            <div className="space-y-2 pt-4 border-t border-slate-800">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">Prediction Confidence:</span>
                <span className="font-semibold text-slate-200 capitalize">{result.prediction_confidence}</span>
              </div>

              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400 flex items-center space-x-1">
                  <span>Conformal Set (95% Conf):</span>
                </span>
                <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 font-semibold">
                  {`{ ${result.conformal_prediction_set.join(', ')} }`}
                </span>
              </div>

              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">Uncertainty State:</span>
                <span className={`font-semibold capitalize ${
                  result.uncertainty_status === 'high' ? 'text-amber-400' : 'text-slate-200'
                }`}>
                  {result.uncertainty_status} Uncertainty
                </span>
              </div>

              {result.out_of_distribution && (
                <div className="mt-2 p-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-[11px] text-amber-300 flex items-start space-x-2">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                  <span>Out-of-Distribution Warning: URL features deviate significantly from baseline training corpus.</span>
                </div>
              )}
            </div>
          </div>

          {/* Action buttons */}
          <div className="mt-6 pt-4 border-t border-slate-800 flex items-center space-x-2">
            <button
              onClick={() => onSelectUrlForAdversarial(result.url)}
              className="flex-1 py-2 px-3 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 flex items-center justify-center space-x-1.5 transition-all cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span>Test in Adversarial Lab</span>
            </button>

            <button
              onClick={handleCopyResult}
              className="p-2 rounded-lg text-xs bg-slate-800 hover:bg-slate-750 text-slate-300 border border-slate-700 transition-all cursor-pointer"
              title="Copy JSON Assessment"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Right 2 Columns: Explainable Reasons & URL Structural Breakdown */}
        <div className="lg:col-span-2 space-y-6">
          {/* Destination & Redirect Chain Trace (Shown for shorteners or resolved redirects) */}
          {(result.features.is_shortener || result.effective_url !== result.url || result.redirect_info) && (
            <div className="bg-slate-900/70 border border-cyan-500/25 rounded-2xl p-5 shadow-xl space-y-3">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center space-x-2">
                  <GitBranch className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-semibold text-white">Redirect &amp; Destination Resolution</h3>
                </div>
                <div className="flex items-center space-x-2 text-[11px]">
                  <span className={`px-2 py-0.5 rounded font-semibold border ${
                    result.features.shortener_resolved
                      ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                      : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                  }`}>
                    {result.features.shortener_resolved ? 'Destination Resolved' : 'Unresolved / Offline Fallback'}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono">
                    {result.features.redirect_hop_count} Hop(s) &bull; {result.features.cross_domain_redirects} Cross-Domain
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-2 text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-slate-950/90 border border-slate-800 flex items-center justify-between gap-2">
                  <span className="text-slate-400 shrink-0 font-sans">Submitted URL:</span>
                  <span className="text-slate-200 truncate">{result.url}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950/90 border border-cyan-500/20 flex items-center justify-between gap-2">
                  <span className="text-cyan-400 shrink-0 font-sans font-medium">Evaluated Target:</span>
                  <span className="text-cyan-200 truncate">{result.effective_url}</span>
                </div>
              </div>
            </div>
          )}

          {/* Top Explainable Risk Factors */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <h3 className="text-sm font-semibold text-white mb-3 flex items-center justify-between">
              <span className="flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-blue-400" />
                <span>Explainable AI Risk Factors (Top Drivers)</span>
              </span>
              <span className="text-xs text-slate-400 font-normal">
                {result.top_reasons.length} Factors Identified
              </span>
            </h3>

            <div className="space-y-3">
              {result.top_reasons.map((reason, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/80 flex items-start justify-between gap-3"
                >
                  <div className="space-y-1">
                    <p className="text-xs text-slate-200 font-medium leading-relaxed">
                      {reason.text}
                    </p>
                    <div className="flex items-center space-x-2">
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">
                        Factor: {reason.factor}
                      </span>
                    </div>
                  </div>
                  <div>
                    {getSeverityBadge(reason.severity)}
                  </div>
                </div>
              ))}
            </div>

            {/* Recommendation Box */}
            <div className={`mt-5 p-4 rounded-xl border flex items-start space-x-3 ${
              result.classification === 'malicious' ? 'bg-rose-500/10 border-rose-500/20' :
              result.classification === 'legitimate' ? 'bg-emerald-500/10 border-emerald-500/20' :
              'bg-amber-500/10 border-amber-500/20'
            }`}>
              {result.classification === 'malicious' && <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />}
              {result.classification === 'legitimate' && <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />}
              {result.classification === 'uncertain' && <HelpCircle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />}

              <div>
                <h4 className="text-xs font-bold text-white mb-1">
                  {result.classification === 'malicious' ? 'Recommended Action: Block Connection' :
                   result.classification === 'legitimate' ? 'Recommended Action: Verified Safe to Browse' :
                   'Recommended Action: Exercise Caution (Ambiguous Evidence)'}
                </h4>
                <p className="text-xs text-slate-300">
                  {result.classification === 'malicious'
                    ? 'Do NOT enter credentials, submit two-factor authentication tokens, or download attachments from this URL.'
                    : result.classification === 'legitimate'
                    ? 'Link structure aligns with authentic registered domain infrastructure and lacks suspicious obfuscation.'
                    : 'The conformal coverage set contains both legitimate and malicious hypotheses. Inspect the destination carefully.'}
                </p>
              </div>
            </div>
          </div>

          {/* Extracted Structural Features Card */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 shadow-xl">
            <div
              className="flex items-center justify-between cursor-pointer"
              onClick={() => setShowRawFeatures(!showRawFeatures)}
            >
              <div className="flex items-center space-x-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-white">Extracted Structural URL Telemetry</h3>
              </div>
              <button className="text-slate-400 hover:text-white">
                {showRawFeatures ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
            </div>

            {showRawFeatures && (
              <div className="mt-4 pt-4 border-t border-slate-800 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">URL Length</span>
                  <span className="font-mono font-semibold text-white">{result.features.url_length} chars</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Shannon Entropy</span>
                  <span className="font-mono font-semibold text-cyan-300">{result.features.entropy} bits</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Subdomains Count</span>
                  <span className="font-mono font-semibold text-white">{result.features.num_subdomains}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Security Keywords</span>
                  <span className="font-mono font-semibold text-white">{result.features.num_keywords}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Punycode (xn--)</span>
                  <span className={`font-mono font-semibold ${result.features.is_punycode ? 'text-rose-400' : 'text-slate-400'}`}>
                    {result.features.is_punycode ? 'DETECTED' : 'None'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Homoglyph Confusables</span>
                  <span className={`font-mono font-semibold ${result.features.homoglyphs_count > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
                    {result.features.homoglyphs_count} found
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">IP Address Host</span>
                  <span className={`font-mono font-semibold ${result.features.is_ip ? 'text-rose-400' : 'text-slate-400'}`}>
                    {result.features.is_ip ? 'YES' : 'No'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Impersonated Brand</span>
                  <span className={`font-mono font-semibold ${result.features.impersonated_brand ? 'text-amber-400' : 'text-slate-400'}`}>
                    {result.features.impersonated_brand || 'None'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Max Path Entropy</span>
                  <span className="font-mono font-semibold text-cyan-300">{result.features.max_path_token_entropy} bits</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Encoded Payload (B64/Hex)</span>
                  <span className={`font-mono font-semibold ${result.features.has_encoded_payload ? 'text-rose-400' : 'text-slate-400'}`}>
                    {result.features.has_encoded_payload ? 'DETECTED' : 'None'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">DGA Consonant Anomaly</span>
                  <span className={`font-mono font-semibold ${result.features.consonant_cluster_anomaly ? 'text-amber-400' : 'text-slate-400'}`}>
                    {result.features.consonant_cluster_anomaly ? 'DETECTED' : 'Normal'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">TLS Downgrade / Port / @</span>
                  <span className={`font-mono font-semibold ${(result.features.protocol_downgrade || result.features.has_port_obfuscation || result.features.has_userinfo_at) ? 'text-rose-400' : 'text-slate-400'}`}>
                    {(result.features.protocol_downgrade || result.features.has_port_obfuscation || result.features.has_userinfo_at) ? 'FLAGGED' : 'Clean'}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
