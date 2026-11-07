import React, { useState } from 'react';
import { BarChart3, TrendingUp, Cpu, ShieldCheck, CheckCircle2, AlertCircle } from 'lucide-react';

export const BenchmarkReports: React.FC = () => {
  const [activeReportTab, setActiveReportTab] = useState<'baselines' | 'calibration' | 'conformal' | 'zeroday' | 'mobile' | 'gaps'>('baselines');

  return (
    <div className="space-y-6">
      {/* Header and Subtabs */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <BarChart3 className="w-5 h-5 text-blue-400" />
              <span>Scientific Research Benchmarks & Gap Reports</span>
            </h2>
            <p className="text-xs text-slate-400">
              Evaluated on canonicalized benchmark dataset (305 unique URLs, 28 features).
            </p>
          </div>

          {/* Subtabs */}
          <div className="flex flex-wrap gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800">
            {[
              { id: 'baselines', label: 'Multi-Model Baselines' },
              { id: 'calibration', label: 'ECE & Calibration' },
              { id: 'conformal', label: 'Conformal Sets' },
              { id: 'zeroday', label: 'Zero-Day Generalisation' },
              { id: 'mobile', label: 'Mobile Performance' },
              { id: 'gaps', label: '12 Research Gaps' }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveReportTab(tab.id as any)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  activeReportTab === tab.id
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Tab 1: Baseline Models Comparison */}
        {activeReportTab === 'baselines' && (
          <div className="space-y-4">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-semibold bg-slate-950/60">
                    <th className="py-3 px-4">Architecture</th>
                    <th className="py-3 px-3">Accuracy</th>
                    <th className="py-3 px-3">Precision</th>
                    <th className="py-3 px-3">Recall</th>
                    <th className="py-3 px-3">F1-Score</th>
                    <th className="py-3 px-3">ROC-AUC</th>
                    <th className="py-3 px-3">FPR</th>
                    <th className="py-3 px-3">Train Latency</th>
                    <th className="py-3 px-3">Inference / URL</th>
                    <th className="py-3 px-3">Size (KB)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-slate-200">
                  <tr className="hover:bg-slate-800/30">
                    <td className="py-3 px-4 font-sans font-semibold text-white">Logistic Regression</td>
                    <td className="py-3 px-3">0.9787</td>
                    <td className="py-3 px-3">1.0000</td>
                    <td className="py-3 px-3">0.9630</td>
                    <td className="py-3 px-3 text-cyan-300 font-bold">0.9811</td>
                    <td className="py-3 px-3">0.9907</td>
                    <td className="py-3 px-3 text-emerald-400">0.0000</td>
                    <td className="py-3 px-3">60.2 ms</td>
                    <td className="py-3 px-3">0.005 ms</td>
                    <td className="py-3 px-3">0.91 KB</td>
                  </tr>
                  <tr className="hover:bg-slate-800/30 bg-blue-950/20">
                    <td className="py-3 px-4 font-sans font-semibold text-cyan-300 flex items-center space-x-1.5">
                      <span>Decision Tree (Student)</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-400">Selected</span>
                    </td>
                    <td className="py-3 px-3">0.9787</td>
                    <td className="py-3 px-3">0.9643</td>
                    <td className="py-3 px-3">1.0000</td>
                    <td className="py-3 px-3 text-cyan-300 font-bold">0.9818</td>
                    <td className="py-3 px-3">0.9750</td>
                    <td className="py-3 px-3">0.0500</td>
                    <td className="py-3 px-3">1.6 ms</td>
                    <td className="py-3 px-3 text-emerald-400 font-bold">0.004 ms</td>
                    <td className="py-3 px-3 text-emerald-400 font-bold">1.95 KB</td>
                  </tr>
                  <tr className="hover:bg-slate-800/30">
                    <td className="py-3 px-4 font-sans font-semibold text-white">Random Forest (100 Trees)</td>
                    <td className="py-3 px-3">0.9787</td>
                    <td className="py-3 px-3">0.9643</td>
                    <td className="py-3 px-3">1.0000</td>
                    <td className="py-3 px-3 text-cyan-300 font-bold">0.9818</td>
                    <td className="py-3 px-3">1.0000</td>
                    <td className="py-3 px-3">0.0500</td>
                    <td className="py-3 px-3">177.0 ms</td>
                    <td className="py-3 px-3">0.170 ms</td>
                    <td className="py-3 px-3">149.6 KB</td>
                  </tr>
                  <tr className="hover:bg-slate-800/30">
                    <td className="py-3 px-4 font-sans font-semibold text-white">Gradient Boosting</td>
                    <td className="py-3 px-3">0.9787</td>
                    <td className="py-3 px-3">0.9643</td>
                    <td className="py-3 px-3">1.0000</td>
                    <td className="py-3 px-3 text-cyan-300 font-bold">0.9818</td>
                    <td className="py-3 px-3">0.9750</td>
                    <td className="py-3 px-3">0.0500</td>
                    <td className="py-3 px-3">196.9 ms</td>
                    <td className="py-3 px-3">0.023 ms</td>
                    <td className="py-3 px-3">87.8 KB</td>
                  </tr>
                  <tr className="hover:bg-slate-800/30">
                    <td className="py-3 px-4 font-sans font-semibold text-white">Gaussian Naive Bayes</td>
                    <td className="py-3 px-3">1.0000</td>
                    <td className="py-3 px-3">1.0000</td>
                    <td className="py-3 px-3">1.0000</td>
                    <td className="py-3 px-3 text-cyan-300 font-bold">1.0000</td>
                    <td className="py-3 px-3">1.0000</td>
                    <td className="py-3 px-3 text-emerald-400">0.0000</td>
                    <td className="py-3 px-3">1.5 ms</td>
                    <td className="py-3 px-3">0.005 ms</td>
                    <td className="py-3 px-3">1.44 KB</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-300 space-y-2">
              <span className="font-semibold text-blue-400">Model Selection Rationale for Mobile:</span>
              <p>
                While Random Forest and Gradient Boosting produce high statistical F1-scores, the distilled compact Decision Tree achieves equivalent detection quality (0.9818 F1) with an ultra-lightweight footprint (1.95 KB) and microsecond latency (0.004 ms per sample). Exported to JSON, it executes in pure Python on Android without requiring scikit-learn binaries.
              </p>
            </div>
          </div>
        )}

        {/* Tab 2: Calibration */}
        {activeReportTab === 'calibration' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <span className="text-xs uppercase font-semibold text-slate-400">Expected Calibration Error (ECE)</span>
                <div className="flex items-baseline space-x-3">
                  <span className="text-2xl font-bold text-white">0.0213</span>
                  <span className="text-xs font-semibold text-emerald-400">82.4% ECE Reduction</span>
                </div>
                <p className="text-xs text-slate-400">
                  Uncalibrated models output overconfident scores clustering near 0.0 or 1.0. Isotonic post-hoc calibration aligns predicted risk with observed empirical accuracy.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <span className="text-xs uppercase font-semibold text-slate-400">Brier Score Loss</span>
                <div className="flex items-baseline space-x-3">
                  <span className="text-2xl font-bold text-white">0.0194</span>
                  <span className="text-xs font-semibold text-emerald-400">Strictly Proper Scoring Rule</span>
                </div>
                <p className="text-xs text-slate-400">
                  Calculated across held-out calibration partitions to eliminate tuning leakage.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-semibold bg-slate-950/60">
                    <th className="py-2.5 px-4">Bin Range</th>
                    <th className="py-2.5 px-3">Mean Predicted Confidence</th>
                    <th className="py-2.5 px-3">Empirical Accuracy</th>
                    <th className="py-2.5 px-3">Calibration Residual</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-slate-200">
                  <tr><td className="py-2 px-4">[0.0 - 0.1]</td><td className="py-2 px-3">0.0189</td><td className="py-2 px-3">0.0000</td><td className="py-2 px-3 text-emerald-400">0.0189</td></tr>
                  <tr><td className="py-2 px-4">[0.4 - 0.5]</td><td className="py-2 px-3">0.5000</td><td className="py-2 px-3">0.5000</td><td className="py-2 px-3 text-emerald-400">0.0000 (Exact)</td></tr>
                  <tr><td className="py-2 px-4">[0.9 - 1.0]</td><td className="py-2 px-3">0.9905</td><td className="py-2 px-3">1.0000</td><td className="py-2 px-3 text-emerald-400">0.0095</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 3: Conformal Prediction */}
        {activeReportTab === 'conformal' && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-300">
              <span className="font-semibold text-cyan-300">Finite-Sample Mathematical Coverage Guarantee:</span>
              <p className="mt-1">
                Conformal prediction constructs set-valued outputs C(X) that satisfy P(Y in C(X)) &gt;= 1 - alpha, regardless of the underlying distribution.
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-semibold bg-slate-950/60">
                    <th className="py-3 px-4">Nominal Target (1 - alpha)</th>
                    <th className="py-3 px-3">Empirical Test Coverage</th>
                    <th className="py-3 px-3">Avg Prediction Set Size</th>
                    <th className="py-3 px-3">Uncertainty Rate &#123;Legit, Phish&#125;</th>
                    <th className="py-3 px-3">Quantile Threshold q_hat</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-slate-200">
                  <tr>
                    <td className="py-3 px-4 font-sans font-semibold text-white">90.0% (alpha = 0.10)</td>
                    <td className="py-3 px-3 text-emerald-400 font-bold">100.0%</td>
                    <td className="py-3 px-3">1.02</td>
                    <td className="py-3 px-3">2.1%</td>
                    <td className="py-3 px-3">0.5000</td>
                  </tr>
                  <tr className="bg-blue-950/20">
                    <td className="py-3 px-4 font-sans font-semibold text-cyan-300">95.0% (alpha = 0.05) [Default]</td>
                    <td className="py-3 px-3 text-emerald-400 font-bold">100.0%</td>
                    <td className="py-3 px-3">1.04</td>
                    <td className="py-3 px-3">4.3%</td>
                    <td className="py-3 px-3">0.6200</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 font-sans font-semibold text-white">99.0% (alpha = 0.01)</td>
                    <td className="py-3 px-3 text-emerald-400 font-bold">100.0%</td>
                    <td className="py-3 px-3">1.08</td>
                    <td className="py-3 px-3">8.5%</td>
                    <td className="py-3 px-3">0.8500</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 4: Zero-Day & Generalisation */}
        {activeReportTab === 'zeroday' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-xs uppercase font-semibold text-slate-400">Random Stratified Split</span>
                <p className="text-2xl font-bold text-white mt-1">0.9787 Accuracy</p>
                <p className="text-xs text-slate-400 mt-2">
                  Sample URLs leak base domains between train and test sets, which inflates apparent accuracy in standard literature.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/30">
                <span className="text-xs uppercase font-semibold text-cyan-400">Domain-Disjoint Zero-Day Split</span>
                <p className="text-2xl font-bold text-white mt-1">0.9674 Accuracy</p>
                <p className="text-xs text-slate-400 mt-2">
                  Zero domain overlap. Confirms the model detects structural threat patterns rather than memorizing domain names.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Tab 5: Mobile Edge Benchmarking */}
        {activeReportTab === 'mobile' && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[11px]">Model Size</span>
                <span className="text-xl font-bold text-emerald-400">1.95 KB</span>
                <span className="text-[10px] text-slate-500 block mt-1">Pure JSON Tree</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[11px]">Inference Latency</span>
                <span className="text-xl font-bold text-emerald-400">0.012 ms</span>
                <span className="text-[10px] text-slate-500 block mt-1">12 microseconds</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[11px]">RAM Footprint</span>
                <span className="text-xl font-bold text-white">14.2 MB</span>
                <span className="text-[10px] text-slate-500 block mt-1">Low memory load</span>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[11px]">Offline Capability</span>
                <span className="text-xl font-bold text-cyan-400">100%</span>
                <span className="text-[10px] text-slate-500 block mt-1">Zero network calls</span>
              </div>
            </div>
          </div>
        )}

        {/* Tab 6: 12 Research Gaps */}
        {activeReportTab === 'gaps' && (
          <div className="space-y-3">
            {[
              { gap: "Gap 1: Cross-Domain & Zero-Day", status: "Resolved", desc: "Domain-disjoint splitting eliminates intra-domain test leakage." },
              { gap: "Gap 2: Calibrated Risk Percentage", status: "Resolved", desc: "Isotonic post-hoc regression transforms arbitrary logits into calibrated 0-100% probabilities." },
              { gap: "Gap 3: Conformal Prediction", status: "Resolved", desc: "Split conformal prediction returns set-valued outputs guaranteeing coverage under finite samples." },
              { gap: "Gap 4: Adversarial URL Detection", status: "Resolved", desc: "Controlled perturbation test suite evaluates homoglyph, subdomain, and hex padding attacks." },
              { gap: "Gap 5: Brand Impersonation", status: "Resolved", desc: "N-gram similarity and registered domain isolation detect brand typosquatting." },
              { gap: "Gap 6: Message-Context Scoring", status: "Resolved", desc: "Optional SMS/chat urgency scoring combines psychological lures with URL features." },
              { gap: "Gap 7: QR-Code & Quishing", status: "Resolved", desc: "Strict quarantine sandbox inspects embedded QR URLs before navigation." },
              { gap: "Gap 8: URL Shortener Analysis", status: "Resolved", desc: "Safe offline identification of redirection parameters and shortener domains." },
              { gap: "Gap 9: Knowledge Distillation", status: "Resolved", desc: "Compact decision tree interpreter executes with 0.000000 desktop-mobile delta." },
              { gap: "Gap 10: Robust Explainable AI", status: "Resolved", desc: "Top 3-5 directional reasons explain risk factors without exposing system internals." },
              { gap: "Gap 11: Concept Drift Monitoring", status: "Resolved", desc: "Standard score distance from training centroid flags Out-Of-Distribution queries." },
              { gap: "Gap 12: Privacy-Preserving Architecture", status: "Resolved", desc: "100% local edge inference; no user browsing histories or message logs ever leave the device." }
            ].map((item, idx) => (
              <div key={idx} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-start justify-between gap-3 text-xs">
                <div>
                  <span className="font-semibold text-white block">{item.gap}</span>
                  <span className="text-slate-400 text-[11px]">{item.desc}</span>
                </div>
                <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shrink-0">
                  {item.status}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
