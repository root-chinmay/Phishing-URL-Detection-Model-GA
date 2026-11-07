import React, { useState } from 'react';
import { X, Github, Terminal, CheckCircle2, Copy, Check, ExternalLink, ArrowRight, Shield } from 'lucide-react';

interface DeploymentModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const DeploymentModal: React.FC<DeploymentModalProps> = ({
  isOpen,
  onClose
}) => {
  const [copiedCmd, setCopiedCmd] = useState(false);
  const repoUrl = "https://github.com/root-chinmay/Phishing-URL-Detection-Model-GA.git";

  if (!isOpen) return null;

  const pushCommand = `git remote set-url origin https://<YOUR_GITHUB_TOKEN>@github.com/root-chinmay/Phishing-URL-Detection-Model-GA.git\ngit branch -M main\ngit push -u origin main`;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full p-6 shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center space-x-3 mb-4">
          <div className="p-2.5 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Github className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white">GitHub Repository & Vercel Deployment</h3>
            <p className="text-xs text-slate-400">
              Target: <span className="font-mono text-cyan-400">{repoUrl}</span>
            </p>
          </div>
        </div>

        <div className="space-y-4 text-xs">
          {/* Status checklist */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
            <div className="flex items-center space-x-2 text-emerald-400">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Git repository initialized on branch <strong>main</strong></span>
            </div>
            <div className="flex items-center space-x-2 text-emerald-400">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Remote origin configured to <strong>{repoUrl}</strong></span>
            </div>
            <div className="flex items-center space-x-2 text-emerald-400">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Vercel zero-config file <strong>vercel.json</strong> prepared</span>
            </div>
            <div className="flex items-center space-x-2 text-emerald-400">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Full Python research suite & Android Buildozer specification committed</span>
            </div>
          </div>

          {/* How to push */}
          <div className="space-y-2">
            <span className="font-semibold text-white block">
              1. Push Code to GitHub with your Personal Access Token (PAT):
            </span>
            <p className="text-slate-400 text-[11px]">
              GitHub requires authentication (Personal Access Token with <code className="text-cyan-300">repo</code> scope) to push to remote repositories:
            </p>
            <div className="relative">
              <pre className="p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-[11px] text-slate-200 overflow-x-auto">
                {pushCommand}
              </pre>
              <button
                onClick={() => copyToClipboard(pushCommand)}
                className="absolute top-2 right-2 p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-all"
                title="Copy Command"
              >
                {copiedCmd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {/* Vercel deployment step */}
          <div className="space-y-2 pt-2 border-t border-slate-800">
            <span className="font-semibold text-white block">
              2. Deploy on Vercel:
            </span>
            <ol className="list-decimal list-inside space-y-1 text-slate-300 text-[11px]">
              <li>Go to <a href="https://vercel.com/new" target="_blank" rel="noreferrer" className="text-blue-400 hover:underline">vercel.com/new</a> and connect your GitHub account.</li>
              <li>Select repository: <code className="text-cyan-300">root-chinmay/Phishing-URL-Detection-Model-GA</code></li>
              <li>Vercel automatically detects the Vite framework and runs <code className="text-cyan-300">npm run build</code> producing the production bundle in <code className="text-cyan-300">dist/</code>.</li>
              <li>Click <strong>Deploy</strong> to get your live production URL!</li>
            </ol>
          </div>
        </div>

        <div className="mt-5 pt-4 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold"
          >
            Got it
          </button>
        </div>
      </div>
    </div>
  );
};
