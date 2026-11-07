import React, { useState, useRef } from 'react';
import { X, QrCode, Upload, ShieldCheck, AlertTriangle, ArrowRight } from 'lucide-react';
import jsQR from 'jsqr';

interface QRQuishingModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSendToScanner: (url: string) => void;
}

export const QRQuishingModal: React.FC<QRQuishingModalProps> = ({
  isOpen,
  onClose,
  onSendToScanner
}) => {
  const [decodedUrl, setDecodedUrl] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsProcessing(true);
    setErrorMsg(null);
    setDecodedUrl(null);

    const reader = new FileReader();
    reader.onload = (event) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        if (!ctx) {
          setErrorMsg("Could not create canvas context.");
          setIsProcessing(false);
          return;
        }

        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, img.width, img.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);

        if (code && code.data) {
          setDecodedUrl(code.data);
        } else {
          setErrorMsg("No readable QR code found in uploaded image.");
        }
        setIsProcessing(false);
      };
      img.onerror = () => {
        setErrorMsg("Failed to load image file.");
        setIsProcessing(false);
      };
      img.src = event.target?.result as string;
    };
    reader.readAsDataURL(file);
  };

  const handleSampleQR = (url: string) => {
    setDecodedUrl(url);
    setErrorMsg(null);
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center space-x-3 mb-4">
          <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <QrCode className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white">Safe QR / Quishing Scanner</h3>
            <p className="text-xs text-slate-400">
              Quarantine inspection isolates embedded URLs without automatic execution.
            </p>
          </div>
        </div>

        {/* Upload Drop Area */}
        <div
          onClick={() => fileInputRef.current?.click()}
          className="border-2 border-dashed border-slate-700 hover:border-purple-500/60 rounded-xl p-6 text-center cursor-pointer transition-all bg-slate-950/50"
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            accept="image/*"
            className="hidden"
          />
          <Upload className="w-8 h-8 text-slate-400 mx-auto mb-2" />
          <p className="text-xs font-medium text-slate-200">
            {isProcessing ? "Processing QR Code..." : "Click to select a QR code image file"}
          </p>
          <p className="text-[11px] text-slate-500 mt-1">PNG, JPG, WebP supported</p>
        </div>

        {/* Presets */}
        <div className="mt-4 pt-3 border-t border-slate-800">
          <span className="text-xs text-slate-400 font-medium block mb-2">Or test sample quishing payloads:</span>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => handleSampleQR("http://paypa1-account-verification-alert.com/login.php?cmd=verify")}
              className="px-2.5 py-1 rounded-lg text-xs bg-slate-800 hover:bg-slate-750 text-slate-300 border border-slate-700"
            >
              Phishing QR Sample
            </button>
            <button
              onClick={() => handleSampleQR("https://www.google.com/search?q=cybersecurity")}
              className="px-2.5 py-1 rounded-lg text-xs bg-slate-800 hover:bg-slate-750 text-slate-300 border border-slate-700"
            >
              Safe QR Sample
            </button>
          </div>
        </div>

        {/* Error message */}
        {errorMsg && (
          <div className="mt-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-xs text-rose-300 flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Decoded Quarantined Payload */}
        {decodedUrl && (
          <div className="mt-4 p-4 rounded-xl bg-slate-950 border border-purple-500/30 space-y-3">
            <div className="flex items-center justify-between text-xs font-semibold text-purple-300">
              <span className="flex items-center space-x-1.5">
                <ShieldCheck className="w-4 h-4" />
                <span>Quarantined Payload Extracted</span>
              </span>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-200">
                Safe Quarantine
              </span>
            </div>

            <p className="font-mono text-xs text-white break-all p-2.5 rounded-lg bg-slate-900 border border-slate-800">
              {decodedUrl}
            </p>

            <button
              onClick={() => {
                onSendToScanner(decodedUrl);
                onClose();
              }}
              className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center space-x-1.5 transition-all cursor-pointer"
            >
              <span>Analyze Extracted URL</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
