import React, { useState } from 'react';
import { Globe, ArrowRight, Shield, AlertTriangle, Sparkles, Terminal } from 'lucide-react';

interface UrlScannerTabProps {
  onScan: (url: string) => Promise<void>;
  isLoading: boolean;
}

const PRESET_URLS = [
  {
    label: 'PayPal Lookalike',
    category: 'Phishing',
    url: 'https://paypa1-account-security-update.xyz/webscr/login?cmd=_session'
  },
  {
    label: 'USPS Delivery Courier',
    category: 'Smishing Domain',
    url: 'https://us-postal-redeliver.top/tracking/94001'
  },
  {
    label: 'Microsoft 365 Harvester',
    category: 'Credential Harvester',
    url: 'https://login.micros0ft-verify-account.com/auth/session-renew'
  },
  {
    label: 'Direct IP Host',
    category: 'Suspicious IP',
    url: 'http://185.220.101.5/banking/authenticate.php'
  },
  {
    label: 'Google Docs',
    category: 'Legitimate',
    url: 'https://docs.google.com/document/d/1yR4wX_presentation/edit'
  },
  {
    label: 'GitHub Official',
    category: 'Legitimate',
    url: 'https://github.com/torvalds/linux'
  }
];

export const UrlScannerTab: React.FC<UrlScannerTabProps> = ({ onScan, isLoading }) => {
  const [urlInput, setUrlInput] = useState('');
  const [inputError, setInputError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) {
      setInputError('Please enter a target URL to analyze.');
      return;
    }
    setInputError(null);
    onScan(urlInput.trim());
  };

  const handleSelectPreset = (url: string) => {
    setUrlInput(url);
    setInputError(null);
  };

  return (
    <div className="space-y-6">
      {/* Scanner Card */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-800/80 mb-5">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-red-400" />
              URL & Web Infrastructure Scanner
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Deep lexical analysis, domain entropy, typosquatting homoglyphs, and AI threat modeling.
            </p>
          </div>
          <div className="text-xs text-slate-500 font-mono">
            RFC-3986 Sanitized & Protected
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <Globe className="w-5 h-5" />
            </div>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => {
                setUrlInput(e.target.value);
                if (inputError) setInputError(null);
              }}
              placeholder="e.g. https://account-verification-paypal.top/login or paste any suspicious link"
              className="w-full pl-11 pr-32 py-3.5 bg-slate-950 border border-slate-700/80 rounded-lg text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500 font-mono transition-all"
              disabled={isLoading}
            />
            <div className="absolute inset-y-1.5 right-1.5 flex items-center">
              <button
                type="submit"
                disabled={isLoading}
                className="h-full px-5 bg-red-600 hover:bg-red-500 disabled:bg-slate-800 text-white text-xs font-semibold rounded-md transition-colors flex items-center gap-2 shadow-sm"
              >
                {isLoading ? (
                  <>
                    <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <span>Inspect Target</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            </div>
          </div>

          {inputError && (
            <div className="text-xs text-red-400 flex items-center gap-1.5 pl-1">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              {inputError}
            </div>
          )}
        </form>

        {/* Preset Sample Targets */}
        <div className="mt-6 pt-5 border-t border-slate-800/60">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-3">
            <span className="font-medium text-slate-300">Quick Test Scenarios:</span>
            <span className="text-[11px] text-slate-500">Click to populate target</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {PRESET_URLS.map((preset, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSelectPreset(preset.url)}
                className="text-left p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 hover:bg-slate-950 transition-all group"
              >
                <div className="flex items-center justify-between gap-1 mb-1">
                  <span className="text-xs font-medium text-slate-200 group-hover:text-red-300 transition-colors">
                    {preset.label}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">
                    {preset.category}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 font-mono truncate group-hover:text-slate-400">
                  {preset.url}
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Safety Notice Strip */}
      <div className="bg-slate-900/30 border border-slate-800/60 rounded-lg p-4 flex items-start gap-3">
        <Shield className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-400 leading-relaxed">
          <strong className="text-slate-300 font-semibold">Zero-Execution Sandbox Guarantee:</strong> PhishGuard never requests or executes malicious web payloads directly in the browser or on backend hosts. Submitted URLs are statically inspected using cryptographic entropy math, lexical pattern vectors, and server-side threat intelligence models.
        </div>
      </div>
    </div>
  );
};
