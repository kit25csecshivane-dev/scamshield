import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, AlertOctagon, 
  ArrowLeft, Download, Copy, Check, ExternalLink, Bookmark, 
  ChevronDown, ChevronUp, Terminal, Info, CornerDownRight
} from 'lucide-react';
import { ScanResult, ThreatSeverity } from '../types/threat.js';

interface ThreatResultViewProps {
  scan: ScanResult;
  onBack: () => void;
  onToggleStar?: (id: string) => void;
}

export const ThreatResultView: React.FC<ThreatResultViewProps> = ({
  scan,
  onBack,
  onToggleStar
}) => {
  const [copied, setCopied] = useState(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  const [isStarred, setIsStarred] = useState(!!scan.starred);

  const getVerdictTheme = (score: number) => {
    if (score >= 76) {
      return {
        label: 'CRITICAL PHISHING THREAT',
        bg: 'bg-red-950/40',
        border: 'border-red-500/50',
        text: 'text-red-400',
        badge: 'text-red-400 border-red-500/30 bg-red-500/10',
        ring: '#ef4444',
        icon: AlertOctagon
      };
    } else if (score >= 51) {
      return {
        label: 'HIGH RISK DETECTION',
        bg: 'bg-orange-950/40',
        border: 'border-orange-500/50',
        text: 'text-orange-400',
        badge: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
        ring: '#f97316',
        icon: AlertTriangle
      };
    } else if (score >= 21) {
      return {
        label: 'SUSPICIOUS / ELEVATED RISK',
        bg: 'bg-amber-950/40',
        border: 'border-amber-500/50',
        text: 'text-amber-400',
        badge: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
        ring: '#f59e0b',
        icon: AlertTriangle
      };
    } else {
      return {
        label: 'LOW RISK / BENIGN INDICATORS',
        bg: 'bg-emerald-950/40',
        border: 'border-emerald-500/50',
        text: 'text-emerald-400',
        badge: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
        ring: '#10b981',
        icon: ShieldCheck
      };
    }
  };

  const theme = getVerdictTheme(scan.riskScore);
  const VerdictIcon = theme.icon;

  const handleCopySummary = () => {
    const text = `PhishGuard Threat Forensic Report:
Target: ${scan.target}
Type: ${scan.type.toUpperCase()}
Risk Score: ${scan.riskScore}/100 (${scan.verdict})
Threat Type: ${scan.threatType}
Confidence: ${Math.round(scan.confidence * 100)}%
Impersonated: ${scan.impersonatedEntity || 'None detected'}
Indicators: ${scan.indicators.map(i => i.name).join(', ') || 'No elevated threat markers'}
Explanation: ${scan.explanation}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    const jsonStr = JSON.stringify(scan, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-report-${scan.id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleStarClick = () => {
    setIsStarred(!isStarred);
    if (onToggleStar) {
      onToggleStar(scan.id);
    }
  };

  const renderSeverityBadge = (sev: ThreatSeverity) => {
    switch (sev) {
      case 'critical':
        return <span className="text-[11px] font-mono text-red-400 font-semibold uppercase">CRITICAL</span>;
      case 'high':
        return <span className="text-[11px] font-mono text-orange-400 font-semibold uppercase">HIGH</span>;
      case 'medium':
        return <span className="text-[11px] font-mono text-amber-400 font-semibold uppercase">MEDIUM</span>;
      case 'low':
      default:
        return <span className="text-[11px] font-mono text-slate-400 font-semibold uppercase">LOW</span>;
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <button
          onClick={onBack}
          className="flex items-center gap-2 text-xs font-medium text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Scanner</span>
        </button>

        <div className="flex items-center gap-2 text-xs">
          <button
            onClick={handleStarClick}
            className={`p-2 rounded-md border transition-colors ${
              isStarred
                ? 'bg-amber-500/10 border-amber-500/40 text-amber-400'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
            }`}
            title={isStarred ? 'Saved to bookmarks' : 'Bookmark this scan'}
          >
            <Bookmark className="w-4 h-4" fill={isStarred ? 'currentColor' : 'none'} />
          </button>

          <button
            onClick={handleCopySummary}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-900 border border-slate-800 text-slate-300 hover:text-white transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Summary'}</span>
          </button>

          <button
            onClick={handleDownloadJson}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-900 border border-slate-800 text-slate-300 hover:text-white transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Primary Score & Verdict Card */}
      <div className={`rounded-xl border ${theme.border} ${theme.bg} p-6 sm:p-8 relative overflow-hidden backdrop-blur-sm shadow-xl`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          
          {/* Left: Verdict and Classification */}
          <div className="space-y-3 flex-1">
            <div className="flex items-center gap-2 text-xs font-mono tracking-wider text-slate-400">
              <span>SCAN ID: {scan.id}</span>
              <span aria-hidden="true">·</span>
              <span className="capitalize">{scan.type} Analysis</span>
              <span aria-hidden="true">·</span>
              <span className="tabular-nums font-mono">{new Date(scan.timestamp).toLocaleTimeString()}</span>
            </div>

            <div className="flex items-center gap-3">
              <VerdictIcon className={`w-8 h-8 ${theme.text} shrink-0`} />
              <div>
                <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white leading-tight">
                  {theme.label}
                </h1>
                <p className="text-sm font-medium text-slate-300 mt-0.5">
                  {scan.threatType}
                </p>
              </div>
            </div>

            {/* Target Display */}
            <div className="pt-2">
              <div className="text-xs text-slate-400 mb-1 font-mono">Target Subject:</div>
              <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 break-all select-all">
                {scan.target}
              </div>
            </div>

            {scan.impersonatedEntity && (
              <div className="flex items-center gap-2 text-xs text-slate-300">
                <span className="text-slate-400">Targeted Brand / Entity:</span>
                <span className="font-semibold text-red-300 bg-red-950/60 border border-red-800/60 px-2 py-0.5 rounded text-[11px] font-mono">
                  {scan.impersonatedEntity}
                </span>
              </div>
            )}
          </div>

          {/* Right: Circular Gauge Metric */}
          <div className="flex flex-col items-center justify-center shrink-0 self-center md:self-auto p-4 bg-slate-950/60 border border-slate-800/80 rounded-xl">
            <div className="relative w-32 h-32 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                {/* Background Ring */}
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  strokeWidth="8"
                  stroke="currentColor"
                  fill="transparent"
                  className="text-slate-800"
                />
                {/* Animated Progress Ring */}
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  strokeWidth="8"
                  stroke={theme.ring}
                  fill="transparent"
                  strokeDasharray={263.89}
                  strokeDashoffset={263.89 - (263.89 * scan.riskScore) / 100}
                  strokeLinecap="round"
                  className="transition-all duration-1000 ease-out"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-3xl font-extrabold font-mono tabular-nums text-white leading-none">
                  {scan.riskScore}
                </span>
                <span className="text-[10px] font-mono text-slate-400 mt-1 uppercase">
                  / 100 Risk
                </span>
              </div>
            </div>

            <div className="mt-2 text-center">
              <span className="text-[11px] text-slate-400 font-mono">
                Model Confidence: <span className="text-slate-200 tabular-nums font-semibold">{Math.round(scan.confidence * 100)}%</span>
              </span>
            </div>
          </div>

        </div>
      </div>

      {/* Mandatory Uncertainty & Limitations Disclosure */}
      <div className="p-4 bg-slate-900/40 border border-slate-800/80 rounded-lg flex items-start gap-3 text-xs leading-relaxed text-slate-400">
        <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-slate-200 font-semibold block mb-0.5">
            Cybersecurity Risk & Uncertainty Notice:
          </strong>
          {scan.uncertaintyCaveat}
        </div>
      </div>

      {/* Explanation Narrative */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-md">
        <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
          <span>Threat Mechanism & Analytical Breakdown</span>
        </h3>
        <p className="text-sm text-slate-300 leading-relaxed font-sans">
          {scan.explanation}
        </p>
      </div>

      {/* Identified Threat Indicators */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-md">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
          <h3 className="text-sm font-semibold text-white">
            Identified Threat Indicators ({scan.indicators.length})
          </h3>
          <span className="text-xs text-slate-500 font-mono">
            Structural & Behavioral Vector Matches
          </span>
        </div>

        {scan.indicators.length === 0 ? (
          <div className="py-6 text-center text-slate-400 text-xs">
            No malicious or suspicious indicators were matched in this target.
          </div>
        ) : (
          <div className="space-y-3">
            {scan.indicators.map((indicator, index) => (
              <div 
                key={indicator.id || index}
                className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800/90 hover:border-slate-700/80 transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-1.5">
                  <div className="flex items-center gap-2.5">
                    {renderSeverityBadge(indicator.severity)}
                    <span className="text-xs font-semibold text-slate-200">
                      {indicator.name}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 uppercase">
                    Vector: {indicator.category}
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">
                  {indicator.description}
                </p>

                {indicator.evidence && (
                  <div className="mt-2 text-[11px] font-mono text-slate-400 bg-slate-900/80 px-2.5 py-1.5 rounded border border-slate-800/60 flex items-start gap-1.5 break-all">
                    <CornerDownRight className="w-3 h-3 text-red-400 shrink-0 mt-0.5" />
                    <span>Evidence: <strong className="text-slate-300 font-normal">{indicator.evidence}</strong></span>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Actionable Recommendations */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-md">
        <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400" />
          <span>Recommended Safety & SOC Response Actions</span>
        </h3>

        <ul className="space-y-2.5 text-xs text-slate-300">
          {scan.recommendedActions.map((action, idx) => (
            <li key={idx} className="flex items-start gap-2.5">
              <span className="w-4 h-4 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center shrink-0 font-mono text-[10px] mt-0.5">
                {idx + 1}
              </span>
              <span className="leading-relaxed">{action}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Technical Forensics Drawer Toggle */}
      <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden">
        <button
          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
          className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-slate-900/60 transition-colors"
        >
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200 font-mono">
            <Terminal className="w-4 h-4 text-slate-400" />
            <span>Raw Forensic Telemetry & Machine Learning Vector Weights</span>
          </div>
          {showTechnicalDetails ? (
            <ChevronUp className="w-4 h-4 text-slate-400" />
          ) : (
            <ChevronDown className="w-4 h-4 text-slate-400" />
          )}
        </button>

        {showTechnicalDetails && (
          <div className="px-6 pb-6 pt-2 border-t border-slate-800/80 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-950 rounded border border-slate-800">
                <span className="text-slate-500 block text-[11px]">Domain Shannon Entropy</span>
                <span className="text-slate-200 text-sm font-bold tabular-nums">
                  {scan.technicalDetails.entropy ? scan.technicalDetails.entropy.toFixed(3) : 'N/A'}
                </span>
                <span className="text-[10px] text-slate-500 block mt-0.5">Threshold: &gt; 3.8</span>
              </div>

              <div className="p-3 bg-slate-950 rounded border border-slate-800">
                <span className="text-slate-500 block text-[11px]">Direct IP Host</span>
                <span className={`text-sm font-bold ${scan.technicalDetails.hasIpHost ? 'text-red-400' : 'text-emerald-400'}`}>
                  {scan.technicalDetails.hasIpHost ? 'TRUE (Direct IP)' : 'FALSE (Registered FQDN)'}
                </span>
              </div>

              <div className="p-3 bg-slate-950 rounded border border-slate-800">
                <span className="text-slate-500 block text-[11px]">Punycode Homoglyph</span>
                <span className={`text-sm font-bold ${scan.technicalDetails.isPunycode ? 'text-red-400' : 'text-emerald-400'}`}>
                  {scan.technicalDetails.isPunycode ? 'TRUE (xn-- detected)' : 'FALSE (Standard ASCII)'}
                </span>
              </div>

              <div className="p-3 bg-slate-950 rounded border border-slate-800">
                <span className="text-slate-500 block text-[11px]">Subdomain Levels</span>
                <span className="text-slate-200 text-sm font-bold tabular-nums">
                  {scan.technicalDetails.subdomainCount || 0}
                </span>
              </div>

              <div className="p-3 bg-slate-950 rounded border border-slate-800">
                <span className="text-slate-500 block text-[11px]">Suspicious TLD Flag</span>
                <span className={`text-sm font-bold ${scan.technicalDetails.suspiciousTld ? 'text-amber-400' : 'text-slate-200'}`}>
                  {scan.technicalDetails.suspiciousTld ? `.${scan.technicalDetails.suspiciousTld}` : 'Standard / Clean'}
                </span>
              </div>

              <div className="p-3 bg-slate-950 rounded border border-slate-800">
                <span className="text-slate-500 block text-[11px]">Inference Engine Pipeline</span>
                <span className="text-slate-200 text-sm font-bold">
                  {scan.engineUsed === 'gemini-ai' ? 'Gemini 3.8 Flash' : 'Local Heuristic + LR'}
                </span>
              </div>
            </div>

            {/* Baseline ML Model Scores if available */}
            {scan.mlBaseline && (
              <div className="p-4 bg-slate-950 rounded-lg border border-slate-800">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-slate-300 font-mono">
                    Deterministic Baseline Classifier Score:
                  </span>
                  <span className="text-xs font-mono font-bold text-red-300 tabular-nums">
                    {scan.mlBaseline.score}/100 ({scan.mlBaseline.verdict})
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 font-mono">
                  Calculated via calibrated L2-Logistic Regression on 13 structural feature vectors.
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
