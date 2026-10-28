import React from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Activity, 
  BarChart3, TrendingUp, ArrowUpRight, Clock, ExternalLink 
} from 'lucide-react';
import { ScanSummaryStats, ScanResult } from '../types/threat.js';

interface DashboardViewProps {
  stats: ScanSummaryStats | null;
  recentScans: ScanResult[];
  onSelectScan: (scan: ScanResult) => void;
  onNavigateScanner: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  stats,
  recentScans,
  onSelectScan,
  onNavigateScanner
}) => {
  if (!stats) {
    return (
      <div className="p-12 text-center text-slate-500 font-mono text-sm">
        <div className="w-6 h-6 border-2 border-red-500/30 border-t-red-500 rounded-full animate-spin mx-auto mb-3" />
        Loading Threat Operations Metrics...
      </div>
    );
  }

  const threatRate = stats.totalScans > 0 
    ? Math.round(((stats.maliciousCount + stats.highRiskCount) / stats.totalScans) * 100) 
    : 0;

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      {/* Top Banner & Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-red-500" />
            Security Operations Threat Telemetry
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time scan analytics, phishing signature distribution, and calibrated threat intelligence.
          </p>
        </div>

        <button
          onClick={onNavigateScanner}
          className="flex items-center gap-2 px-3.5 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded-md text-xs font-semibold self-start sm:self-auto transition-colors"
        >
          <span>Launch New Scan</span>
          <ArrowUpRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm">
          <div className="text-xs font-medium text-slate-400 mb-1 flex items-center justify-between">
            <span>Total Targets Inspected</span>
            <Activity className="w-4 h-4 text-slate-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-white tabular-nums">
            {stats.totalScans}
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">
            All URLs and messages
          </div>
        </div>

        {/* Metric 2 */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm">
          <div className="text-xs font-medium text-slate-400 mb-1 flex items-center justify-between">
            <span>Phishing & Malicious Blocked</span>
            <ShieldAlert className="w-4 h-4 text-red-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400 tabular-nums">
            {stats.maliciousCount + stats.highRiskCount}
          </div>
          <div className="text-[11px] text-red-400/80 font-mono mt-1">
            {threatRate}% threat detection rate
          </div>
        </div>

        {/* Metric 3 */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm">
          <div className="text-xs font-medium text-slate-400 mb-1 flex items-center justify-between">
            <span>Benign / Low Risk</span>
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 tabular-nums">
            {stats.safeCount}
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">
            Validated authentic infrastructure
          </div>
        </div>

        {/* Metric 4 */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm">
          <div className="text-xs font-medium text-slate-400 mb-1 flex items-center justify-between">
            <span>Average Threat Score</span>
            <TrendingUp className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 tabular-nums">
            {stats.averageRiskScore}
            <span className="text-sm text-slate-500 font-normal"> / 100</span>
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">
            Calibrated across dataset
          </div>
        </div>
      </div>

      {/* Grid: Attack Types & 7-Day Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Attack Vector Distribution */}
        <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-red-400" />
              Threat Category Breakdown
            </h2>
            <span className="text-xs font-mono text-slate-500">
              Aggregated Telemetry
            </span>
          </div>

          <div className="space-y-3 pt-1">
            {Object.entries(stats.threatTypeCounts).length === 0 ? (
              <div className="text-xs text-slate-500 py-4 text-center font-mono">
                No threat records logged yet.
              </div>
            ) : (
              Object.entries(stats.threatTypeCounts).map(([type, count]) => {
                const pct = stats.totalScans > 0 ? Math.round((count / stats.totalScans) * 100) : 0;
                return (
                  <div key={type} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-300 font-medium truncate max-w-[280px]">
                        {type}
                      </span>
                      <span className="font-mono text-slate-400 tabular-nums">
                        {count} <span className="text-slate-600">({pct}%)</span>
                      </span>
                    </div>
                    <div className="h-2 w-full bg-slate-950 rounded-full overflow-hidden border border-slate-800/80">
                      <div 
                        className="h-full bg-red-500/80 rounded-full transition-all duration-500"
                        style={{ width: `${Math.max(4, pct)}%` }}
                      />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* 7-Day Activity Feed */}
        <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-slate-400" />
              7-Day Activity & Threat Trends
            </h2>
            <span className="text-xs font-mono text-slate-500">
              Daily Scan Volume
            </span>
          </div>

          <div className="space-y-3 pt-2">
            {stats.scansOverTime.map((day) => (
              <div key={day.date} className="flex items-center gap-4 text-xs font-mono">
                <span className="w-24 text-slate-400 shrink-0">{day.date}</span>
                <div className="flex-1 flex items-center gap-2">
                  <div className="h-4 flex-1 bg-slate-950 rounded overflow-hidden flex border border-slate-800">
                    <div
                      className="bg-red-500/80 h-full transition-all"
                      style={{ width: `${day.count > 0 ? (day.threats / day.count) * 100 : 0}%` }}
                      title={`${day.threats} threats`}
                    />
                    <div
                      className="bg-slate-700/60 h-full transition-all"
                      style={{ width: `${day.count > 0 ? ((day.count - day.threats) / day.count) * 100 : 0}%` }}
                      title={`${day.count - day.threats} clean`}
                    />
                  </div>
                </div>
                <span className="w-16 text-right text-slate-300 font-semibold tabular-nums shrink-0">
                  {day.count} <span className="text-slate-500 font-normal">scans</span>
                </span>
              </div>
            ))}
          </div>

          <div className="flex items-center justify-end gap-4 pt-2 text-[11px] font-mono text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-red-500/80 inline-block" />
              Malicious Detections
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-slate-700/60 inline-block" />
              Benign / Clean
            </span>
          </div>
        </div>

      </div>

      {/* Recent Activity Table */}
      <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-white">
              Recent Incident Stream
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Click any incident to open full forensic threat analysis.
            </p>
          </div>
          <span className="text-xs text-slate-500 font-mono">
            Latest {recentScans.slice(0, 5).length} Scans
          </span>
        </div>

        <div className="divide-y divide-slate-800/60">
          {recentScans.slice(0, 6).map((scan) => {
            const isMalicious = scan.riskScore >= 51;
            return (
              <div
                key={scan.id}
                onClick={() => onSelectScan(scan)}
                className="py-3 px-2 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-800/40 rounded-lg cursor-pointer transition-colors group"
              >
                <div className="space-y-1 min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono uppercase text-slate-400">
                      [{scan.type}]
                    </span>
                    <span className="text-xs font-semibold text-slate-200 group-hover:text-red-300 transition-colors">
                      {scan.threatType}
                    </span>
                    {scan.impersonatedEntity && (
                      <span className="text-[10px] text-red-400 font-mono">
                        · Impersonating {scan.impersonatedEntity}
                      </span>
                    )}
                  </div>
                  <div className="text-xs font-mono text-slate-400 truncate max-w-xl">
                    {scan.target}
                  </div>
                </div>

                <div className="flex items-center gap-4 shrink-0">
                  <div className="text-right">
                    <div className={`text-xs font-mono font-bold tabular-nums ${isMalicious ? 'text-red-400' : 'text-emerald-400'}`}>
                      {scan.riskScore}/100
                    </div>
                    <div className="text-[10px] text-slate-500 font-mono">
                      {new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </div>
                  </div>
                  <ExternalLink className="w-4 h-4 text-slate-500 group-hover:text-slate-300 transition-colors" />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
