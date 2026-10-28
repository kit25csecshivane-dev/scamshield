import React, { useState } from 'react';
import { 
  Search, Filter, Bookmark, Trash2, Download, ExternalLink, 
  ShieldAlert, ShieldCheck, AlertTriangle, FileSpreadsheet, RefreshCw 
} from 'lucide-react';
import { ScanResult, ScanType } from '../types/threat.js';

interface HistoryViewProps {
  scans: ScanResult[];
  onSelectScan: (scan: ScanResult) => void;
  onDeleteScan: (id: string) => Promise<void>;
  onToggleStar: (id: string) => Promise<void>;
  onRefresh: () => void;
  onNavigateScanner: () => void;
}

export const HistoryView: React.FC<HistoryViewProps> = ({
  scans,
  onSelectScan,
  onDeleteScan,
  onToggleStar,
  onRefresh,
  onNavigateScanner
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<'ALL' | ScanType>('ALL');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [starredOnly, setStarredOnly] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const filteredScans = scans.filter((s) => {
    if (typeFilter !== 'ALL' && s.type !== typeFilter) return false;
    if (verdictFilter !== 'ALL' && s.verdict !== verdictFilter) return false;
    if (starredOnly && !s.starred) return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const matchTarget = s.target.toLowerCase().includes(q);
      const matchType = s.threatType.toLowerCase().includes(q);
      const matchBrand = s.impersonatedEntity?.toLowerCase().includes(q);
      if (!matchTarget && !matchType && !matchBrand) return false;
    }
    return true;
  });

  const handleExportCsv = () => {
    if (filteredScans.length === 0) return;
    const headers = ['ID', 'Timestamp', 'Type', 'Target', 'RiskScore', 'Verdict', 'ThreatType', 'ImpersonatedBrand'];
    const rows = filteredScans.map(s => [
      s.id,
      s.timestamp,
      s.type,
      `"${s.target.replace(/"/g, '""')}"`,
      s.riskScore,
      s.verdict,
      `"${s.threatType.replace(/"/g, '""')}"`,
      `"${(s.impersonatedEntity || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `phishguard-scans-export-${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleExportJson = () => {
    if (filteredScans.length === 0) return;
    const jsonStr = JSON.stringify(filteredScans, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-scans-export-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    if (confirm('Are you sure you want to delete this scan report?')) {
      setDeletingId(id);
      await onDeleteScan(id);
      setDeletingId(null);
    }
  };

  const handleStar = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    await onToggleStar(id);
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            Historical Scan Database
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Persisted forensic reports, threat intelligence classifications, and bookmarked investigations.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto text-xs">
          <button
            onClick={onRefresh}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:text-white text-slate-300 rounded-md transition-colors"
            title="Refresh Scan List"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>

          <button
            onClick={handleExportCsv}
            disabled={filteredScans.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:text-white text-slate-300 disabled:opacity-50 rounded-md transition-colors"
          >
            <FileSpreadsheet className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>

          <button
            onClick={handleExportJson}
            disabled={filteredScans.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:text-white text-slate-300 disabled:opacity-50 rounded-md transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>JSON</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 shadow-sm space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          
          {/* Search Box */}
          <div className="relative md:col-span-2">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 transform -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by URL, message keywords, brand..."
              className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-red-500"
            />
          </div>

          {/* Type Filter */}
          <div>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value as any)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-red-500"
            >
              <option value="ALL">All Media Types</option>
              <option value="url">URLs Only</option>
              <option value="message">Messages Only</option>
            </select>
          </div>

          {/* Verdict Filter */}
          <div>
            <select
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-red-500"
            >
              <option value="ALL">All Threat Verdicts</option>
              <option value="MALICIOUS_PHISHING">Malicious Phishing</option>
              <option value="HIGH_RISK">High Risk</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="SAFE">Safe / Low Risk</option>
            </select>
          </div>

        </div>

        {/* Quick Starred Toggle & Counter */}
        <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-xs">
          <button
            onClick={() => setStarredOnly(!starredOnly)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded transition-colors ${
              starredOnly
                ? 'bg-amber-500/20 text-amber-300 font-medium'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Bookmark className="w-3.5 h-3.5" fill={starredOnly ? 'currentColor' : 'none'} />
            <span>Bookmarked Cases Only</span>
          </button>

          <span className="text-slate-500 font-mono text-[11px]">
            Showing <strong className="text-slate-300 tabular-nums">{filteredScans.length}</strong> of{' '}
            <span className="tabular-nums">{scans.length}</span> records
          </span>
        </div>
      </div>

      {/* Scans Table View */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {filteredScans.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <p className="text-sm text-slate-400">
              No scan logs match your search or filter criteria.
            </p>
            <button
              onClick={onNavigateScanner}
              className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-md text-xs font-semibold transition-colors"
            >
              Run a New Scan
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 font-mono border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4 w-10">★</th>
                  <th className="py-3 px-4">Target Asset</th>
                  <th className="py-3 px-4 w-28">Type</th>
                  <th className="py-3 px-4 w-44">Classification</th>
                  <th className="py-3 px-4 w-24 text-right">Risk Score</th>
                  <th className="py-3 px-4 w-32">Timestamp</th>
                  <th className="py-3 px-4 w-20 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredScans.map((scan) => {
                  const isMalicious = scan.riskScore >= 51;
                  return (
                    <tr
                      key={scan.id}
                      onClick={() => onSelectScan(scan)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors group"
                    >
                      {/* Star */}
                      <td className="py-3.5 px-4">
                        <button
                          onClick={(e) => handleStar(e, scan.id)}
                          className={`hover:text-amber-400 transition-colors ${
                            scan.starred ? 'text-amber-400' : 'text-slate-600'
                          }`}
                        >
                          <Bookmark className="w-3.5 h-3.5" fill={scan.starred ? 'currentColor' : 'none'} />
                        </button>
                      </td>

                      {/* Target */}
                      <td className="py-3.5 px-4 font-sans max-w-xs sm:max-w-md">
                        <div className="font-mono text-slate-200 text-xs truncate group-hover:text-white transition-colors">
                          {scan.target}
                        </div>
                        {scan.impersonatedEntity && (
                          <div className="text-[11px] text-red-400 font-sans mt-0.5">
                            Targeting: {scan.impersonatedEntity}
                          </div>
                        )}
                      </td>

                      {/* Type */}
                      <td className="py-3.5 px-4 text-slate-400 uppercase text-[11px]">
                        {scan.type}
                        {scan.subtype && <span className="text-slate-600">/{scan.subtype}</span>}
                      </td>

                      {/* Classification */}
                      <td className="py-3.5 px-4 font-sans">
                        <span className="text-xs text-slate-300 font-medium block truncate">
                          {scan.threatType}
                        </span>
                      </td>

                      {/* Risk Score */}
                      <td className="py-3.5 px-4 text-right">
                        <span className={`font-bold tabular-nums text-xs ${
                          isMalicious ? 'text-red-400' : 'text-emerald-400'
                        }`}>
                          {scan.riskScore}/100
                        </span>
                      </td>

                      {/* Timestamp */}
                      <td className="py-3.5 px-4 text-slate-500 text-[11px] tabular-nums">
                        {new Date(scan.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' })}
                        <span className="text-slate-600 block">
                          {new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={(e) => handleDelete(e, scan.id)}
                          disabled={deletingId === scan.id}
                          className="p-1 text-slate-600 hover:text-red-400 rounded transition-colors"
                          title="Delete Scan Record"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
