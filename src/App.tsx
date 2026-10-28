import React, { useState, useEffect } from 'react';
import { Navbar, ActiveTab } from './components/Navbar.js';
import { UrlScannerTab } from './components/UrlScannerTab.js';
import { MessageScannerTab } from './components/MessageScannerTab.js';
import { ThreatResultView } from './components/ThreatResultView.js';
import { DashboardView } from './components/DashboardView.js';
import { HistoryView } from './components/HistoryView.js';
import { MlBenchmarkView } from './components/MlBenchmarkView.js';
import { EducationalRadar } from './components/EducationalRadar.js';
import { ScanResult, ScanSummaryStats, MessageSubtype } from './types/threat.js';
import { Globe, Mail, AlertCircle, ShieldAlert } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('scanner');
  const [scannerSubTab, setScannerSubTab] = useState<'url' | 'message'>('url');
  const [activeScan, setActiveScan] = useState<ScanResult | null>(null);
  
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [stats, setStats] = useState<ScanSummaryStats | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [serverOnline, setServerOnline] = useState(true);

  // Load initial scans and stats
  const fetchData = async () => {
    try {
      const [scansRes, statsRes] = await Promise.all([
        fetch('/api/scans'),
        fetch('/api/stats')
      ]);

      if (scansRes.ok) {
        const scansData = await scansRes.json();
        setScans(scansData);
      }
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }
      setServerOnline(true);
    } catch (err) {
      console.error('Failed to fetch data from PhishGuard API:', err);
      setServerOnline(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleScanUrl = async (url: string) => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const res = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      if (!res.ok) {
        let errorMsg = 'Failed to complete URL scan';
        try {
          const contentType = res.headers.get('content-type');
          if (contentType && contentType.includes('application/json')) {
            const errJson = await res.json();
            errorMsg = errJson.error || errorMsg;
          } else {
            errorMsg = `Server responded with status ${res.status}. If deployed on Vercel, ensure GEMINI_API_KEY is configured in Environment Variables.`;
          }
        } catch {
          errorMsg = `Server error (${res.status})`;
        }
        throw new Error(errorMsg);
      }

      const scanResult: ScanResult = await res.json();
      setActiveScan(scanResult);
      // Refresh list and stats
      fetchData();
    } catch (err: any) {
      console.error('Scan URL Error:', err);
      setErrorMessage(err.message || 'Unable to scan URL. Please verify server connection.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleScanMessage = async (message: string, subtype: MessageSubtype) => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const res = await fetch('/api/scan/message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, subtype })
      });

      if (!res.ok) {
        let errorMsg = 'Failed to complete message scan';
        try {
          const contentType = res.headers.get('content-type');
          if (contentType && contentType.includes('application/json')) {
            const errJson = await res.json();
            errorMsg = errJson.error || errorMsg;
          } else {
            errorMsg = `Server responded with status ${res.status}. If deployed on Vercel, ensure GEMINI_API_KEY is configured in Environment Variables.`;
          }
        } catch {
          errorMsg = `Server error (${res.status})`;
        }
        throw new Error(errorMsg);
      }

      const scanResult: ScanResult = await res.json();
      setActiveScan(scanResult);
      // Refresh list and stats
      fetchData();
    } catch (err: any) {
      console.error('Scan Message Error:', err);
      setErrorMessage(err.message || 'Unable to scan message. Please verify server connection.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteScan = async (id: string) => {
    try {
      const res = await fetch(`/api/scans/${id}`, { method: 'DELETE' });
      if (res.ok) {
        if (activeScan && activeScan.id === id) {
          setActiveScan(null);
        }
        fetchData();
      }
    } catch (err) {
      console.error('Delete scan error:', err);
    }
  };

  const handleToggleStar = async (id: string) => {
    try {
      const res = await fetch(`/api/scans/${id}/star`, { method: 'POST' });
      if (res.ok) {
        const updated = await res.json();
        if (activeScan && activeScan.id === id) {
          setActiveScan(updated);
        }
        fetchData();
      }
    } catch (err) {
      console.error('Toggle star error:', err);
    }
  };

  const handleNewScan = () => {
    setActiveScan(null);
    setActiveTab('scanner');
    setErrorMessage(null);
  };

  const handleSelectHistoricalScan = (scan: ScanResult) => {
    setActiveScan(scan);
    setActiveTab('scanner');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-red-500/30 selection:text-red-200">
      {/* Strict Top Bar Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setActiveTab(tab);
          if (tab !== 'scanner') {
            setActiveScan(null);
          }
        }}
        onNewScan={handleNewScan}
        serverOnline={serverOnline}
      />

      {/* Main Workspace Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        {/* Global Error Banner if any */}
        {errorMessage && (
          <div className="mb-6 p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-xs text-red-300 flex items-start justify-between gap-3 shadow-md">
            <div className="flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div>
                <strong className="font-semibold block text-red-200">Scan Execution Error:</strong>
                {errorMessage}
              </div>
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              className="text-red-400 hover:text-red-200 text-xs px-2 py-1 font-mono"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* 1. Scanner Tab */}
        {activeTab === 'scanner' && (
          <>
            {activeScan ? (
              <ThreatResultView
                scan={activeScan}
                onBack={() => setActiveScan(null)}
                onToggleStar={handleToggleStar}
              />
            ) : (
              <div className="space-y-6 max-w-4xl mx-auto">
                {/* Hero / Pitch Strip */}
                <div className="text-center space-y-2 py-4">
                  <div className="inline-flex items-center gap-1.5 text-xs text-slate-400 font-mono tracking-wide">
                    <span>DUAL-ENGINE THREAT DETECTION</span>
                    <span aria-hidden="true">·</span>
                    <span>ML LOGISTIC REGRESSION + GEMINI 3.8 FLASH</span>
                  </div>
                  <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
                    Inspect Suspect URLs & Messages
                  </h1>
                  <p className="text-sm text-slate-400 max-w-xl mx-auto leading-relaxed">
                    Unmask typosquatting domains, credential-harvesting endpoints, smishing package alerts, and executive wire fraud in milliseconds.
                  </p>
                </div>

                {/* Sub-tab segmented filter (URL vs Message) */}
                <div className="flex justify-center">
                  <div className="flex items-center p-1 bg-slate-900 border border-slate-800 rounded-lg">
                    <button
                      onClick={() => setScannerSubTab('url')}
                      className={`flex items-center gap-2 px-5 py-2 rounded-md text-xs font-semibold transition-all ${
                        scannerSubTab === 'url'
                          ? 'bg-slate-800 text-white shadow-sm'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <Globe className="w-4 h-4 text-red-400" />
                      <span>URL Scanner</span>
                    </button>

                    <button
                      onClick={() => setScannerSubTab('message')}
                      className={`flex items-center gap-2 px-5 py-2 rounded-md text-xs font-semibold transition-all ${
                        scannerSubTab === 'message'
                          ? 'bg-slate-800 text-white shadow-sm'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <Mail className="w-4 h-4 text-red-400" />
                      <span>Message Scanner</span>
                    </button>
                  </div>
                </div>

                {/* Active Subtab Component */}
                {scannerSubTab === 'url' ? (
                  <UrlScannerTab onScan={handleScanUrl} isLoading={isLoading} />
                ) : (
                  <MessageScannerTab onScan={handleScanMessage} isLoading={isLoading} />
                )}
              </div>
            )}
          </>
        )}

        {/* 2. SOC Dashboard Tab */}
        {activeTab === 'dashboard' && (
          <DashboardView
            stats={stats}
            recentScans={scans}
            onSelectScan={handleSelectHistoricalScan}
            onNavigateScanner={handleNewScan}
          />
        )}

        {/* 3. Scan History Tab */}
        {activeTab === 'history' && (
          <HistoryView
            scans={scans}
            onSelectScan={handleSelectHistoricalScan}
            onDeleteScan={handleDeleteScan}
            onToggleStar={handleToggleStar}
            onRefresh={fetchData}
            onNavigateScanner={handleNewScan}
          />
        )}

        {/* 4. Machine Learning Benchmark Tab */}
        {activeTab === 'ml-benchmark' && (
          <MlBenchmarkView />
        )}

        {/* 5. Threat Radar / Knowledge Base Tab */}
        {activeTab === 'radar' && (
          <EducationalRadar />
        )}

      </main>

      {/* Clean Footer (Quiet copyright and status, strictly no ornamental tickers) */}
      <footer className="border-t border-slate-900 py-6 mt-12 bg-slate-950 text-slate-500 text-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-red-500" />
            <span className="font-semibold text-slate-300">PhishGuard</span>
            <span aria-hidden="true">·</span>
            <span>AI Cybersecurity Threat Intelligence</span>
          </div>

          <div className="flex items-center gap-4 text-[11px] text-slate-500 font-mono">
            <span>Server: Express / Vite</span>
            <span aria-hidden="true">/</span>
            <span>Model: Gemini 3.8 Flash</span>
            <span aria-hidden="true">/</span>
            <span>Dataset: PhishTank & Enron</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
