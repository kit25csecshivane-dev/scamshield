import React from 'react';
import { ShieldAlert, Activity, History, Cpu, BookOpen, Plus } from 'lucide-react';

export type ActiveTab = 'scanner' | 'dashboard' | 'history' | 'ml-benchmark' | 'radar';

interface NavbarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  onNewScan: () => void;
  serverOnline: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  onNewScan,
  serverOnline
}) => {
  return (
    <header className="sticky top-0 z-40 bg-slate-950/90 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Strict Top Bar Contract: Zone 1 (Brand) - Zone 2 (4-5 Nav Links) - Zone 3 (1 Primary Action) */}
        <div className="flex items-center justify-between gap-8 h-16">
          
          {/* Zone 1: Brand Wordmark */}
          <div 
            onClick={() => setActiveTab('scanner')} 
            className="flex items-center gap-2.5 cursor-pointer whitespace-nowrap shrink-0 group"
          >
            <div className="w-9 h-9 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 group-hover:border-red-500/50 transition-colors">
              <ShieldAlert className="w-5 h-5 text-red-500" />
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight text-white block leading-none">
                PhishGuard
              </span>
              <span className="text-[10px] text-slate-500 font-mono tracking-wider block mt-0.5">
                AI THREAT INTELLIGENCE
              </span>
            </div>
          </div>

          {/* Zone 2: Navigation Links (Single-line, subtle hover underlines) */}
          <nav className="hidden md:flex items-center gap-7 text-sm font-medium">
            <button
              onClick={() => setActiveTab('scanner')}
              className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 pb-0.5 border-b-2 ${
                activeTab === 'scanner'
                  ? 'border-red-500 text-white'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <ShieldAlert className="w-4 h-4" />
              Scanner
            </button>

            <button
              onClick={() => setActiveTab('dashboard')}
              className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 pb-0.5 border-b-2 ${
                activeTab === 'dashboard'
                  ? 'border-red-500 text-white'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Activity className="w-4 h-4" />
              SOC Dashboard
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 pb-0.5 border-b-2 ${
                activeTab === 'history'
                  ? 'border-red-500 text-white'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <History className="w-4 h-4" />
              Scan History
            </button>

            <button
              onClick={() => setActiveTab('ml-benchmark')}
              className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 pb-0.5 border-b-2 ${
                activeTab === 'ml-benchmark'
                  ? 'border-red-500 text-white'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Cpu className="w-4 h-4" />
              ML Benchmark
            </button>

            <button
              onClick={() => setActiveTab('radar')}
              className={`flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 pb-0.5 border-b-2 ${
                activeTab === 'radar'
                  ? 'border-red-500 text-white'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <BookOpen className="w-4 h-4" />
              Threat Radar
            </button>
          </nav>

          {/* Zone 3: 1 Primary Action */}
          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={onNewScan}
              className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-500 rounded-md transition-colors whitespace-nowrap shadow-sm shadow-red-950/40"
            >
              <Plus className="w-3.5 h-3.5" />
              New Scan
            </button>
          </div>

        </div>

        {/* Mobile secondary navigation */}
        <div className="flex md:hidden overflow-x-auto py-2.5 gap-4 border-t border-slate-900 text-xs text-slate-400 scrollbar-none">
          <button
            onClick={() => setActiveTab('scanner')}
            className={`whitespace-nowrap ${activeTab === 'scanner' ? 'text-white font-semibold' : ''}`}
          >
            Scanner
          </button>
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`whitespace-nowrap ${activeTab === 'dashboard' ? 'text-white font-semibold' : ''}`}
          >
            Dashboard
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`whitespace-nowrap ${activeTab === 'history' ? 'text-white font-semibold' : ''}`}
          >
            History
          </button>
          <button
            onClick={() => setActiveTab('ml-benchmark')}
            className={`whitespace-nowrap ${activeTab === 'ml-benchmark' ? 'text-white font-semibold' : ''}`}
          >
            ML Benchmark
          </button>
          <button
            onClick={() => setActiveTab('radar')}
            className={`whitespace-nowrap ${activeTab === 'radar' ? 'text-white font-semibold' : ''}`}
          >
            Radar
          </button>
        </div>
      </div>
    </header>
  );
};
