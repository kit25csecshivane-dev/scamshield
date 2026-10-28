/**
 * Server-side File-backed Storage Service for Scan History & Telemetry
 */

import fs from 'fs';
import path from 'path';
import { ScanResult, ScanSummaryStats, ScanType } from '../types/threat.js';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DATA_FILE = path.join(DATA_DIR, 'scans.json');

// Ensure data directory exists
function ensureStorage(): void {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DATA_FILE)) {
    const initialScans: ScanResult[] = getInitialSeedScans();
    fs.writeFileSync(DATA_FILE, JSON.stringify(initialScans, null, 2), 'utf-8');
  }
}

function readScans(): ScanResult[] {
  try {
    ensureStorage();
    const data = fs.readFileSync(DATA_FILE, 'utf-8');
    return JSON.parse(data || '[]');
  } catch (err) {
    console.error('Failed to read scans storage:', err);
    return [];
  }
}

function writeScans(scans: ScanResult[]): void {
  try {
    ensureStorage();
    fs.writeFileSync(DATA_FILE, JSON.stringify(scans, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to write scans storage:', err);
  }
}

export function getAllScans(filter?: {
  search?: string;
  type?: ScanType;
  verdict?: string;
  starredOnly?: boolean;
}): ScanResult[] {
  let list = readScans();

  if (filter?.type) {
    list = list.filter(s => s.type === filter.type);
  }
  if (filter?.verdict && filter.verdict !== 'ALL') {
    list = list.filter(s => s.verdict === filter.verdict);
  }
  if (filter?.starredOnly) {
    list = list.filter(s => !!s.starred);
  }
  if (filter?.search) {
    const q = filter.search.toLowerCase();
    list = list.filter(s => 
      s.target.toLowerCase().includes(q) ||
      s.threatType.toLowerCase().includes(q) ||
      (s.impersonatedEntity && s.impersonatedEntity.toLowerCase().includes(q)) ||
      s.explanation.toLowerCase().includes(q)
    );
  }

  // Sort latest first
  return list.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

export function getScanById(id: string): ScanResult | null {
  const list = readScans();
  return list.find(s => s.id === id) || null;
}

export function saveScan(scan: ScanResult): ScanResult {
  const list = readScans();
  // Check if exists
  const idx = list.findIndex(s => s.id === scan.id);
  if (idx >= 0) {
    list[idx] = scan;
  } else {
    list.unshift(scan);
  }
  writeScans(list);
  return scan;
}

export function deleteScan(id: string): boolean {
  const list = readScans();
  const filtered = list.filter(s => s.id !== id);
  if (filtered.length !== list.length) {
    writeScans(filtered);
    return true;
  }
  return false;
}

export function toggleStarScan(id: string): ScanResult | null {
  const list = readScans();
  const scan = list.find(s => s.id === id);
  if (!scan) return null;
  scan.starred = !scan.starred;
  writeScans(list);
  return scan;
}

export function getStats(): ScanSummaryStats {
  const list = readScans();
  const totalScans = list.length;
  
  let maliciousCount = 0;
  let highRiskCount = 0;
  let suspiciousCount = 0;
  let safeCount = 0;
  let totalScore = 0;

  const threatTypeCounts: Record<string, number> = {};

  for (const s of list) {
    totalScore += s.riskScore;
    if (s.verdict === 'MALICIOUS_PHISHING') maliciousCount++;
    else if (s.verdict === 'HIGH_RISK') highRiskCount++;
    else if (s.verdict === 'SUSPICIOUS') suspiciousCount++;
    else safeCount++;

    const t = s.threatType || 'Unclassified';
    threatTypeCounts[t] = (threatTypeCounts[t] || 0) + 1;
  }

  const averageRiskScore = totalScans > 0 ? Math.round(totalScore / totalScans) : 0;

  // Aggregate scans over last 7 days
  const scansOverTime: Array<{ date: string; count: number; threats: number }> = [];
  const daysMap = new Map<string, { count: number; threats: number }>();

  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().split('T')[0];
    daysMap.set(key, { count: 0, threats: 0 });
  }

  for (const s of list) {
    const day = s.timestamp.split('T')[0];
    if (daysMap.has(day)) {
      const entry = daysMap.get(day)!;
      entry.count++;
      if (s.riskScore >= 50) entry.threats++;
    }
  }

  for (const [date, val] of daysMap.entries()) {
    scansOverTime.push({ date, count: val.count, threats: val.threats });
  }

  return {
    totalScans,
    maliciousCount,
    highRiskCount,
    suspiciousCount,
    safeCount,
    averageRiskScore,
    threatTypeCounts,
    scansOverTime
  };
}

function getInitialSeedScans(): ScanResult[] {
  const now = Date.now();
  const hour = 3600 * 1000;
  const day = 24 * hour;

  return [
    {
      id: 'scan-seed-1',
      timestamp: new Date(now - 2 * hour).toISOString(),
      target: 'https://paypa1-security-verification.xyz/webscr/login?cmd=_session',
      type: 'url',
      riskScore: 96,
      verdict: 'MALICIOUS_PHISHING',
      confidence: 0.98,
      threatType: 'Credential Harvesting Phishing Link',
      impersonatedEntity: 'PayPal',
      indicators: [
        {
          id: 'ind-1',
          name: 'Brand Typosquatting (PayPal)',
          severity: 'critical',
          category: 'reputation',
          description: 'Domain replaces letter "l" with numeral "1" (paypa1).',
          evidence: 'paypa1-security-verification.xyz'
        },
        {
          id: 'ind-2',
          name: 'High-Risk Top Level Domain',
          severity: 'medium',
          category: 'domain',
          description: 'TLD .xyz has high volume of malicious disposable domains.',
          evidence: '.xyz'
        },
        {
          id: 'ind-3',
          name: 'Classic Authentication Path Injection',
          severity: 'high',
          category: 'credential_lure',
          description: 'Path mimics legacy PayPal IPN login handler (/webscr/login).',
          evidence: '/webscr/login?cmd=_session'
        }
      ],
      explanation: 'Critical credential harvesting domain spoofing PayPal. The domain deliberately typo-squats the registered trademark and leads directly to a credential exfiltration script.',
      technicalDetails: {
        domain: 'paypa1-security-verification.xyz',
        entropy: 3.92,
        hasIpHost: false,
        isPunycode: false,
        subdomainCount: 2,
        suspiciousTld: 'xyz',
        pathKeywords: ['login', 'webscr', 'cmd=_login'],
        impersonatedBrand: 'PayPal'
      },
      recommendedActions: [
        'Do not visit the URL or enter credentials.',
        'Block paypa1-security-verification.xyz at perimeter DNS/firewall.',
        'Report to PayPal Anti-Phishing team (spoof@paypal.com).'
      ],
      uncertaintyCaveat: 'Deterministic indicators confirm active brand impersonation and credential lure.',
      engineUsed: 'gemini-ai',
      starred: true
    },
    {
      id: 'scan-seed-2',
      timestamp: new Date(now - 5 * hour).toISOString(),
      target: 'USPS Notice: Your package 940011189922 could not be delivered due to an incorrect house number. Update your details within 24 hours at https://us-postal-redeliver.top/tracking to prevent return to sender.',
      type: 'message',
      subtype: 'sms',
      riskScore: 92,
      verdict: 'MALICIOUS_PHISHING',
      confidence: 0.97,
      threatType: 'Postal Courier Smishing (SMS Phishing)',
      impersonatedEntity: 'USPS',
      indicators: [
        {
          id: 'ind-4',
          name: 'Artificial 24-Hour Time Pressure',
          severity: 'high',
          category: 'urgency',
          description: 'Imposes short deadline to panic the victim into immediate action without verification.',
          evidence: 'within 24 hours'
        },
        {
          id: 'ind-5',
          name: 'Postal Delivery Impersonation',
          severity: 'high',
          category: 'reputation',
          description: 'Classic courier redelivery scam requesting personal address and credit card fee.',
          evidence: 'package could not be delivered'
        },
        {
          id: 'ind-6',
          name: 'Suspicious TLD in Link',
          severity: 'high',
          category: 'technical',
          description: 'Extracted link uses .top domain rather than official usps.com.',
          evidence: 'us-postal-redeliver.top'
        }
      ],
      explanation: 'Standard mass-delivery smishing scam designed to harvest credit cards and personal identities under the guise of redelivering a fictitious postal parcel.',
      technicalDetails: {
        messageLength: 215,
        urgencyScore: 1,
        extractedLinks: ['https://us-postal-redeliver.top/tracking'],
        impersonatedBrand: 'USPS'
      },
      recommendedActions: [
        'Delete SMS message immediately.',
        'Do not click the link or pay any redelivery fee.',
        'Forward SMS to 7726 (SPAM) for carrier-level blocking.'
      ],
      uncertaintyCaveat: 'Verified smishing pattern with unauthorized lookalike courier domain.',
      engineUsed: 'gemini-ai'
    },
    {
      id: 'scan-seed-3',
      timestamp: new Date(now - 1 * day).toISOString(),
      target: 'https://github.com/torvalds/linux',
      type: 'url',
      riskScore: 4,
      verdict: 'SAFE',
      confidence: 0.96,
      threatType: 'Verified Benign Developer Repository',
      impersonatedEntity: null,
      indicators: [],
      explanation: 'Official repository hosted on legitimate github.com domain. No suspicious lexical, typosquatting, or redirection markers detected.',
      technicalDetails: {
        domain: 'github.com',
        entropy: 2.75,
        hasIpHost: false,
        isPunycode: false,
        subdomainCount: 2,
        suspiciousTld: null,
        pathKeywords: []
      },
      recommendedActions: [
        'Standard development browsing.',
        'Ensure HTTPS connection remains verified by your browser certificate validator.'
      ],
      uncertaintyCaveat: 'Target domain is verified, but remember that legitimate platforms can occasionally host malicious third-party user uploads.',
      engineUsed: 'gemini-ai'
    },
    {
      id: 'scan-seed-4',
      timestamp: new Date(now - 2 * day).toISOString(),
      target: 'URGENT: Executive Wire Transfer Authorization required. Wire $42,500 to account #88129-C by 3:00 PM today. Do not call, I am currently in a board meeting.',
      type: 'message',
      subtype: 'email',
      riskScore: 88,
      verdict: 'MALICIOUS_PHISHING',
      confidence: 0.94,
      threatType: 'Business Email Compromise (BEC / CEO Fraud)',
      impersonatedEntity: 'Corporate Executive',
      indicators: [
        {
          id: 'ind-7',
          name: 'Executive Wire Transfer Solicitation',
          severity: 'critical',
          category: 'credential_lure',
          description: 'Unscheduled high-value wire transfer demand.',
          evidence: 'Wire $42,500'
        },
        {
          id: 'ind-8',
          name: 'Out-of-Band Channel Blockade',
          severity: 'high',
          category: 'linguistic',
          description: 'Explicit instruction discouraging phone calls to prevent verbal confirmation.',
          evidence: 'Do not call, I am currently in a board meeting'
        }
      ],
      explanation: 'Hallmark indicators of Business Email Compromise (BEC). Attackers frequently pose as executives in meetings to bypass multi-party financial authorization protocols.',
      technicalDetails: {
        messageLength: 172,
        urgencyScore: 1,
        extractedLinks: []
      },
      recommendedActions: [
        'Hold all financial disbursements.',
        'Verbally verify payment authorization using a pre-established internal telephone directory.'
      ],
      uncertaintyCaveat: 'Heuristic and AI models flag high social engineering risk. Out-of-band human verification is mandatory.',
      engineUsed: 'gemini-ai',
      starred: true
    },
    {
      id: 'scan-seed-5',
      timestamp: new Date(now - 3 * day).toISOString(),
      target: 'https://docs.google.com/document/d/1yR4wX_presentation/edit',
      type: 'url',
      riskScore: 8,
      verdict: 'SAFE',
      confidence: 0.92,
      threatType: 'Clean Cloud Collaboration Asset',
      impersonatedEntity: null,
      indicators: [],
      explanation: 'Authentic Google Docs workspace URL. Uses official Google root domain and standard document identifier structure.',
      technicalDetails: {
        domain: 'docs.google.com',
        entropy: 3.12,
        hasIpHost: false,
        isPunycode: false,
        subdomainCount: 3,
        suspiciousTld: null,
        pathKeywords: []
      },
      recommendedActions: [
        'Exercise normal discretion when opening shared documents from external unverified senders.'
      ],
      uncertaintyCaveat: 'The host domain is legitimate; however, public cloud services can sometimes be utilized by attackers to share deceptive lure documents.',
      engineUsed: 'gemini-ai'
    }
  ];
}
