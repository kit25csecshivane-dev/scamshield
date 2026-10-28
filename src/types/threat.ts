/**
 * PhishGuard Threat Analysis Types & Interfaces
 */

export type ThreatSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type ThreatVerdict = 
  | 'SAFE' 
  | 'SUSPICIOUS' 
  | 'HIGH_RISK' 
  | 'MALICIOUS_PHISHING';

export type ScanType = 'url' | 'message';

export type MessageSubtype = 'email' | 'sms' | 'chat';

export interface ThreatIndicator {
  id: string;
  name: string;
  severity: ThreatSeverity;
  category: 'domain' | 'linguistic' | 'urgency' | 'credential_lure' | 'technical' | 'reputation';
  description: string;
  evidence?: string;
}

export interface TechnicalDetails {
  domain?: string;
  entropy?: number;
  hasIpHost?: boolean;
  isPunycode?: boolean;
  subdomainCount?: number;
  suspiciousTld?: string | null;
  pathKeywords?: string[];
  homoglyphTarget?: string | null;
  messageLength?: number;
  urgencyScore?: number;
  extractedLinks?: string[];
  impersonatedBrand?: string | null;
}

export interface MLBaselinePrediction {
  score: number; // 0 - 100
  verdict: ThreatVerdict;
  confidence: number; // 0 - 1
  featuresExtracted: Record<string, number | boolean | string>;
  modelName: string;
}

export interface ScanResult {
  id: string;
  timestamp: string;
  target: string; // The URL or Message text
  type: ScanType;
  subtype?: MessageSubtype;
  riskScore: number; // 0 - 100
  verdict: ThreatVerdict;
  confidence: number; // 0.0 - 1.0
  threatType: string;
  impersonatedEntity: string | null;
  indicators: ThreatIndicator[];
  explanation: string;
  technicalDetails: TechnicalDetails;
  recommendedActions: string[];
  uncertaintyCaveat: string;
  engineUsed: 'gemini-ai' | 'ml-baseline-heuristic' | 'hybrid';
  starred?: boolean;
  mlBaseline?: MLBaselinePrediction;
}

export interface ScanSummaryStats {
  totalScans: number;
  maliciousCount: number;
  highRiskCount: number;
  suspiciousCount: number;
  safeCount: number;
  averageRiskScore: number;
  threatTypeCounts: Record<string, number>;
  scansOverTime: Array<{ date: string; count: number; threats: number }>;
}

export interface MLModelEvaluation {
  modelName: string;
  architecture: string;
  dataset: {
    name: string;
    totalSamples: number;
    phishingSamples: number;
    benignSamples: number;
    trainingSplit: string;
  };
  metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    rocAuc: number;
  };
  confusionMatrix: {
    trueNegative: number;
    falsePositive: number;
    falseNegative: number;
    truePositive: number;
  };
  featureImportance: Array<{
    feature: string;
    weight: number;
    description: string;
  }>;
}
