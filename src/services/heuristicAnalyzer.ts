/**
 * PhishGuard Heuristic Threat Analyzer
 * Provides deterministic feature extraction, pattern matching, and heuristic indicators
 * for suspicious URLs and deceptive messages.
 */

import { ThreatIndicator, TechnicalDetails } from '../types/threat.js';

// Suspicious top-level domains commonly used in bulk phishing and spam campaigns
export const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'buzz', 'click',
  'rest', 'cfd', 'bid', 'loan', 'win', 'men', 'party', 'date', 'stream',
  'download', 'racing', 'accountant', 'science', 'cricket', 'faith'
]);

// Well-known brands frequently impersonated by cybercriminals
export const HIGH_VALUE_BRANDS = [
  { name: 'PayPal', domain: 'paypal.com', patterns: [/paypa[l1i]/i, /pay-?pal/i] },
  { name: 'Apple', domain: 'apple.com', patterns: [/app[l1i]e-?id/i, /icloud-?verify/i, /appleid/i] },
  { name: 'Microsoft', domain: 'microsoft.com', patterns: [/micros[o0]ft/i, /ms-?office/i, /office365/i, /onedrive-?share/i] },
  { name: 'Google', domain: 'google.com', patterns: [/g[o0]{2}g[l1]e/i, /gmail-?security/i, /google-?drive-?share/i] },
  { name: 'Amazon', domain: 'amazon.com', patterns: [/amaz[o0]n/i, /aws-?billing/i, /prime-?renewal/i] },
  { name: 'Netflix', domain: 'netflix.com', patterns: [/netf[l1]ix/i, /netflix-?payment/i] },
  { name: 'Chase Bank', domain: 'chase.com', patterns: [/chase-?online/i, /chase-?bank/i] },
  { name: 'Wells Fargo', domain: 'wellsfargo.com', patterns: [/wells-?fargo/i, /wellsfarg[o0]/i] },
  { name: 'Bank of America', domain: 'bankofamerica.com', patterns: [/bank-?of-?america/i, /bofa-?alert/i] },
  { name: 'Coinbase', domain: 'coinbase.com', patterns: [/c[o0]inbase/i, /coinbase-?wallet/i] },
  { name: 'USPS', domain: 'usps.com', patterns: [/usps-?tracking/i, /us-?post/i, /postal-?delivery/i] },
  { name: 'FedEx', domain: 'fedex.com', patterns: [/fed-?ex/i, /fedex-?package/i] },
  { name: 'DHL', domain: 'dhl.com', patterns: [/dhl-?express/i, /dhl-?track/i] },
  { name: 'Meta / Facebook', domain: 'facebook.com', patterns: [/faceb[o0]{2}k/i, /meta-?support/i, /instagram-?badge/i] }
];

// Sensitive keywords often found in phishing paths
const SENSITIVE_PATH_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification', 'authenticate',
  'security', 'update', 'confirm', 'wallet', 'banking', 'secure', 'password',
  'credential', 'validate', 'session', 'webscr', 'cmd=_login', 're-login'
];

// Calculate Shannon entropy of a string (higher entropy indicates randomized or obfuscated domain names)
export function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

// Extract hostname and path from a raw URL safely without executing or fetching it
export function parseUrlSafely(rawUrl: string): {
  isValid: boolean;
  urlObj: URL | null;
  hostname: string;
  pathname: string;
  tld: string;
  error?: string;
} {
  let cleaned = rawUrl.trim();
  if (!/^https?:\/\//i.test(cleaned)) {
    cleaned = 'http://' + cleaned;
  }

  try {
    const urlObj = new URL(cleaned);
    const hostname = urlObj.hostname.toLowerCase();
    const parts = hostname.split('.');
    const tld = parts.length > 1 ? parts[parts.length - 1] : '';
    return {
      isValid: true,
      urlObj,
      hostname,
      pathname: urlObj.pathname + urlObj.search,
      tld
    };
  } catch (err) {
    return {
      isValid: false,
      urlObj: null,
      hostname: '',
      pathname: '',
      tld: '',
      error: 'Invalid URL format'
    };
  }
}

/**
 * Heuristic URL Analysis
 */
export function analyzeUrlHeuristics(rawUrl: string): {
  indicators: ThreatIndicator[];
  technical: TechnicalDetails;
  heuristicScore: number; // 0 - 100
  brandDetected: string | null;
} {
  const indicators: ThreatIndicator[] = [];
  let heuristicScore = 0;

  const parsed = parseUrlSafely(rawUrl);
  if (!parsed.isValid || !parsed.urlObj) {
    indicators.push({
      id: 'invalid-url',
      name: 'Malformed URL Syntax',
      severity: 'medium',
      category: 'technical',
      description: 'The supplied input could not be parsed as a standard RFC-compliant URL.',
      evidence: rawUrl
    });
    return {
      indicators,
      technical: { domain: rawUrl },
      heuristicScore: 40,
      brandDetected: null
    };
  }

  const { hostname, pathname, tld } = parsed;
  const domainParts = hostname.split('.');
  const entropy = calculateShannonEntropy(hostname);

  // 1. Check for IP address in host (classic indicator of raw phishing infrastructure)
  const isIpv4 = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname);
  const isIpv6 = hostname.startsWith('[') || /^[0-9a-fA-F:]+$/.test(hostname);
  if (isIpv4 || isIpv6) {
    heuristicScore += 35;
    indicators.push({
      id: 'ip-as-host',
      name: 'Direct IP Address in Hostname',
      severity: 'high',
      category: 'domain',
      description: 'Legitimate services use registered domain names. Using a raw IP address avoids domain reputation systems.',
      evidence: hostname
    });
  }

  // 2. Punycode / Homoglyph check
  const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
  if (isPunycode) {
    heuristicScore += 30;
    indicators.push({
      id: 'punycode-homoglyph',
      name: 'Internationalized Domain Name (Punycode)',
      severity: 'high',
      category: 'domain',
      description: 'Punycode notation can be used to spoof visually identical Unicode characters (homograph attack).',
      evidence: hostname
    });
  }

  // 3. Suspicious or high-risk TLD
  if (SUSPICIOUS_TLDS.has(tld)) {
    heuristicScore += 25;
    indicators.push({
      id: 'suspicious-tld',
      name: 'High-Risk Top Level Domain (TLD)',
      severity: 'medium',
      category: 'domain',
      description: `The .${tld} top-level domain has a statistically high correlation with disposable phishing registrations.`,
      evidence: `.${tld}`
    });
  }

  // 4. Excessive Subdomains (Domain fronting / sub-domain stacking)
  if (domainParts.length >= 4) {
    heuristicScore += 20;
    indicators.push({
      id: 'excessive-subdomains',
      name: 'Deep Subdomain Nesting',
      severity: 'medium',
      category: 'domain',
      description: 'Excessive subdomains are frequently used to mimic authentic organization domains inside third-party hosts.',
      evidence: `${domainParts.length} levels: ${hostname}`
    });
  }

  // 5. Brand Impersonation / Typosquatting Analysis
  let brandDetected: string | null = null;
  for (const brand of HIGH_VALUE_BRANDS) {
    const isTargetDomain = hostname === brand.domain || hostname.endsWith('.' + brand.domain);
    const mentionsBrand = brand.patterns.some(p => p.test(hostname));

    if (mentionsBrand && !isTargetDomain) {
      brandDetected = brand.name;
      heuristicScore += 45;
      indicators.push({
        id: `impersonation-${brand.name.toLowerCase().replace(/\s+/g, '-')}`,
        name: `Brand Impersonation (${brand.name})`,
        severity: 'critical',
        category: 'reputation',
        description: `Hostname contains brand identifiers for ${brand.name}, but is registered under an unauthorized root domain (${domainParts.slice(-2).join('.')}).`,
        evidence: `Domain: ${hostname} vs Official: ${brand.domain}`
      });
      break;
    }
  }

  // 6. Sensitive Path Keywords (Credential Harvesting)
  const matchedPathKeywords = SENSITIVE_PATH_KEYWORDS.filter(k => 
    pathname.toLowerCase().includes(k)
  );
  if (matchedPathKeywords.length > 0) {
    heuristicScore += Math.min(25, matchedPathKeywords.length * 10);
    indicators.push({
      id: 'credential-harvest-path',
      name: 'Authentication / Credential Harvesting Path',
      severity: matchedPathKeywords.length >= 2 ? 'high' : 'medium',
      category: 'credential_lure',
      description: 'The URL path specifically directs users to verification, login, or security credentials submission.',
      evidence: matchedPathKeywords.join(', ')
    });
  }

  // 7. Excessive Hyphens in Hostname
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    heuristicScore += 15;
    indicators.push({
      id: 'excessive-hyphens',
      name: 'Heavy Hyphenation Pattern',
      severity: 'low',
      category: 'domain',
      description: 'Multiple hyphens are commonly used to chain legitimate-sounding terms into a lookalike domain name.',
      evidence: `${hyphenCount} hyphens detected in ${hostname}`
    });
  }

  // 8. Domain Entropy Check (DGA - Domain Generation Algorithm detection)
  if (entropy > 3.8 && hostname.length > 14) {
    heuristicScore += 20;
    indicators.push({
      id: 'high-entropy-domain',
      name: 'High Lexical Randomness (Entropy)',
      severity: 'medium',
      category: 'domain',
      description: 'Domain exhibits high Shannon randomness, characteristic of algorithmic domain generation or disposable infrastructure.',
      evidence: `Entropy score: ${entropy.toFixed(2)} (threshold > 3.8)`
    });
  }

  // 9. @ symbol in URL (HTTP basic auth deception)
  if (rawUrl.includes('@')) {
    heuristicScore += 35;
    indicators.push({
      id: 'at-symbol-deception',
      name: 'Credential Prefix Obfuscation (@ symbol)',
      severity: 'high',
      category: 'technical',
      description: 'The @ character directs the browser to ignore text before it and connect to the host specified after it.',
      evidence: rawUrl
    });
  }

  // 10. URL length anomaly
  if (rawUrl.length > 150) {
    heuristicScore += 10;
    indicators.push({
      id: 'abnormal-url-length',
      name: 'Abnormal URL Length',
      severity: 'low',
      category: 'technical',
      description: 'Extremely long URLs are often used to bury redirect targets or payload parameters.',
      evidence: `${rawUrl.length} characters`
    });
  }

  const technical: TechnicalDetails = {
    domain: hostname,
    entropy,
    hasIpHost: isIpv4 || isIpv6,
    isPunycode,
    subdomainCount: domainParts.length,
    suspiciousTld: SUSPICIOUS_TLDS.has(tld) ? tld : null,
    pathKeywords: matchedPathKeywords,
    homoglyphTarget: brandDetected,
    impersonatedBrand: brandDetected
  };

  return {
    indicators,
    technical,
    heuristicScore: Math.min(100, Math.max(0, heuristicScore)),
    brandDetected
  };
}

/**
 * Heuristic Message Analysis (Email / SMS / Chat)
 */
export function analyzeMessageHeuristics(text: string): {
  indicators: ThreatIndicator[];
  technical: TechnicalDetails;
  heuristicScore: number;
  extractedLinks: string[];
} {
  const indicators: ThreatIndicator[] = [];
  let heuristicScore = 0;

  // Extract all links in message
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`[\]]+/gi;
  const matches = text.match(urlRegex) || [];
  const extractedLinks = Array.from(new Set(matches));

  // 1. High Urgency & Coercive Language
  const urgencyPatterns = [
    { regex: /\burgent\b|\burgenc(?:y|tly)\b/i, label: 'Explicit Urgency Cue' },
    { regex: /account(?:\s+has\s+been|\s+is)?\s+suspended|account\s+locked/i, label: 'Account Suspension Threat' },
    { regex: /within\s+24\s*(?:hours|hrs)|immediate(?:ly)?(?:\s+(?:action|transfer|payment|response|attention))?/i, label: 'Artificial Time Pressure (Urgent / 24h)' },
    { regex: /unauthorized\s+(?:access|transaction|login|activity)/i, label: 'Unauthorized Activity Alert' },
    { regex: /law\s+enforcement|legal\s+action|warrant\s+issued|arrest/i, label: 'Legal Coercion / Threat' },
    { regex: /final\s+notice|last\s+chance|service\s+termination/i, label: 'Final Notice Pressure' },
    { regex: /failure\s+to\s+comply|permanently\s+disabled/i, label: 'Punitive Threat Warning' },
    { regex: /do\s+not\s+call|cannot\s+take\s+calls|in\s+a\s+meeting/i, label: 'Communication Channel Blockade' }
  ];

  let matchedUrgencyCount = 0;
  for (const pattern of urgencyPatterns) {
    if (pattern.regex.test(text)) {
      matchedUrgencyCount++;
      heuristicScore += 20;
      indicators.push({
        id: `urgency-${matchedUrgencyCount}`,
        name: pattern.label,
        severity: 'high',
        category: 'urgency',
        description: 'Attackers create urgent psychological pressure to rush victims into bypassing rational scrutiny.',
        evidence: text.match(pattern.regex)?.[0]
      });
    }
  }

  // 2. Sensitive Credential / Information Harvesting
  const credentialPatterns = [
    { regex: /password|passcode|pin\s+code/i, label: 'Password / PIN Request' },
    { regex: /2fa|mfa|otp|verification\s+code|one-time\s+code/i, label: '2FA / One-Time Code Harvesting' },
    { regex: /social\s+security|ssn|identity\s+verification/i, label: 'Identity / SSN Solicit' },
    { regex: /credit\s+card|cvv|card\s+number|billing\s+details/i, label: 'Payment Card Details Request' },
    { regex: /seed\s+phrase|private\s+key|recovery\s+phrase/i, label: 'Cryptocurrency Wallet Key Request' }
  ];

  for (const pattern of credentialPatterns) {
    if (pattern.regex.test(text)) {
      heuristicScore += 25;
      indicators.push({
        id: `cred-${pattern.label.toLowerCase().replace(/\s+/g, '-')}`,
        name: pattern.label,
        severity: 'critical',
        category: 'credential_lure',
        description: 'Direct solicitations for authentication credentials, secret codes, or private keys are classic scam patterns.',
        evidence: text.match(pattern.regex)?.[0]
      });
    }
  }

  // 3. Financial Fraud / Payment Redirection / Gift Cards / Wire
  const financialPatterns = [
    { regex: /gift\s+card|apple\s+gift|steam\s+card|google\s+play\s+card/i, label: 'Untraceable Gift Card Demand' },
    { regex: /wire\s+transfer|wire\s+\$?\d+|western\s+union|moneygram/i, label: 'Wire Transfer Instruction' },
    { regex: /crypto|bitcoin|usdt|ethereum|wallet\s+address/i, label: 'Cryptocurrency Payment Demand' },
    { regex: /inheritance|lottery|beneficiary|unclaimed\s+funds/i, label: 'Advance-Fee / Lottery Scam Lure' },
    { regex: /invoice\s+(?:#\d+|overdue|attached|unpaid)/i, label: 'Fake Invoice Alert' }
  ];

  for (const pattern of financialPatterns) {
    if (pattern.regex.test(text)) {
      heuristicScore += 25;
      indicators.push({
        id: `fin-${pattern.label.toLowerCase().replace(/\s+/g, '-')}`,
        name: pattern.label,
        severity: 'high',
        category: 'credential_lure',
        description: 'Demands for untraceable financial transfers or gift cards are nearly always fraudulent.',
        evidence: text.match(pattern.regex)?.[0]
      });
    }
  }

  // 4. Package / Delivery Smishing Signals
  const deliveryPatterns = [
    { regex: /package(?:.*?(?:cannot\s+be\s+delivered|held|undelivered|reschedule|delivery\s+failed|address|tracking))/i, label: 'Delivery / Parcel Interception Smishing' },
    { regex: /\b(?:usps|fedex|dhl|ups|postal\s+service)\b/i, label: 'Postal / Courier Brand Impersonation' },
    { regex: /unpaid\s+toll|toll\s+fee|sunpass|ezpass/i, label: 'Fake Highway Toll Invoice' }
  ];

  for (const pattern of deliveryPatterns) {
    if (pattern.regex.test(text)) {
      heuristicScore += 20;
      indicators.push({
        id: `delivery-${pattern.label.toLowerCase().replace(/\s+/g, '-')}`,
        name: pattern.label,
        severity: 'high',
        category: 'urgency',
        description: 'Impersonating postal couriers or toll authorities with missing parcel lures is a major smishing vector.',
        evidence: text.match(pattern.regex)?.[0]
      });
    }
  }

  // 5. Embedded link analysis in message
  if (extractedLinks.length > 0) {
    let linkRiskSum = 0;
    for (const link of extractedLinks) {
      const linkAnalysis = analyzeUrlHeuristics(link);
      linkRiskSum += linkAnalysis.heuristicScore;
      if (linkAnalysis.heuristicScore > 40) {
        indicators.push({
          id: `embedded-suspicious-link-${link.slice(0, 15)}`,
          name: 'Suspicious Hyperlink Embedded in Message',
          severity: 'high',
          category: 'technical',
          description: `Extracted link (${link}) triggers elevated phishing markers.`,
          evidence: link
        });
      }
    }
    heuristicScore += Math.min(30, Math.floor(linkRiskSum / extractedLinks.length * 0.5));
  }

  // 6. Generic or Spoofed Institutional Signatures
  if (/dear\s+(?:customer|user|client|account\s+holder|member)/i.test(text)) {
    heuristicScore += 10;
    indicators.push({
      id: 'impersonal-greeting',
      name: 'Generic Impersonal Salutation',
      severity: 'low',
      category: 'linguistic',
      description: 'Phishing campaigns sent en-masse rarely possess genuine user names and default to generic greetings.',
      evidence: text.match(/dear\s+[a-z\s]+/i)?.[0]
    });
  }

  const technical: TechnicalDetails = {
    messageLength: text.length,
    urgencyScore: matchedUrgencyCount,
    extractedLinks
  };

  return {
    indicators,
    technical,
    heuristicScore: Math.min(100, Math.max(0, heuristicScore)),
    extractedLinks
  };
}
