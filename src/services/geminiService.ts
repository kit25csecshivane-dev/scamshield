/**
 * Server-side Gemini AI Threat Intelligence Service
 * Uses @google/genai SDK with gemini-3.8-flash for explainable cybersecurity threat analysis.
 */

import { GoogleGenAI, Type, ThinkingLevel } from '@google/genai';
import { ScanResult, ScanType, ThreatVerdict, ThreatIndicator } from '../types/threat.js';
import { analyzeUrlHeuristics, analyzeMessageHeuristics } from './heuristicAnalyzer.js';
import { predictBaseline } from './mlBaseline.js';

let aiClient: GoogleGenAI | null = null;

function getAiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  if (!aiClient) {
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build'
        }
      }
    });
  }
  return aiClient;
}

export async function analyzeThreatWithGemini(
  input: string,
  type: ScanType,
  subtype?: 'email' | 'sms' | 'chat'
): Promise<ScanResult> {
  const isUrl = type === 'url';

  // 1. Run local deterministic heuristic and ML baseline first
  const heuristicData = isUrl
    ? analyzeUrlHeuristics(input)
    : analyzeMessageHeuristics(input);

  const mlPrediction = predictBaseline(input, isUrl);

  const ai = getAiClient();

  // If Gemini is not available or key is not configured, synthesize calibrated hybrid report
  if (!ai) {
    return buildFallbackReport(input, type, subtype, heuristicData, mlPrediction);
  }

  const prompt = isUrl
    ? `You are an expert Cybersecurity Threat Intelligence & SOC Analyst. Analyze this suspicious URL:
URL: "${input}"

Heuristic Engine Flags:
${JSON.stringify(heuristicData.indicators, null, 2)}
Technical Attributes:
${JSON.stringify(heuristicData.technical, null, 2)}
Baseline ML Model Risk Score: ${mlPrediction.score}/100 (Verdict: ${mlPrediction.verdict})

Perform a rigorous threat evaluation:
1. Identify if this is a phishing, credential harvester, malware distributor, typosquatting domain, or legitimate site.
2. If legitimate, assess risk score (0-20). If suspicious or malicious, score (21-100).
3. Identify any brand impersonated.
4. Extract specific technical and social engineering indicators with evidence.
5. Provide actionable, practical security recommendations.
6. MANDATORY CAVEAT: Explain the inherent uncertainty (e.g., zero-day infrastructure, newly registered domains, evasive cloaking, and false positive/negative risks). Never claim 100% certainty or unconditional safety.`
    : `You are an expert Cybersecurity Threat Intelligence & SOC Analyst. Analyze this suspicious ${subtype || 'message'}:
Content:
"""
${input}
"""

Heuristic Engine Flags:
${JSON.stringify(heuristicData.indicators, null, 2)}
Technical Attributes:
${JSON.stringify(heuristicData.technical, null, 2)}
Baseline ML Model Risk Score: ${mlPrediction.score}/100 (Verdict: ${mlPrediction.verdict})

Perform a rigorous threat evaluation:
1. Identify whether this is an email phishing lure, smishing (SMS scam), CEO fraud, tech support scam, delivery fee scam, or legitimate message.
2. Determine risk score (0-100) and calibrated confidence (0.0 - 1.0).
3. Identify targeted brand or organization if any.
4. Highlight urgency triggers, coercive tactics, payment/gift card demands, or link deception.
5. Provide actionable safety recommendations for the recipient.
6. MANDATORY CAVEAT: Explain uncertainty, false positives/negatives, and why the absence of obvious scam keywords does not guarantee safety.`;

  try {
    // Wrap Gemini call with 12-second timeout to maintain prompt UI responsiveness
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Gemini API call timed out')), 12000)
    );

    const apiCallPromise = ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        thinkingConfig: {
          thinkingLevel: ThinkingLevel.LOW
        },
        systemInstruction: `You are PhishGuard Threat Analysis AI. Output ONLY valid JSON adhering strictly to the requested schema. Avoid hyperbole. Base your risk score on genuine security evidence.`,
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            verdict: {
              type: Type.STRING,
              description: 'One of: SAFE, SUSPICIOUS, HIGH_RISK, MALICIOUS_PHISHING'
            },
            riskScore: {
              type: Type.INTEGER,
              description: 'Calibrated score from 0 to 100'
            },
            confidence: {
              type: Type.NUMBER,
              description: 'Calibrated confidence from 0.0 to 1.0'
            },
            threatType: {
              type: Type.STRING,
              description: 'E.g. Credential Harvesting, Brand Impersonation Phishing, Delivery Smishing, Safe / Benign'
            },
            impersonatedEntity: {
              type: Type.STRING,
              description: 'Name of impersonated brand or entity, or null if none'
            },
            indicators: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  name: { type: Type.STRING },
                  severity: { type: Type.STRING, description: 'low, medium, high, or critical' },
                  category: { type: Type.STRING, description: 'domain, linguistic, urgency, credential_lure, technical, reputation' },
                  description: { type: Type.STRING },
                  evidence: { type: Type.STRING }
                },
                required: ['name', 'severity', 'category', 'description']
              }
            },
            explanation: {
              type: Type.STRING,
              description: 'Clear, human-understandable explanation of why this was or was not flagged'
            },
            technicalAnalysis: {
              type: Type.STRING,
              description: 'Technical breakdown of infrastructure, linguistic markers, or obfuscation vectors'
            },
            recommendedActions: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: 'Concrete security steps the user or SOC team should take'
            },
            uncertaintyCaveat: {
              type: Type.STRING,
              description: 'Explicit statement addressing potential false positives, evasion techniques, and residual uncertainty'
            }
          },
          required: [
            'verdict',
            'riskScore',
            'confidence',
            'threatType',
            'indicators',
            'explanation',
            'technicalAnalysis',
            'recommendedActions',
            'uncertaintyCaveat'
          ]
        }
      }
    });

    const response = await Promise.race([apiCallPromise, timeoutPromise]);
    const parsedJson = JSON.parse(response.text || '{}');

    // Merge AI indicators with heuristic indicators to ensure comprehensive coverage
    const combinedIndicators: ThreatIndicator[] = [...heuristicData.indicators];
    if (Array.isArray(parsedJson.indicators)) {
      for (const item of parsedJson.indicators) {
        if (!combinedIndicators.some(ci => ci.name.toLowerCase() === item.name.toLowerCase())) {
          combinedIndicators.push({
            id: `ai-${Math.random().toString(36).substring(2, 8)}`,
            name: item.name,
            severity: (item.severity || 'medium') as any,
            category: (item.category || 'technical') as any,
            description: item.description,
            evidence: item.evidence
          });
        }
      }
    }

    // Calibrate verdict to valid enum
    let normalizedVerdict: ThreatVerdict = 'SAFE';
    const rawVerdict = String(parsedJson.verdict).toUpperCase();
    if (rawVerdict.includes('MALICIOUS') || rawVerdict.includes('PHISH')) {
      normalizedVerdict = 'MALICIOUS_PHISHING';
    } else if (rawVerdict.includes('HIGH')) {
      normalizedVerdict = 'HIGH_RISK';
    } else if (rawVerdict.includes('SUSPICIOUS')) {
      normalizedVerdict = 'SUSPICIOUS';
    }

    const calibratedScore = Math.min(100, Math.max(0, Number(parsedJson.riskScore) || mlPrediction.score));

    return {
      id: `scan-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      target: input,
      type,
      subtype,
      riskScore: calibratedScore,
      verdict: normalizedVerdict,
      confidence: Math.min(1.0, Math.max(0.1, Number(parsedJson.confidence) || 0.85)),
      threatType: parsedJson.threatType || (calibratedScore > 60 ? 'Suspicious Phishing Vector' : 'Clean Asset'),
      impersonatedEntity: parsedJson.impersonatedEntity || heuristicData.technical.impersonatedBrand || null,
      indicators: combinedIndicators,
      explanation: parsedJson.explanation || 'Analyzed via dual-pass cybersecurity AI intelligence model.',
      technicalDetails: {
        ...heuristicData.technical,
        impersonatedBrand: parsedJson.impersonatedEntity || heuristicData.technical.impersonatedBrand
      },
      recommendedActions: parsedJson.recommendedActions || [
        'Do not submit login credentials or personal data.',
        'Verify communications directly through official channels.',
        'Report suspicious incident to information security.'
      ],
      uncertaintyCaveat: parsedJson.uncertaintyCaveat || 'Automated analysis cannot provide 100% certainty. Clean results do not guarantee absolute safety from sophisticated zero-day attack infrastructure.',
      engineUsed: 'gemini-ai',
      mlBaseline: mlPrediction
    };
  } catch (err: any) {
    console.error('Gemini API call failed, falling back to local ML engine:', err?.message || err);
    return buildFallbackReport(input, type, subtype, heuristicData, mlPrediction);
  }
}

/**
 * Robust fallback report synthesis using deterministic ML Baseline and Heuristics
 */
function buildFallbackReport(
  input: string,
  type: ScanType,
  subtype: 'email' | 'sms' | 'chat' | undefined,
  heuristicData: ReturnType<typeof analyzeUrlHeuristics> | ReturnType<typeof analyzeMessageHeuristics>,
  mlPrediction: ReturnType<typeof predictBaseline>
): ScanResult {
  const isUrl = type === 'url';
  const score = mlPrediction.score;
  const verdict = mlPrediction.verdict;

  let threatType = 'Benign / Low Risk Content';
  if (verdict === 'MALICIOUS_PHISHING') {
    threatType = isUrl ? 'Credential Harvesting Phishing Link' : 'Targeted Social Engineering Scam';
  } else if (verdict === 'HIGH_RISK') {
    threatType = isUrl ? 'High-Risk Lookalike Domain' : 'Suspicious Coercive Solicitation';
  } else if (verdict === 'SUSPICIOUS') {
    threatType = 'Anomalous Threat Indicators Detected';
  }

  const actions = score >= 50 ? [
    'Do NOT open the link or enter sensitive credentials.',
    'Do not reply or provide 2FA tokens, gift cards, or wire transfers.',
    'Navigate directly to the official organization website by typing the verified URL in your browser.',
    'Report the indicator to your organization’s Security Operations Center (SOC).'
  ] : [
    'No high-confidence phishing patterns were matched by the initial feature vector.',
    'Remain vigilant: Always verify the sender address and domain certificate before entering sensitive information.',
    'Do not bypass multi-factor authentication prompts without independent confirmation.'
  ];

  return {
    id: `scan-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    timestamp: new Date().toISOString(),
    target: input,
    type,
    subtype,
    riskScore: score,
    verdict,
    confidence: mlPrediction.confidence,
    threatType,
    impersonatedEntity: heuristicData.technical.impersonatedBrand || null,
    indicators: heuristicData.indicators,
    explanation: score >= 50
      ? `The target exhibits ${heuristicData.indicators.length} elevated threat markers according to the PhishGuard heuristic and logistic regression baseline classifier.`
      : `The target does not exhibit overt phishing triggers in its structural features, though continued caution is advised.`,
    technicalDetails: heuristicData.technical,
    recommendedActions: actions,
    uncertaintyCaveat: 'DISCLAIMER: Threat classification models evaluate structural, lexical, and behavioral markers. Zero-day attacks and legitimate compromised infrastructure may appear benign. Conversely, novel benign sites may trigger statistical false positives.',
    engineUsed: 'ml-baseline-heuristic',
    mlBaseline: mlPrediction
  };
}
