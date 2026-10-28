/**
 * PhishGuard Threat Engine Automated Test Suite
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrlHeuristics, analyzeMessageHeuristics, calculateShannonEntropy, parseUrlSafely } from '../src/services/heuristicAnalyzer.js';
import { predictBaseline, extractFeatureVector } from '../src/services/mlBaseline.js';

describe('URL Parser & Security Sanitizer', () => {
  test('correctly parses legitimate standard URLs', () => {
    const res = parseUrlSafely('https://www.google.com/search?q=cybersecurity');
    assert.equal(res.isValid, true);
    assert.equal(res.hostname, 'www.google.com');
    assert.equal(res.tld, 'com');
  });

  test('normalizes URLs without protocol prefix', () => {
    const res = parseUrlSafely('github.com/torvalds/linux');
    assert.equal(res.isValid, true);
    assert.equal(res.hostname, 'github.com');
  });
});

describe('Shannon Entropy Calculation', () => {
  test('calculates lower entropy for repetitive or plain words', () => {
    const low = calculateShannonEntropy('google.com');
    const high = calculateShannonEntropy('x8f93qla01zks92ndla9.biz');
    assert.ok(high > low, 'Randomized strings must exhibit higher Shannon entropy');
  });
});

describe('URL Threat Heuristics', () => {
  test('flags brand typosquatting targeting PayPal', () => {
    const res = analyzeUrlHeuristics('https://paypa1-account-verify.xyz/login');
    assert.ok(res.heuristicScore >= 50, 'Score should be high for obvious typosquatting');
    const hasBrand = res.indicators.some(i => i.name.includes('PayPal'));
    assert.ok(hasBrand, 'Must detect PayPal brand impersonation');
    assert.equal(res.brandDetected, 'PayPal');
  });

  test('detects direct IP as host', () => {
    const res = analyzeUrlHeuristics('http://192.168.1.55/update-security');
    const hasIp = res.indicators.some(i => i.id === 'ip-as-host');
    assert.ok(hasIp, 'Must flag direct IP address in hostname');
  });

  test('detects Punycode homoglyph attack', () => {
    const res = analyzeUrlHeuristics('https://xn--pple-43d.com/store');
    const hasPunycode = res.indicators.some(i => i.id === 'punycode-homoglyph');
    assert.ok(hasPunycode, 'Must identify punycode (xn--) domain notation');
  });

  test('cleans legitimate official sites with minimal risk score', () => {
    const res = analyzeUrlHeuristics('https://docs.google.com/document');
    assert.ok(res.heuristicScore <= 20, 'Legitimate domain must have low heuristic score');
  });
});

describe('Message Scam & Smishing Heuristics', () => {
  test('flags SMS smishing with fake USPS delivery lure', () => {
    const sms = 'USPS: Your package 88910 cannot be delivered due to incomplete address. Update within 24 hours at https://us-postal-redeliver.top/tracking';
    const res = analyzeMessageHeuristics(sms);
    assert.ok(res.heuristicScore >= 50, 'Smishing message must trigger high risk score');
    const hasUrgency = res.indicators.some(i => i.category === 'urgency');
    assert.ok(hasUrgency, 'Must detect artificial urgency trigger');
  });

  test('flags CEO fraud / wire transfer request', () => {
    const email = 'URGENT: Please process an immediate wire transfer of $50,000 to vendor account today. Do not call, I am traveling.';
    const res = analyzeMessageHeuristics(email);
    assert.ok(res.heuristicScore >= 40, 'Financial wire lure must be flagged');
  });
});

describe('Baseline ML Model & Vectorizer', () => {
  test('extracts feature vector with correct shape', () => {
    const vec = extractFeatureVector('https://paypa1-security.xyz/login', true);
    assert.equal(typeof vec.brand_spoof, 'number');
    assert.equal(typeof vec.suspicious_tld, 'number');
    assert.equal(vec.brand_spoof, 1);
    assert.equal(vec.suspicious_tld, 1);
  });

  test('predicts malicious verdict for high-risk phishing URL', () => {
    const pred = predictBaseline('https://paypa1-account-login.xyz/auth', true);
    assert.ok(pred.score >= 70, `Score was ${pred.score}, expected >= 70`);
    assert.ok(pred.verdict === 'MALICIOUS_PHISHING' || pred.verdict === 'HIGH_RISK');
  });

  test('predicts safe verdict for benign mainstream URL', () => {
    const pred = predictBaseline('https://github.com/torvalds/linux', true);
    assert.ok(pred.score <= 30, `Score was ${pred.score}, expected <= 30`);
    assert.equal(pred.verdict, 'SAFE');
  });
});
