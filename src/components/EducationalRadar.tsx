import React from 'react';
import { 
  ShieldAlert, QrCode, Smartphone, Globe, 
  KeyRound, Users, CheckCircle2, AlertTriangle, ShieldCheck 
} from 'lucide-react';

const THREAT_VECTORS = [
  {
    id: 'quishing',
    title: 'QR Code Phishing ("Quishing")',
    category: 'Evasion Vector',
    icon: QrCode,
    description: 'Attackers embed malicious redirect URLs inside QR codes in PDFs or emails. Traditional email security scanners fail to parse image pixels, allowing the lure to reach the victim’s mobile browser.',
    defense: 'Never scan QR codes in unsolicited emails requesting password changes or 2FA confirmations.'
  },
  {
    id: 'aitm',
    title: 'Adversary-in-the-Middle (AitM) Phishing',
    category: 'Session Hijacking',
    icon: KeyRound,
    description: 'Proxies like Evilginx2 sit between the victim and authentic portals (Microsoft 365, Google Workspace). The attacker captures the live session cookie directly, bypassing standard OTP and SMS 2FA.',
    defense: 'Enforce FIDO2/WebAuthn hardware security keys which bind the browser domain origin to the cryptographic handshake.'
  },
  {
    id: 'smishing',
    title: 'Postal & Highway Toll Smishing',
    category: 'SMS Engineering',
    icon: Smartphone,
    description: 'Mass SMS text campaigns alleging missed USPS, FedEx, or SunPass payments with links ending in disposable TLDs (.top, .xyz). Designed to steal credit card numbers under small $2-$5 payment pretexts.',
    defense: 'Ignore SMS delivery notices from unknown shortcodes. Verify tracking directly on official courier apps.'
  },
  {
    id: 'bec',
    title: 'Business Email Compromise (BEC)',
    category: 'Executive Impersonation',
    icon: Users,
    description: 'Threat actors spoof corporate executives or vendors requesting urgent off-channel wire transfers, gift card purchases, or modified invoice routing numbers.',
    defense: 'Mandate verbal dual-control verification via verified internal phone extensions before executing financial wires.'
  },
  {
    id: 'homoglyph',
    title: 'IDN Homograph & Typosquatting',
    category: 'Domain Deception',
    icon: Globe,
    description: 'Using Unicode characters (Punycode xn--) or lookalike numerals (e.g., paypa1.com, micros0ft.com) to deceive users into believing they are interacting with legitimate institutions.',
    defense: 'Inspect the address bar certificate and check for punycode notation in browser navigation.'
  }
];

export const EducationalRadar: React.FC = () => {
  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Header */}
      <div className="pb-4 border-b border-slate-800">
        <div className="flex items-center gap-2 text-xs font-mono text-red-400 mb-1">
          <ShieldAlert className="w-4 h-4" />
          <span>CYBERSECURITY THREAT RADAR</span>
        </div>
        <h1 className="text-xl font-bold tracking-tight text-white">
          Active Phishing Vectors & Attack Anatomy
        </h1>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
          Intelligence overview of contemporary social engineering techniques, authentication bypass mechanisms, and defensive hardening strategies.
        </p>
      </div>

      {/* Vector Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {THREAT_VECTORS.map((vector) => {
          const Icon = vector.icon;
          return (
            <div 
              key={vector.id} 
              className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 transition-colors space-y-3"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 shrink-0">
                    <Icon className="w-4 h-4" />
                  </div>
                  <div>
                    <h2 className="text-sm font-semibold text-white">
                      {vector.title}
                    </h2>
                    <span className="text-[10px] font-mono text-slate-500 uppercase">
                      {vector.category}
                    </span>
                  </div>
                </div>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed font-sans">
                {vector.description}
              </p>

              <div className="pt-2 border-t border-slate-800/60 text-xs">
                <span className="text-slate-500 font-mono text-[11px] block mb-1">
                  Defensive Countermeasure:
                </span>
                <span className="text-slate-300 font-medium leading-relaxed block">
                  {vector.defense}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Security Best Practices Checklist */}
      <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>PhishGuard Organizational Defense Principles</span>
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs text-slate-300">
          <div className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800/80">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-200 block font-semibold">1. Inspect the Root Domain</strong>
              <span>Always verify the 2-level root domain (e.g., paypal.com, not paypal.account-update.xyz).</span>
            </div>
          </div>

          <div className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800/80">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-200 block font-semibold">2. Never Act Under Urgent Pressure</strong>
              <span>Artificial deadlines ("within 24 hours or account suspended") are designed to suppress critical thinking.</span>
            </div>
          </div>

          <div className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800/80">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-200 block font-semibold">3. Use Phishing-Resistant MFA</strong>
              <span>Upgrade from SMS/OTP codes to WebAuthn/FIDO2 hardware passkeys to thwart AitM reverse proxies.</span>
            </div>
          </div>

          <div className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800/80">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-200 block font-semibold">4. Out-of-Band Verification</strong>
              <span>Call senders on known, independently verified telephone lines before routing payments or sensitive data.</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
