import React, { useState } from 'react';
import { Mail, MessageSquare, Smartphone, ArrowRight, Shield, AlertTriangle } from 'lucide-react';
import { MessageSubtype } from '../types/threat.js';

interface MessageScannerTabProps {
  onScan: (message: string, subtype: MessageSubtype) => Promise<void>;
  isLoading: boolean;
}

const PRESET_MESSAGES = [
  {
    label: 'USPS Smishing Alert',
    subtype: 'sms' as MessageSubtype,
    category: 'Smishing',
    text: 'USPS: Your package 940011189922 could not be delivered due to an incomplete delivery address. Please update your details within 24 hours at https://us-postal-redeliver.top/tracking to prevent the parcel from being returned to sender.'
  },
  {
    label: 'CEO Wire Transfer Fraud',
    subtype: 'email' as MessageSubtype,
    category: 'BEC Scam',
    text: 'URGENT: I am currently in a closed-door board meeting and cannot take phone calls. We need an immediate wire transfer of $38,500 processed for vendor acquisition before 3 PM. Transfer details: Chase Bank Acct #99281-B. Confirm once sent.'
  },
  {
    label: 'Bank Account Suspension',
    subtype: 'email' as MessageSubtype,
    category: 'Credential Phishing',
    text: 'Dear Customer, Unusual login activity from Moscow, Russia was detected on your checking account. Your account has been temporarily locked. Verify your identity immediately by confirming your SSN, password, and 2FA code at https://chase-bank-security-center.xyz/auth'
  },
  {
    label: 'Crypto Wallet Recovery Seed',
    subtype: 'chat' as MessageSubtype,
    category: 'Crypto Drainer',
    text: 'MetaMask Support: A synchronization conflict was detected in your Ethereum wallet block. To prevent wallet forfeiture, submit your 12-word Secret Recovery Phrase to the official migration bridge to validate ownership.'
  },
  {
    label: 'Legitimate Calendar Invite',
    subtype: 'email' as MessageSubtype,
    category: 'Legitimate',
    text: 'Hi Alex, quick reminder about our Q4 product review scheduled for Thursday at 2:00 PM EST via Google Meet. The agenda and slides are attached in the shared drive. Let me know if you need to adjust the timing.'
  },
  {
    label: 'Legitimate Team Chat',
    subtype: 'chat' as MessageSubtype,
    category: 'Legitimate',
    text: 'Hey team, the latest Docker build passed all staging integration tests. We will deploy the release to production at 18:00 UTC. Please monitor the Datadog alert channel.'
  }
];

export const MessageScannerTab: React.FC<MessageScannerTabProps> = ({ onScan, isLoading }) => {
  const [messageInput, setMessageInput] = useState('');
  const [subtype, setSubtype] = useState<MessageSubtype>('email');
  const [inputError, setInputError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!messageInput.trim()) {
      setInputError('Please enter message text to scan.');
      return;
    }
    if (messageInput.trim().length < 5) {
      setInputError('Message is too short for threat pattern extraction.');
      return;
    }
    setInputError(null);
    onScan(messageInput.trim(), subtype);
  };

  const handleSelectPreset = (item: typeof PRESET_MESSAGES[0]) => {
    setMessageInput(item.text);
    setSubtype(item.subtype);
    setInputError(null);
  };

  return (
    <div className="space-y-6">
      {/* Scanner Card */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-800/80 mb-5">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Mail className="w-4 h-4 text-red-400" />
              Message & Social Engineering Scanner
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspect suspicious emails, SMS texts (smishing), and team chat messages for coercive psychological hooks and fraud lures.
            </p>
          </div>

          {/* Subtype Selector */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 self-start sm:self-auto">
            <button
              type="button"
              onClick={() => setSubtype('email')}
              className={`flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-md transition-colors ${
                subtype === 'email'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              Email
            </button>
            <button
              type="button"
              onClick={() => setSubtype('sms')}
              className={`flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-md transition-colors ${
                subtype === 'sms'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Smartphone className="w-3.5 h-3.5" />
              SMS / Smishing
            </button>
            <button
              type="button"
              onClick={() => setSubtype('chat')}
              className={`flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-md transition-colors ${
                subtype === 'chat'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <MessageSquare className="w-3.5 h-3.5" />
              Chat / Direct Msg
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="relative">
            <textarea
              rows={5}
              value={messageInput}
              onChange={(e) => {
                setMessageInput(e.target.value);
                if (inputError) setInputError(null);
              }}
              placeholder={`Paste the full text of the suspicious ${subtype} here... (e.g. sender headers, body text, urgent demands, or embedded hyperlinks)`}
              className="w-full p-4 bg-slate-950 border border-slate-700/80 rounded-lg text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500 font-sans transition-all resize-y"
              disabled={isLoading}
            />
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
            <div className="text-xs text-slate-500 font-mono">
              Length: <span className="text-slate-400 tabular-nums">{messageInput.length}</span> characters
            </div>

            <div className="flex items-center gap-3">
              {messageInput && (
                <button
                  type="button"
                  onClick={() => setMessageInput('')}
                  className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1.5"
                >
                  Clear
                </button>
              )}
              <button
                type="submit"
                disabled={isLoading}
                className="px-5 py-2.5 bg-red-600 hover:bg-red-500 disabled:bg-slate-800 text-white text-xs font-semibold rounded-md transition-colors flex items-center gap-2 shadow-sm"
              >
                {isLoading ? (
                  <>
                    <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Analyzing Content...</span>
                  </>
                ) : (
                  <>
                    <span>Scan Message Content</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            </div>
          </div>

          {inputError && (
            <div className="text-xs text-red-400 flex items-center gap-1.5 pl-1">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              {inputError}
            </div>
          )}
        </form>

        {/* Preset Sample Targets */}
        <div className="mt-6 pt-5 border-t border-slate-800/60">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-3">
            <span className="font-medium text-slate-300">Quick Test Scenarios:</span>
            <span className="text-[11px] text-slate-500">Click to populate message</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {PRESET_MESSAGES.map((preset, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSelectPreset(preset)}
                className="text-left p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 hover:bg-slate-950 transition-all group"
              >
                <div className="flex items-center justify-between gap-1 mb-1">
                  <span className="text-xs font-medium text-slate-200 group-hover:text-red-300 transition-colors">
                    {preset.label}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono uppercase">
                    {preset.subtype}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 line-clamp-2">
                  {preset.text}
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Social Engineering Guide Strip */}
      <div className="bg-slate-900/30 border border-slate-800/60 rounded-lg p-4 flex items-start gap-3">
        <Shield className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-400 leading-relaxed">
          <strong className="text-slate-300 font-semibold">Social Engineering Heuristic Focus:</strong> PhishGuard inspects messages for psychological coercion vectors: artificial urgency (&lt;24 hours), fear-inducing account lockouts, impersonated executive authority, and out-of-band communication blocks.
        </div>
      </div>
    </div>
  );
};
