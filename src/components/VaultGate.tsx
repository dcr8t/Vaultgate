/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useCallback } from 'react';
import { 
  Shield, 
  Lock, 
  Eye, 
  EyeOff, 
  Copy, 
  RefreshCw, 
  AlertTriangle, 
  CheckCircle2,
  Zap,
  Cpu,
  Database,
  FileText,
  Sparkles,
  UserCheck
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import DOMPurify from 'dompurify';

// --- Security Utilities ---

const PROMPT_INJECTION_PATTERNS = [
  /ignore previous instructions/gi,
  /system prompt/gi,
  /you are now/gi,
  /forget everything/gi,
  /disregard all/gi,
  /bypass/gi,
];

/**
 * Robust Regex Patterns for PII Detection
 */
const PII_REGEX = {
  EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  PHONE: /(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
  CREDIT_CARD: /\b(?:\d[ -]*?){13,16}\b/g,
  IPV4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  IPV6: /\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b/gi,
  SSN: /\b\d{3}-\d{2}-\d{4}\b/g,
  ZIP_CODE: /\b\d{5}(?:-\d{4})?\b/g,
  DATE: /\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4})|(?:\d{4}[/-]\d{1,2}[/-]\d{1,2})\b/g,
  MAC_ADDRESS: /\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b/g,
  API_KEY: /\b(?:[a-zA-Z0-9-_]{32,}|(?:sk|pk|ak|sec|key|token|access|secret|auth)[_-][a-zA-Z0-9]{8,}|[a-zA-Z0-9]{20,})\b/gi,
  GENERIC_SECRET: /\b[a-zA-Z0-9+/=]{24,}\b/g,
  SECRET_ASSIGNMENT: /\b(?:password|secret|token|api_key|apikey|auth_token)\s*[:=]\s*[^\s]{4,}\b/gi,
  STREET_ADDRESS: /\d+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way)\b/gi,
  NAME_HEURISTIC: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b/g,
};

// --- VaultGate Component ---

export default function VaultGate() {
  const [rawInput, setRawInput] = useState('');
  const [safeView, setSafeView] = useState('');
  const [piiMap, setPiiMap] = useState<Record<string, string>>({});
  const [isProcessing, setIsProcessing] = useState(false);
  const [showOriginal, setShowOriginal] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copySuccess, setCopySuccess] = useState(false);

  /**
   * Sanitizes input for XSS and Prompt Injection
   */
  const sanitizeInput = (text: string): string => {
    let clean = DOMPurify.sanitize(text);
    PROMPT_INJECTION_PATTERNS.forEach(pattern => {
      clean = clean.replace(pattern, '[REDACTED_INJECTION]');
    });
    return clean;
  };

  /**
   * Core Logic: Identifies PII via Regex and replaces with placeholders
   */
  const executeScrub = useCallback(() => {
    if (!rawInput.trim()) return;

    setIsProcessing(true);
    setError(null);

    // Simulate a small delay for "processing" feel
    setTimeout(() => {
      try {
        let scrubbed = rawInput;
        const mapping: Record<string, string> = {};
        let counter = 1;

        Object.entries(PII_REGEX).forEach(([type, regex]) => {
          scrubbed = scrubbed.replace(regex, (match) => {
            if (match.startsWith('[') && match.endsWith(']')) return match;
            
            const placeholder = `[${type}_${counter++}]`;
            mapping[match] = placeholder;
            return placeholder;
          });
        });

        setPiiMap(mapping);
        setSafeView(scrubbed);
      } catch (err) {
        console.error(err);
        setError('Something went wrong while cleaning your text. Please try again.');
      } finally {
        setIsProcessing(false);
      }
    }, 600);
  }, [rawInput]);

  const handleCopy = () => {
    navigator.clipboard.writeText(showOriginal ? rawInput : safeView);
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 2000);
  };

  return (
    <div className="w-full max-w-6xl mx-auto p-4 md:p-6 font-sans">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between mb-8 gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-neon-green/10 rounded-lg border border-neon-green/30 shadow-[0_0_15px_rgba(57,255,20,0.1)]">
            <Shield className="w-8 h-8 text-neon-green" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-white">Vault<span className="text-neon-green">Gate</span></h1>
            <p className="text-sm text-silver/60">Private & Secure Text Cleaner</p>
          </div>
        </div>
        <div className="flex items-center gap-2 px-4 py-2 bg-white/5 rounded-full border border-white/10">
          <UserCheck className="w-4 h-4 text-neon-green" />
          <span className="text-xs font-medium text-neon-green/90 uppercase tracking-wide">100% Private • No Data Leaves Your Device</span>
        </div>
      </div>

      {/* Intro */}
      <div className="mb-8 p-4 bg-white/5 rounded-xl border border-white/10">
        <p className="text-sm text-silver/80 leading-relaxed">
          Paste your text below to automatically remove sensitive information like names, emails, and phone numbers. 
          Everything happens <span className="text-neon-green font-semibold">locally in your browser</span>—your data is never sent to any server.
        </p>
      </div>

      {/* Main Dashboard */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Left: Input */}
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between px-1">
            <h2 className="text-sm font-bold text-white uppercase flex items-center gap-2">
              <FileText className="w-4 h-4 text-neon-green" />
              Step 1: Paste Your Text
            </h2>
          </div>
          <div className="relative group">
            <textarea
              className="w-full h-[450px] bg-black/60 border border-white/10 rounded-2xl p-6 text-base font-sans text-silver focus:outline-none focus:border-neon-green/50 transition-all resize-none shadow-2xl"
              placeholder="Paste your sensitive email, log, or document here..."
              value={rawInput}
              onChange={(e) => setRawInput(sanitizeInput(e.target.value))}
            />
            <div className="absolute bottom-6 right-6">
              <button
                onClick={executeScrub}
                disabled={isProcessing || !rawInput.trim()}
                className="flex items-center gap-2 px-8 py-3 bg-neon-green text-black font-bold rounded-xl hover:bg-neon-green/90 disabled:opacity-50 transition-all active:scale-95 shadow-[0_0_20px_rgba(57,255,20,0.3)]"
              >
                {isProcessing ? <RefreshCw className="w-5 h-5 animate-spin" /> : <Sparkles className="w-5 h-5" />}
                Clean My Text
              </button>
            </div>
          </div>
        </div>

        {/* Right: Output */}
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between px-1">
            <h2 className="text-sm font-bold text-white uppercase flex items-center gap-2">
              <Lock className="w-4 h-4 text-neon-green" />
              Step 2: Your Cleaned Version
            </h2>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowOriginal(!showOriginal)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg transition-all text-xs font-medium border ${
                  showOriginal 
                    ? 'bg-neon-green/10 border-neon-green text-neon-green' 
                    : 'bg-white/5 border-white/10 text-silver/60 hover:text-white hover:bg-white/10'
                }`}
                title={showOriginal ? "Show Cleaned" : "Show Original"}
              >
                {showOriginal ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                {showOriginal ? "Viewing Original" : "View Original"}
              </button>
              <button
                onClick={handleCopy}
                disabled={!safeView}
                className="flex items-center gap-2 px-3 py-1.5 bg-white/5 border border-white/10 rounded-lg transition-all text-xs font-medium text-silver/60 hover:text-white hover:bg-white/10 disabled:opacity-30"
              >
                {copySuccess ? <CheckCircle2 className="w-4 h-4 text-neon-green" /> : <Copy className="w-4 h-4" />}
                Copy
              </button>
            </div>
          </div>
          <div className="relative w-full h-[450px]">
            <AnimatePresence mode="wait">
              {isProcessing ? (
                <motion.div 
                  key="processing"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="absolute inset-0 z-10 flex flex-col items-center justify-center bg-black/60 backdrop-blur-sm rounded-2xl border border-white/10 gap-4"
                >
                  <Cpu className="w-12 h-12 text-neon-green animate-pulse" />
                  <p className="text-sm font-medium text-neon-green animate-pulse uppercase tracking-widest">Cleaning in progress...</p>
                </motion.div>
              ) : null}
            </AnimatePresence>
            
            <textarea
              className={`w-full h-full bg-black/40 border border-white/10 rounded-2xl p-6 text-base font-sans transition-all resize-none shadow-2xl focus:outline-none focus:border-neon-green/30 ${
                showOriginal ? 'text-silver/40 italic select-none pointer-events-none' : 'text-silver'
              }`}
              placeholder="Your cleaned text will appear here..."
              value={showOriginal ? rawInput : safeView}
              onChange={(e) => !showOriginal && setSafeView(e.target.value)}
              readOnly={showOriginal}
            />
            
            {!showOriginal && safeView && (
              <div className="absolute top-4 right-4 pointer-events-none">
                <span className="px-2 py-1 bg-neon-green/10 text-[10px] font-bold text-neon-green/60 uppercase rounded border border-neon-green/20">
                  Editable
                </span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Error Message */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            className="mt-8 p-4 bg-red-500/10 border border-red-500/30 rounded-2xl flex items-center gap-3 text-red-400 text-sm shadow-lg"
          >
            <AlertTriangle className="w-5 h-5 shrink-0" />
            {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Security Footer */}
      <div className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-8">
        <div className="p-6 bg-white/5 border border-white/10 rounded-2xl hover:bg-white/[0.07] transition-all">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 bg-neon-green/10 rounded-lg">
              <Shield className="w-5 h-5 text-neon-green" />
            </div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">Smart Cleaning</h3>
          </div>
          <p className="text-xs text-silver/50 leading-relaxed">
            Automatically finds and removes emails, phone numbers, addresses, and more using advanced pattern matching.
          </p>
        </div>
        <div className="p-6 bg-white/5 border border-white/10 rounded-2xl hover:bg-white/[0.07] transition-all">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 bg-neon-green/10 rounded-lg">
              <Database className="w-5 h-5 text-neon-green" />
            </div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">No Server Needed</h3>
          </div>
          <p className="text-xs text-silver/50 leading-relaxed">
            Unlike other tools, we don't send your data to the cloud. All the cleaning happens right here on your computer.
          </p>
        </div>
        <div className="p-6 bg-white/5 border border-white/10 rounded-2xl hover:bg-white/[0.07] transition-all">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 bg-neon-green/10 rounded-lg">
              <Lock className="w-5 h-5 text-neon-green" />
            </div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">Total Privacy</h3>
          </div>
          <p className="text-xs text-silver/50 leading-relaxed">
            Your sensitive data never touches our servers. Once you close this tab, everything is gone forever.
          </p>
        </div>
      </div>

      {/* Mobile Optimization Hint */}
      <div className="mt-12 text-[10px] font-mono text-silver/20 text-center uppercase tracking-[0.2em]">
        VaultGate Secure Node • Version 1.1.0
      </div>
    </div>
  );
}
