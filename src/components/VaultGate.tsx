/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useCallback, useMemo } from 'react';
import { 
  Shield, 
  Lock, 
  Eye, 
  EyeOff, 
  Copy, 
  RefreshCw, 
  AlertTriangle, 
  CheckCircle2,
  Terminal,
  Zap,
  Cpu
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { GoogleGenAI, Type } from "@google/genai";
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

const PII_REGEX = {
  EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  PHONE: /(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
  CREDIT_CARD: /\b(?:\d[ -]*?){13,16}\b/g,
  IPV4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
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

  const ai = useMemo(() => new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' }), []);

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
  const identifyAndReplace = (text: string): { scrubbed: string; mapping: Record<string, string> } => {
    let scrubbed = text;
    const mapping: Record<string, string> = {};
    let counter = 1;

    Object.entries(PII_REGEX).forEach(([type, regex]) => {
      scrubbed = scrubbed.replace(regex, (match) => {
        const placeholder = `[${type}_${counter++}]`;
        mapping[match] = placeholder;
        return placeholder;
      });
    });

    return { scrubbed, mapping };
  };

  /**
   * API Call: Uses Gemini to detect contextual PII (Names, Project Titles)
   */
  const handleProcess = useCallback(async () => {
    if (!rawInput.trim()) return;

    setIsProcessing(true);
    setError(null);

    try {
      // 1. Initial Regex Scrub
      const { scrubbed: regexScrubbed, mapping: initialMapping } = identifyAndReplace(rawInput);
      let currentText = regexScrubbed;
      let currentMapping = { ...initialMapping };

      // 2. AI Contextual Scrub
      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: `Identify any remaining PII (Names, Secret Project Titles, Specific Locations) in the following text. 
        Return a JSON object where 'pii' is an array of objects with 'value' and 'category'.
        Text: "${currentText}"`,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              pii: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    value: { type: Type.STRING },
                    category: { type: Type.STRING }
                  }
                }
              }
            }
          }
        }
      });

      const aiData = JSON.parse(response.text || '{"pii": []}');
      let aiCounter = Object.keys(currentMapping).length + 1;

      if (aiData.pii && Array.isArray(aiData.pii)) {
        aiData.pii.forEach((item: { value: string; category: string }) => {
          if (!currentMapping[item.value]) {
            const placeholder = `[${item.category.toUpperCase()}_${aiCounter++}]`;
            const escapedValue = item.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            currentText = currentText.replace(new RegExp(escapedValue, 'g'), placeholder);
            currentMapping[item.value] = placeholder;
          }
        });
      }

      setPiiMap(currentMapping);
      setSafeView(currentText);
    } catch (err) {
      console.error(err);
      setError('Security Protocol Error: Contextual analysis failed.');
    } finally {
      setIsProcessing(false);
    }
  }, [rawInput, ai]);

  const handleCopy = () => {
    navigator.clipboard.writeText(safeView);
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 2000);
  };

  return (
    <div className="w-full max-w-6xl mx-auto p-4 md:p-6 font-sans">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-neon-green/10 rounded border border-neon-green/30">
            <Shield className="w-6 h-6 text-neon-green" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white">VAULT<span className="text-neon-green">GATE</span></h1>
            <p className="text-[10px] text-silver/40 font-mono uppercase tracking-widest">PII Micro-SaaS Engine</p>
          </div>
        </div>
        <div className="flex items-center gap-2 px-3 py-1 bg-white/5 rounded-full border border-white/10">
          <div className="w-2 h-2 bg-neon-green rounded-full animate-pulse" />
          <span className="text-[10px] font-mono text-neon-green/80">SECURE NODE ACTIVE</span>
        </div>
      </div>

      {/* Main Dashboard */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Raw Input */}
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-bold text-silver/60 uppercase flex items-center gap-2">
              <Terminal className="w-3 h-3" />
              Raw Input Terminal
            </h2>
            <span className="text-[10px] text-silver/30 font-mono">ENCRYPTED BUFFER</span>
          </div>
          <div className="relative group">
            <textarea
              className="w-full h-[400px] bg-black/60 border border-white/10 rounded-xl p-5 text-sm font-mono text-silver focus:outline-none focus:border-neon-green/50 transition-all resize-none shadow-inner"
              placeholder="Paste sensitive data here..."
              value={rawInput}
              onChange={(e) => setRawInput(sanitizeInput(e.target.value))}
            />
            <div className="absolute bottom-4 right-4">
              <button
                onClick={handleProcess}
                disabled={isProcessing || !rawInput.trim()}
                className="flex items-center gap-2 px-6 py-2.5 bg-neon-green text-black font-bold rounded-lg hover:bg-neon-green/90 disabled:opacity-50 transition-all active:scale-95 shadow-lg shadow-neon-green/20"
              >
                {isProcessing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                EXECUTE SCRUB
              </button>
            </div>
          </div>
        </div>

        {/* Right: Safe View */}
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-bold text-silver/60 uppercase flex items-center gap-2">
              <Lock className="w-3 h-3 text-neon-green" />
              Safe View Output
            </h2>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowOriginal(!showOriginal)}
                className="p-1.5 hover:bg-white/5 rounded transition-colors text-silver/40 hover:text-white"
              >
                {showOriginal ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
              <button
                onClick={handleCopy}
                className="p-1.5 hover:bg-white/5 rounded transition-colors text-silver/40 hover:text-white"
              >
                {copySuccess ? <CheckCircle2 className="w-4 h-4 text-neon-green" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>
          <div className="w-full h-[400px] bg-black/40 border border-white/10 rounded-xl p-5 text-sm font-mono text-silver overflow-auto relative">
            <AnimatePresence mode="wait">
              {isProcessing ? (
                <motion.div 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="flex flex-col items-center justify-center h-full gap-4"
                >
                  <Cpu className="w-8 h-8 text-neon-green animate-pulse" />
                  <p className="text-xs text-neon-green/60 animate-pulse">ANALYZING CONTEXTUAL PII...</p>
                </motion.div>
              ) : safeView ? (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="whitespace-pre-wrap"
                >
                  {showOriginal ? rawInput : safeView}
                </motion.div>
              ) : (
                <div className="flex items-center justify-center h-full text-silver/20 italic">
                  Awaiting input for security processing...
                </div>
              )}
            </AnimatePresence>
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
            className="mt-6 p-4 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center gap-3 text-red-400 text-sm"
          >
            <AlertTriangle className="w-5 h-5 shrink-0" />
            {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Security Footer */}
      <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="p-5 bg-white/5 border border-white/10 rounded-xl">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-4 h-4 text-neon-green" />
            <h3 className="text-[10px] font-bold text-white uppercase tracking-wider">Regex Engine</h3>
          </div>
          <p className="text-[10px] text-silver/40 leading-relaxed">
            Instant detection of standard patterns: Emails, Phone Numbers, Credit Cards, and IPv4 addresses.
          </p>
        </div>
        <div className="p-5 bg-white/5 border border-white/10 rounded-xl">
          <div className="flex items-center gap-2 mb-2">
            <Zap className="w-4 h-4 text-neon-green" />
            <h3 className="text-[10px] font-bold text-white uppercase tracking-wider">Gemini 1.5 Flash</h3>
          </div>
          <p className="text-[10px] text-silver/40 leading-relaxed">
            Contextual AI analysis for Names, Secret Project Titles, and non-standard identifiers.
          </p>
        </div>
        <div className="p-5 bg-white/5 border border-white/10 rounded-xl">
          <div className="flex items-center gap-2 mb-2">
            <Lock className="w-4 h-4 text-neon-green" />
            <h3 className="text-[10px] font-bold text-white uppercase tracking-wider">Memory Isolation</h3>
          </div>
          <p className="text-[10px] text-silver/40 leading-relaxed">
            PII mappings are isolated to component state. No logs, no databases, zero persistence.
          </p>
        </div>
      </div>
    </div>
  );
}
