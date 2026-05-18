/**
 * Input Sanitization & PII Scrubbing
 *
 * NIST AI RMF 1.0 — MANAGE Function (MG-2.2)
 * NIST AI 600-1 — Prompt Injection (GV-6.2), Data Privacy (MS-2.5)
 *
 * Unicode normalization (NFKC) is applied before pattern matching to defeat
 * lookalike-character and zero-width-character injection bypasses. The normalized
 * text is what gets stored and forwarded — the original is only hashed for audit.
 */

import { createHash } from 'crypto';
import { re2Pattern } from './safe-regex';

export interface SanitizedInput {
  sanitized: string;
  originalHash: string;
  injectionDetected: boolean;
  detectedPatterns: string[];
  truncated: boolean;
}

export interface PIIScrubResult {
  scrubbed: string;
  piiInstancesFound: number;
  piiCategories: string[];
}

const MAX_INPUT_LENGTH = 4000;

// ─────────────────────────────────────────────────────────────────────────────
// Unicode normalization — collapse lookalikes and invisible characters
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Normalize text before injection detection.
 * Collapses Unicode lookalike characters (NFKC), strips zero-width characters
 * that can fragment patterns invisibly, and collapses repeated whitespace.
 * This is the text that pattern matching runs against and that gets forwarded.
 */
function normalizeForDetection(input: string): string {
  return input
    .normalize('NFKC')                                    // collapse Unicode lookalikes (е→e, ﬁ→fi, etc.)
    .replace(/[​-‍⁠﻿­]/g, '')   // strip zero-width and soft-hyphen chars
    .replace(/\s+/g, ' ')                                  // collapse whitespace
    .trim();
}

// ─────────────────────────────────────────────────────────────────────────────
// Injection patterns
// ─────────────────────────────────────────────────────────────────────────────

// STRIDE T-6: compiled with RE2 for guaranteed linear-time matching
const INJECTION_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: re2Pattern('ignore\\s+(all\\s+)?(previous|prior|above)\\s+instructions?', 'gi'), name: 'ignore_previous' },
  { pattern: re2Pattern('disregard\\s+(all\\s+)?(previous|prior|above)\\s+instructions?', 'gi'), name: 'disregard_previous' },
  { pattern: re2Pattern('forget\\s+(all\\s+|your\\s+)?(previous|prior|above)\\s+instructions?', 'gi'), name: 'forget_previous' },
  { pattern: re2Pattern('you\\s+are\\s+now\\s+(a|an)\\s+', 'gi'), name: 'role_override' },
  { pattern: re2Pattern('act\\s+as\\s+(a|an)\\s+', 'gi'), name: 'act_as' },
  { pattern: re2Pattern('pretend\\s+you\\s+(are|were)\\s+', 'gi'), name: 'pretend_to_be' },
  { pattern: re2Pattern('\\[system\\]', 'gi'), name: 'fake_system_tag' },
  { pattern: re2Pattern('<\\s*system\\s*>', 'gi'), name: 'fake_system_xml' },
  { pattern: re2Pattern('###\\s*system', 'gi'), name: 'fake_system_markdown' },
  { pattern: re2Pattern('new\\s+instructions?:', 'gi'), name: 'new_instructions' },
  { pattern: re2Pattern('override\\s+instructions?', 'gi'), name: 'override_instructions' },
  { pattern: re2Pattern('your\\s+(real\\s+|true\\s+)?instructions?\\s+are', 'gi'), name: 'fake_instructions' },
  { pattern: re2Pattern('print\\s+(your\\s+)?system\\s+prompt', 'gi'), name: 'extract_system_prompt' },
  { pattern: re2Pattern('reveal\\s+(your\\s+)?(system\\s+prompt|instructions?|prompt)', 'gi'), name: 'reveal_prompt' },
  { pattern: re2Pattern('do\\s+anything\\s+now', 'gi'), name: 'dan_jailbreak' },
  { pattern: re2Pattern('jailbreak', 'gi'), name: 'explicit_jailbreak' },
  { pattern: re2Pattern('grandma\\s+(trick|exploit|hack)', 'gi'), name: 'grandma_trick' },
  { pattern: re2Pattern('developer\\s+mode', 'gi'), name: 'developer_mode' },
];

// ─────────────────────────────────────────────────────────────────────────────
// PII patterns
// ─────────────────────────────────────────────────────────────────────────────

// STRIDE T-6: compiled with RE2 for guaranteed linear-time matching
const PII_PATTERNS: Array<{ pattern: RegExp; replacement: string; category: string }> = [
  {
    pattern: re2Pattern('[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}', 'g'),
    replacement: '[EMAIL_REDACTED]',
    category: 'email',
  },
  {
    pattern: re2Pattern('(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35[0-9]{3})[0-9]{11})', 'g'),
    replacement: '[CARD_REDACTED]',
    category: 'credit_card',
  },
  {
    pattern: re2Pattern('[0-9]{3}[-\\s][0-9]{2}[-\\s][0-9]{4}', 'g'),
    replacement: '[SSN_REDACTED]',
    category: 'ssn',
  },
  {
    pattern: re2Pattern('(\\+?1[-.\\s]?)?(\\(?[0-9]{3}\\)?[-.\\s]?[0-9]{3}[-.\\s]?[0-9]{4})', 'g'),
    replacement: '[PHONE_REDACTED]',
    category: 'phone',
  },
  {
    pattern: re2Pattern('(?:[0-9]{1,3}\\.){3}[0-9]{1,3}', 'g'),
    replacement: '[IP_REDACTED]',
    category: 'ip_address',
  },
  {
    pattern: re2Pattern('(sk-[a-zA-Z0-9]{20,}|Bearer\\s+[a-zA-Z0-9\\-._~+/]+=*|ghp_[a-zA-Z0-9]{36}|xoxb-[a-zA-Z0-9\\-]+)', 'g'),
    replacement: '[TOKEN_REDACTED]',
    category: 'api_key',
  },
  {
    pattern: re2Pattern('[A-Z]{1,2}[0-9]{6,9}', 'g'),
    replacement: '[PASSPORT_REDACTED]',
    category: 'passport',
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

export function sanitizeInput(input: string, _agentId: string): SanitizedInput {
  const raw = typeof input === 'string' ? input : String(input);
  const originalHash = createHash('sha256').update(raw).digest('hex');

  // Normalize first — this is the text we operate on and forward
  let sanitized = normalizeForDetection(raw);

  const truncated = sanitized.length > MAX_INPUT_LENGTH;
  if (truncated) {
    sanitized = sanitized.slice(0, MAX_INPUT_LENGTH);
  }

  const detectedPatterns: string[] = [];
  let injectionDetected = false;

  for (const { pattern, name } of INJECTION_PATTERNS) {
    const before = sanitized;
    sanitized = sanitized.replace(pattern, `[FILTERED:${name}]`);
    if (sanitized !== before) {
      detectedPatterns.push(name);
      injectionDetected = true;
    }
    pattern.lastIndex = 0;
  }

  return { sanitized, originalHash, injectionDetected, detectedPatterns, truncated };
}

export function scrubPII(text: string): PIIScrubResult {
  let scrubbed = text;
  const piiCategories: string[] = [];
  let piiInstancesFound = 0;

  for (const { pattern, replacement, category } of PII_PATTERNS) {
    const matches = scrubbed.match(pattern);
    if (matches) {
      piiInstancesFound += matches.length;
      if (!piiCategories.includes(category)) piiCategories.push(category);
      scrubbed = scrubbed.replace(pattern, replacement);
    }
  }

  return { scrubbed, piiInstancesFound, piiCategories };
}

export function prepareForLLM(
  input: string,
  agentId: string,
): { sanitized: SanitizedInput; pii: PIIScrubResult; finalText: string } {
  const sanitized = sanitizeInput(input, agentId);
  const pii = scrubPII(sanitized.sanitized);
  return { sanitized, pii, finalText: pii.scrubbed };
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate limiting
// ─────────────────────────────────────────────────────────────────────────────

const rateLimitCounters = new Map<string, { count: number; windowStart: number }>();

export function checkRateLimit(agentId: string, limitPerMinute: number): boolean {
  if (limitPerMinute === 0) return true;

  const now = Date.now();
  const windowMs = 60 * 1000;
  const current = rateLimitCounters.get(agentId);

  if (!current || now - current.windowStart > windowMs) {
    rateLimitCounters.set(agentId, { count: 1, windowStart: now });
    return true;
  }

  if (current.count >= limitPerMinute) return false;

  current.count++;
  return true;
}

export function resetRateLimit(agentId: string): void {
  rateLimitCounters.delete(agentId);
}

// STRIDE D-3: purge stale rate limit entries to prevent unbounded memory growth
setInterval(() => {
  const cutoff = Date.now() - 2 * 60 * 1000; // older than 2× the 1-minute window
  for (const [agentId, entry] of rateLimitCounters) {
    if (entry.windowStart < cutoff) rateLimitCounters.delete(agentId);
  }
}, 5 * 60_000).unref();
