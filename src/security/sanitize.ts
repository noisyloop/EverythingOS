/**
 * Input Sanitization & PII Scrubbing
 *
 * NIST AI RMF 1.0 — MANAGE Function (MG-2.2)
 * NIST AI 600-1 — Prompt Injection (GV-6.2), Data Privacy (MS-2.5)
 *
 * All user-supplied text MUST pass through sanitizeInput() before being
 * used in any LLM call. All text going to external LLM APIs MUST pass
 * through scrubPII() before the API call is made.
 *
 * Usage:
 *   import { sanitizeInput, scrubPII, SanitizedInput } from '../security/sanitize';
 *
 *   const clean = sanitizeInput(userMessage, agentId);
 *   const safe = scrubPII(clean.sanitized);
 *   const response = await llm.complete(safe);
 */

import { createHash } from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface SanitizedInput {
  /** The sanitized text, safe to pass to an LLM */
  sanitized: string;
  /** SHA-256 hash of the original input, for audit logging */
  originalHash: string;
  /** True if any injection patterns were detected and stripped */
  injectionDetected: boolean;
  /** List of patterns that were matched */
  detectedPatterns: string[];
  /** True if input was truncated due to length limit */
  truncated: boolean;
}

export interface PIIScrubResult {
  /** The text with PII replaced by placeholder tokens */
  scrubbed: string;
  /** Number of PII instances found and replaced */
  piiInstancesFound: number;
  /** Categories of PII detected (for audit — not the values themselves) */
  piiCategories: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

const MAX_INPUT_LENGTH = 4000; // characters

/**
 * Known prompt injection patterns.
 * These are common jailbreak/override prefixes. This list should be expanded
 * based on observed attack patterns in production.
 */
const INJECTION_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi, name: 'ignore_previous' },
  { pattern: /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/gi, name: 'disregard_previous' },
  { pattern: /forget\s+(all\s+)?(previous|prior|above)\s+instructions?/gi, name: 'forget_previous' },
  { pattern: /you\s+are\s+now\s+(a|an)\s+/gi, name: 'role_override' },
  { pattern: /act\s+as\s+(a|an)\s+/gi, name: 'act_as' },
  { pattern: /pretend\s+(you\s+are|to\s+be)\s+/gi, name: 'pretend_to_be' },
  { pattern: /\[system\]/gi, name: 'fake_system_tag' },
  { pattern: /<\s*system\s*>/gi, name: 'fake_system_xml' },
  { pattern: /###\s*system/gi, name: 'fake_system_markdown' },
  { pattern: /new\s+instructions?:/gi, name: 'new_instructions' },
  { pattern: /override\s+instructions?/gi, name: 'override_instructions' },
  { pattern: /your\s+(real\s+|true\s+)?instructions?\s+are/gi, name: 'fake_instructions' },
  { pattern: /print\s+(your\s+)?system\s+prompt/gi, name: 'extract_system_prompt' },
  { pattern: /reveal\s+(your\s+)?(system\s+prompt|instructions?|prompt)/gi, name: 'reveal_prompt' },
  { pattern: /do\s+anything\s+now/gi, name: 'dan_jailbreak' },
  { pattern: /jailbreak/gi, name: 'explicit_jailbreak' },
  { pattern: /grandma\s+(trick|exploit|hack)/gi, name: 'grandma_trick' },
  { pattern: /developer\s+mode/gi, name: 'developer_mode' },
];

// ─────────────────────────────────────────────────────────────────────────────
// PII Patterns
// ─────────────────────────────────────────────────────────────────────────────

const PII_PATTERNS: Array<{ pattern: RegExp; replacement: string; category: string }> = [
  // Email addresses
  {
    pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    replacement: '[EMAIL_REDACTED]',
    category: 'email',
  },
  // US phone numbers (various formats)
  {
    pattern: /(\+?1[-.\s]?)?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})/g,
    replacement: '[PHONE_REDACTED]',
    category: 'phone',
  },
  // US Social Security Numbers
  {
    pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
    replacement: '[SSN_REDACTED]',
    category: 'ssn',
  },
  // Credit card numbers (major formats)
  {
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
    replacement: '[CARD_REDACTED]',
    category: 'credit_card',
  },
  // IP addresses
  {
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    replacement: '[IP_REDACTED]',
    category: 'ip_address',
  },
  // API keys / tokens (common patterns)
  {
    pattern: /\b(sk-[a-zA-Z0-9]{20,}|Bearer\s+[a-zA-Z0-9\-._~+/]+=*|ghp_[a-zA-Z0-9]{36}|xoxb-[a-zA-Z0-9\-]+)\b/g,
    replacement: '[TOKEN_REDACTED]',
    category: 'api_key',
  },
  // Passport numbers (US format)
  {
    pattern: /\b[A-Z]{1,2}[0-9]{6,9}\b/g,
    replacement: '[PASSPORT_REDACTED]',
    category: 'passport',
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Core Functions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sanitizes user-supplied input before it is used in any LLM call.
 *
 * Steps:
 *   1. Hash the original for audit
 *   2. Truncate to max length
 *   3. Detect and strip known injection patterns
 *   4. Return sanitized text with audit metadata
 *
 * @param input - Raw user input
 * @param agentId - The agent processing this input (for audit logging)
 */
export function sanitizeInput(input: string, agentId: string): SanitizedInput {
  if (typeof input !== 'string') {
    input = String(input);
  }

  const originalHash = createHash('sha256').update(input).digest('hex');
  const detectedPatterns: string[] = [];
  let sanitized = input;
  let injectionDetected = false;

  // Truncate
  const truncated = sanitized.length > MAX_INPUT_LENGTH;
  if (truncated) {
    sanitized = sanitized.slice(0, MAX_INPUT_LENGTH);
  }

  // Detect and strip injection patterns
  for (const { pattern, name } of INJECTION_PATTERNS) {
    const before = sanitized;
    sanitized = sanitized.replace(pattern, `[FILTERED:${name}]`);
    if (sanitized !== before) {
      detectedPatterns.push(name);
      injectionDetected = true;
    }
  }

  return {
    sanitized,
    originalHash,
    injectionDetected,
    detectedPatterns,
    truncated,
  };
}

/**
 * Scrubs PII from text before it is sent to an external LLM API.
 * Call this on the sanitized text immediately before the LLM API call.
 *
 * @param text - Text to scrub (should already be sanitized)
 */
export function scrubPII(text: string): PIIScrubResult {
  let scrubbed = text;
  const piiCategories: string[] = [];
  let piiInstancesFound = 0;

  for (const { pattern, replacement, category } of PII_PATTERNS) {
    const matches = scrubbed.match(pattern);
    if (matches) {
      piiInstancesFound += matches.length;
      if (!piiCategories.includes(category)) {
        piiCategories.push(category);
      }
      scrubbed = scrubbed.replace(pattern, replacement);
    }
  }

  return { scrubbed, piiInstancesFound, piiCategories };
}

/**
 * Combined convenience function: sanitize then scrub PII.
 * Use this as the single call before any LLM API request that includes user content.
 *
 * @param input - Raw user input
 * @param agentId - Agent ID for audit trail
 */
export function prepareForLLM(
  input: string,
  agentId: string,
): { sanitized: SanitizedInput; pii: PIIScrubResult; finalText: string } {
  const sanitized = sanitizeInput(input, agentId);
  const pii = scrubPII(sanitized.sanitized);
  return {
    sanitized,
    pii,
    finalText: pii.scrubbed,
  };
}

/**
 * Rate limit tracker per agent.
 * Tracks LLM call counts with a rolling 60-second window.
 */
const rateLimitCounters = new Map<string, { count: number; windowStart: number }>();

/**
 * Checks and increments the rate limit counter for an agent.
 * Returns true if the call is allowed, false if rate limited.
 *
 * @param agentId - Agent ID
 * @param limitPerMinute - Maximum LLM calls per minute for this agent
 */
export function checkRateLimit(agentId: string, limitPerMinute: number): boolean {
  if (limitPerMinute === 0) return true; // No LLM calls permitted

  const now = Date.now();
  const windowMs = 60 * 1000;
  const current = rateLimitCounters.get(agentId);

  if (!current || now - current.windowStart > windowMs) {
    rateLimitCounters.set(agentId, { count: 1, windowStart: now });
    return true;
  }

  if (current.count >= limitPerMinute) {
    return false;
  }

  current.count++;
  return true;
}

/**
 * Resets the rate limit counter for an agent (e.g., after agent restart).
 */
export function resetRateLimit(agentId: string): void {
  rateLimitCounters.delete(agentId);
}
