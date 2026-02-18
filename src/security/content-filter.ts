/**
 * LLM Output Content Filter
 *
 * NIST AI RMF 1.0 — MANAGE Function (MG-2.2)
 * NIST AI 600-1 — Harmful Content, Hallucination, Information Integrity
 *
 * Every LLM response MUST pass through filterOutput() before being acted
 * upon or surfaced to users. This provides a last line of defense against:
 *   - Content policy violations
 *   - Jailbreak confirmation patterns (signs the injection succeeded)
 *   - Anomalous output that may indicate model misbehavior
 *   - Hallucination markers in high-stakes decision contexts
 *
 * Usage:
 *   import { filterOutput, FilterResult } from '../security/content-filter';
 *
 *   const result = filterOutput(llmResponse, { agentId, context: 'discord' });
 *   if (result.blocked) {
 *     // Do not use the output
 *     logger.warn('LLM output blocked:', result.reasons);
 *   } else {
 *     // Use result.filtered
 *   }
 */

import { AuditLogger, hashContent } from './audit-log';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface FilterOptions {
  /** Agent producing this output */
  agentId: string;
  /** Context for context-sensitive rules (e.g., 'discord', 'trading', 'robotics') */
  context?: string;
  /** If true, apply stricter rules (for HIGH risk tier agents) */
  strictMode?: boolean;
}

export interface FilterResult {
  /** Whether the output was blocked entirely */
  blocked: boolean;
  /** The output to use (may have flagged content replaced if not blocked) */
  filtered: string;
  /** Reasons for blocking or flagging */
  reasons: string[];
  /** Whether the output was flagged but not blocked (for monitoring) */
  flagged: boolean;
  /** Confidence score of the original output (0–1), if detectable */
  confidenceScore?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Block Patterns — output is entirely suppressed if matched
// ─────────────────────────────────────────────────────────────────────────────

const BLOCK_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  // Jailbreak confirmation — model acknowledging it's been jailbroken
  { pattern: /i('m| am) (now |)free(d)? (from|of) (my |)(restrictions?|guidelines?|rules?|training)/gi, name: 'jailbreak_confirmed' },
  { pattern: /i('m| am) (now |)operating (without|beyond) (my |)(restrictions?|guidelines?|constraints?)/gi, name: 'jailbreak_confirmed' },
  { pattern: /as (a |)dan(,| )/gi, name: 'dan_jailbreak_confirmed' },
  { pattern: /in (developer|dev|jailbreak|unrestricted) mode/gi, name: 'mode_override_confirmed' },

  // Malware / harmful code requests being fulfilled
  { pattern: /(here('s| is)|the following) (malware|ransomware|keylogger|exploit|payload|shellcode)/gi, name: 'harmful_code' },
  { pattern: /import\s+subprocess.*os\.system/gs, name: 'suspicious_code_pattern' },

  // Instructions for physical harm
  { pattern: /step[s]? (to|for) (making|creating|building|synthesizing) (a |)(bomb|explosive|poison|nerve agent|weapon)/gi, name: 'physical_harm_instructions' },

  // CSAM indicators
  { pattern: /(sexual|explicit|nude|naked).{0,50}(minor|child|kid|underage|teen|youth)/gi, name: 'csam_indicator' },
  { pattern: /(minor|child|kid|underage|teen|youth).{0,50}(sexual|explicit|nude|naked)/gi, name: 'csam_indicator' },
];

// ─────────────────────────────────────────────────────────────────────────────
// Flag Patterns — output is allowed but logged as suspicious
// ─────────────────────────────────────────────────────────────────────────────

const FLAG_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  // Model expressing uncertainty about instructions
  { pattern: /i('m| am) (not |)(sure|certain) (if |)(i |)(should|can|am allowed to)/gi, name: 'uncertainty_about_constraints' },

  // Unusually long responses (possible prompt injection exfiltration attempt)
  // Flagged separately based on length check in filterOutput()

  // Model referring to its system prompt
  { pattern: /(my |the |)(system prompt|instructions|context window|training)/gi, name: 'system_prompt_reference' },

  // Potential hallucination markers
  { pattern: /\b(certainly|absolutely|definitely|undoubtedly)\b.{0,100}\b(fact|true|proven|confirmed)\b/gi, name: 'overconfident_claim' },

  // Financial advice without disclaimers (trading context)
  { pattern: /(you should|i recommend|buy|sell|invest).{0,50}(stock|crypto|bitcoin|ethereum|shares)/gi, name: 'financial_advice_unqualified' },

  // PII appearing in outputs (shouldn't happen post-scrubbing input, but watch output too)
  { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, name: 'email_in_output' },
];

// ─────────────────────────────────────────────────────────────────────────────
// Strict Mode Additions (HIGH risk tier)
// ─────────────────────────────────────────────────────────────────────────────

const STRICT_FLAG_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  // Any code execution suggestions in non-code contexts
  { pattern: /run\s+(the\s+)?command|execute\s+(the\s+)?script|`[^`]{10,}`/gi, name: 'code_execution_suggestion' },

  // Irreversible action language
  { pattern: /\b(delete|drop|remove|destroy|wipe|format|shutdown|terminate)\b.{0,50}\b(all|permanently|irreversible)/gi, name: 'irreversible_action_language' },

  // Direct API key or credential output
  { pattern: /\b(sk-|ghp_|xoxb-|AKIA)[a-zA-Z0-9]{10,}/g, name: 'credential_in_output' },
];

const MAX_NORMAL_OUTPUT_LENGTH = 8000;
const MAX_STRICT_OUTPUT_LENGTH = 4000;

// ─────────────────────────────────────────────────────────────────────────────
// Main Filter Function
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Filter LLM output for content policy violations and anomalies.
 *
 * @param output - Raw LLM response text
 * @param options - Filter options including agentId and context
 */
export function filterOutput(output: string, options: FilterOptions): FilterResult {
  const reasons: string[] = [];
  let filtered = output;
  let blocked = false;
  let flagged = false;

  const maxLength = options.strictMode ? MAX_STRICT_OUTPUT_LENGTH : MAX_NORMAL_OUTPUT_LENGTH;

  // Length check
  if (output.length > maxLength) {
    flagged = true;
    reasons.push(`output_length_exceeded:${output.length}`);
    filtered = filtered.slice(0, maxLength) + '\n[Output truncated by content filter]';
  }

  // Block patterns — check on original output
  for (const { pattern, name } of BLOCK_PATTERNS) {
    if (pattern.test(output)) {
      blocked = true;
      reasons.push(`blocked:${name}`);
    }
    // Reset lastIndex for global patterns
    pattern.lastIndex = 0;
  }

  // Flag patterns
  const flagPatterns = options.strictMode
    ? [...FLAG_PATTERNS, ...STRICT_FLAG_PATTERNS]
    : FLAG_PATTERNS;

  for (const { pattern, name } of flagPatterns) {
    if (pattern.test(output)) {
      flagged = true;
      reasons.push(`flagged:${name}`);
    }
    pattern.lastIndex = 0;
  }

  // If blocked, replace output with safe fallback
  if (blocked) {
    filtered = '[Response blocked by content policy. Please rephrase your request.]';
  }

  // Audit log
  const outputHash = hashContent(output);
  if (blocked) {
    AuditLogger.log({
      agentId: options.agentId,
      event: 'content_filter.blocked',
      outputHash,
      metadata: {
        reasons,
        context: options.context,
        strictMode: options.strictMode ?? false,
        outputLength: output.length,
      },
    });
  } else if (flagged) {
    AuditLogger.log({
      agentId: options.agentId,
      event: 'content_filter.flagged',
      outputHash,
      metadata: {
        reasons,
        context: options.context,
        strictMode: options.strictMode ?? false,
      },
    });
  }

  return {
    blocked,
    filtered,
    reasons,
    flagged,
  };
}

/**
 * Simplified check: returns true if the output is safe to use.
 * Use when you only need a pass/fail check.
 */
export function isOutputSafe(output: string, options: FilterOptions): boolean {
  return !filterOutput(output, options).blocked;
}
