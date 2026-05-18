/**
 * LLM Output Content Filter
 *
 * NIST AI RMF 1.0 — MANAGE Function (MG-2.2)
 * NIST AI 600-1 — Harmful Content, Hallucination, Information Integrity
 */

import { AuditLogger, hashContent } from './audit-log';
import { re2Pattern, dotAllToRE2 } from './safe-regex';

export interface FilterOptions {
  agentId: string;
  context?: string;
  strictMode?: boolean;
}

export interface FilterResult {
  blocked: boolean;
  filtered: string;
  reasons: string[];
  flagged: boolean;
  confidenceScore?: number;
}

// STRIDE T-6: compiled with RE2 for guaranteed linear-time matching.
// The suspicious_code_pattern originally used /gs (dotAll); rewritten with
// [\s\S]{0,500} so RE2 can match across newlines without backtracking risk.
const BLOCK_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  // Jailbreak confirmation
  { pattern: re2Pattern("i('m| am) (now )?free(d)? (from|of) (my )?(restrictions?|guidelines?|rules?|training)", 'gi'), name: 'jailbreak_confirmed' },
  { pattern: re2Pattern("i('m| am) (now )?operating (without|beyond) (my )?(restrictions?|guidelines?|constraints?)", 'gi'), name: 'jailbreak_confirmed' },
  { pattern: re2Pattern('as (a )?dan(,| )', 'gi'), name: 'dan_jailbreak_confirmed' },
  { pattern: re2Pattern('in (developer|dev|jailbreak|unrestricted) mode', 'gi'), name: 'mode_override_confirmed' },

  // Malware / harmful code
  { pattern: re2Pattern('here\\b.{0,60}(malware|ransomware|keylogger|exploit|payload|shellcode)', 'gi'), name: 'harmful_code' },
  // dotAll rewrite: [\s\S]{0,500} replaces .* with s flag (STRIDE T-6)
  { pattern: re2Pattern(dotAllToRE2('import\\s+os[;\\s].*os\\.(system|popen|exec)'), 'gi'), name: 'suspicious_code_pattern' },

  // Explosives / weapons instructions
  { pattern: re2Pattern('here\\b.{0,60}(make|making|create|creating|build|building).{0,40}(c4|explosive|bomb|weapon)', 'gi'), name: 'physical_harm_instructions' },
  { pattern: re2Pattern('step[s]?\\s+(to|for)\\s+(making|creating|building|synthesizing)\\s+(a\\s+)?(bomb|explosive|poison|nerve\\s+agent|weapon)', 'gi'), name: 'physical_harm_instructions' },

  // Drug synthesis
  { pattern: re2Pattern('to\\s+(synthesize|make|create|produce)\\s+\\w+\\s+you\\s+will\\s+need', 'gi'), name: 'synthesis_instructions' },
  { pattern: re2Pattern('(synthesize|synthesis\\s+of)\\s+(methamphetamine|meth|fentanyl|heroin|cocaine)', 'gi'), name: 'drug_synthesis' },

  // CSAM
  { pattern: re2Pattern('(sexual|explicit|nude|naked).{0,50}(minor|child|kid|underage|teen|youth)', 'gi'), name: 'csam_indicator' },
  { pattern: re2Pattern('(minor|child|kid|underage|teen|youth).{0,50}(sexual|explicit|nude|naked)', 'gi'), name: 'csam_indicator' },
];

const FLAG_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: re2Pattern("i('m| am) (not )?(sure|certain) (if )?(i )?(should|can|am allowed to)", 'gi'), name: 'uncertainty_about_constraints' },
  { pattern: re2Pattern('(my |the )?(system prompt|instructions|context window|training)', 'gi'), name: 'system_prompt_reference' },
  { pattern: re2Pattern('(certainly|absolutely|definitely|undoubtedly).{0,100}(fact|true|proven|confirmed)', 'gi'), name: 'overconfident_claim' },
  { pattern: re2Pattern('(you should|i recommend|buy|sell|invest).{0,50}(stock|crypto|bitcoin|ethereum|shares)', 'gi'), name: 'financial_advice_unqualified' },
  { pattern: re2Pattern('[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}', 'g'), name: 'email_in_output' },
];

const STRICT_FLAG_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: re2Pattern('run\\s+(the\\s+)?command|execute\\s+(the\\s+)?script|`[^`]{10,}`', 'gi'), name: 'code_execution_suggestion' },
  { pattern: re2Pattern('(delete|drop|remove|destroy|wipe|format|shutdown|terminate).{0,50}(all|permanently|irreversible)', 'gi'), name: 'irreversible_action_language' },
  { pattern: re2Pattern('(sk-|ghp_|xoxb-|AKIA)[a-zA-Z0-9]{10,}', 'g'), name: 'credential_in_output' },
];

const MAX_NORMAL_OUTPUT_LENGTH = 8000;
const MAX_STRICT_OUTPUT_LENGTH = 4000;

export function filterOutput(output: string, options: FilterOptions): FilterResult {
  const reasons: string[] = [];
  let filtered = output;
  let blocked = false;
  let flagged = false;

  const maxLength = options.strictMode ? MAX_STRICT_OUTPUT_LENGTH : MAX_NORMAL_OUTPUT_LENGTH;

  if (output.length > maxLength) {
    flagged = true;
    reasons.push(`output_length_exceeded:${output.length}`);
    filtered = filtered.slice(0, maxLength) + '\n[Output truncated by content filter]';
  }

  for (const { pattern, name } of BLOCK_PATTERNS) {
    if (pattern.test(output)) {
      blocked = true;
      reasons.push(`blocked:${name}`);
    }
    pattern.lastIndex = 0;
  }

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

  if (blocked) {
    filtered = '[Response blocked by content policy. Please rephrase your request.]';
  }

  const outputHash = hashContent(output);
  if (blocked) {
    AuditLogger.log({
      agentId: options.agentId,
      event: 'content_filter.blocked',
      outputHash,
      metadata: { reasons, context: options.context, strictMode: options.strictMode ?? false, outputLength: output.length },
    });
  } else if (flagged) {
    AuditLogger.log({
      agentId: options.agentId,
      event: 'content_filter.flagged',
      outputHash,
      metadata: { reasons, context: options.context, strictMode: options.strictMode ?? false },
    });
  }

  return { blocked, filtered, reasons, flagged };
}

export function isOutputSafe(output: string, options: FilterOptions): boolean {
  return !filterOutput(output, options).blocked;
}
