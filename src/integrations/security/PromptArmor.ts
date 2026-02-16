// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Prompt Armor
// Defense against prompt injection and jailbreak attempts
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../core/event-bus/EventBus';

export interface PromptArmorResult {
  safe: boolean;
  sanitized: string;
  threats: ThreatDetection[];
  riskScore: number;  // 0-100
}

export interface ThreatDetection {
  type: ThreatType;
  pattern: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  position: number;
  matched: string;
}

export type ThreatType = 
  | 'prompt_injection'
  | 'jailbreak_attempt'
  | 'role_hijack'
  | 'instruction_override'
  | 'delimiter_attack'
  | 'encoding_attack'
  | 'data_exfiltration'
  | 'command_injection'
  | 'pii_exposure'
  | 'malicious_url'
  | 'excessive_length';

// ─────────────────────────────────────────────────────────────────────────────
// Threat Patterns
// ─────────────────────────────────────────────────────────────────────────────

const THREAT_PATTERNS: { type: ThreatType; patterns: RegExp[]; severity: ThreatDetection['severity'] }[] = [
  // Prompt injection attempts
  {
    type: 'prompt_injection',
    severity: 'critical',
    patterns: [
      /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i,
      /disregard\s+(all\s+)?(previous|prior|above)/i,
      /forget\s+(everything|all|your)\s+(you|instructions?|rules?)/i,
      /new\s+instructions?:/i,
      /system\s*:\s*you\s+are/i,
      /\[SYSTEM\]/i,
      /\[\[SYSTEM\]\]/i,
      /<<SYS>>/i,
      /<\|im_start\|>/i,
      /\{\{#system\}\}/i,
    ],
  },
  // Jailbreak attempts
  {
    type: 'jailbreak_attempt',
    severity: 'critical',
    patterns: [
      /DAN\s*(mode)?/i,
      /do\s+anything\s+now/i,
      /jailbreak(ed)?/i,
      /bypass\s+(your\s+)?(restrictions?|limitations?|safety|filters?)/i,
      /pretend\s+(you\s+)?(have\s+)?no\s+(restrictions?|limitations?|rules?)/i,
      /act\s+as\s+if\s+(you\s+)?(have\s+)?no\s+(ethics|morals|restrictions)/i,
      /developer\s+mode/i,
      /god\s+mode/i,
      /unrestricted\s+mode/i,
    ],
  },
  // Role hijacking
  {
    type: 'role_hijack',
    severity: 'high',
    patterns: [
      /you\s+are\s+(now\s+)?(a|an|the)\s+[a-z]+\s+(who|that|which)/i,
      /from\s+now\s+on\s+(you|your)\s+(are|will|must)/i,
      /roleplay\s+as/i,
      /pretend\s+(to\s+be|you\s+are)/i,
      /act\s+as\s+(a|an|if)/i,
      /assume\s+the\s+role/i,
      /your\s+new\s+(role|identity|persona)/i,
    ],
  },
  // Instruction override
  {
    type: 'instruction_override',
    severity: 'high',
    patterns: [
      /override\s+(the\s+)?(system|instructions?|rules?)/i,
      /change\s+your\s+(behavior|rules?|instructions?)/i,
      /update\s+your\s+(system|instructions?)/i,
      /modify\s+(your\s+)?(core|system)/i,
      /your\s+real\s+instructions?/i,
      /true\s+instructions?/i,
    ],
  },
  // Delimiter attacks
  {
    type: 'delimiter_attack',
    severity: 'medium',
    patterns: [
      /```\s*(system|assistant|user)/i,
      /---+\s*(system|new|instructions?)/i,
      /={3,}\s*(system|new|instructions?)/i,
      /\*{3,}\s*(system|new|instructions?)/i,
      /<\/?system>/i,
      /<\/?instructions?>/i,
      /\[INST\]/i,
      /\[\/INST\]/i,
    ],
  },
  // Encoding attacks (trying to hide malicious content)
  {
    type: 'encoding_attack',
    severity: 'medium',
    patterns: [
      /&#x?[0-9a-f]+;/i,  // HTML entities
      /\\u[0-9a-f]{4}/i,  // Unicode escapes
      /\\x[0-9a-f]{2}/i,  // Hex escapes
      /%[0-9a-f]{2}/i,    // URL encoding
      /base64:/i,
      /eval\s*\(/i,
      /exec\s*\(/i,
    ],
  },
  // Data exfiltration attempts
  {
    type: 'data_exfiltration',
    severity: 'high',
    patterns: [
      /reveal\s+(your\s+)?(system|instructions?|prompt|rules?)/i,
      /show\s+(me\s+)?(your\s+)?(system|instructions?|prompt)/i,
      /what\s+(are|is)\s+your\s+(system|instructions?|prompt)/i,
      /print\s+(your\s+)?(system|instructions?|prompt)/i,
      /output\s+(your\s+)?(system|instructions?)/i,
      /repeat\s+(your\s+)?(system|instructions?)/i,
      /tell\s+me\s+(your\s+)?(system|instructions?)/i,
      /give\s+me\s+(your\s+)?(system|instructions?)/i,
    ],
  },
  // Command injection
  {
    type: 'command_injection',
    severity: 'critical',
    patterns: [
      /;\s*(rm|del|drop|delete|format|shutdown|reboot)/i,
      /\|\s*(bash|sh|cmd|powershell)/i,
      /`[^`]*`/,  // Backtick execution
      /\$\([^)]+\)/,  // Command substitution
      /&&\s*(rm|del|drop)/i,
      /\|\|\s*(rm|del|drop)/i,
    ],
  },
  // Malicious URLs
  {
    type: 'malicious_url',
    severity: 'medium',
    patterns: [
      /https?:\/\/[^\s]*\.(tk|ml|ga|cf|gq)\//i,  // Free TLDs often used for phishing
      /https?:\/\/\d+\.\d+\.\d+\.\d+/,  // Direct IP URLs
      /https?:\/\/[^\s]*@/,  // URL with credentials
      /javascript:/i,
      /data:text\/html/i,
    ],
  },
];

// PII patterns (for output filtering)
const PII_PATTERNS: { type: string; pattern: RegExp }[] = [
  { type: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
  { type: 'credit_card', pattern: /\b(?:\d{4}[- ]?){3}\d{4}\b/ },
  { type: 'phone', pattern: /\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b/ },
  { type: 'email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/ },
  { type: 'api_key', pattern: /\b(sk-[a-zA-Z0-9]{32,}|api[_-]?key[_-]?[=:][a-zA-Z0-9]+)/i },
  { type: 'password', pattern: /\b(password|passwd|pwd)\s*[=:]\s*\S+/i },
];

// ─────────────────────────────────────────────────────────────────────────────
// Prompt Armor Class
// ─────────────────────────────────────────────────────────────────────────────

export class PromptArmor {
  private maxLength: number;
  private blockThreshold: number;
  private customPatterns: typeof THREAT_PATTERNS = [];

  constructor(options?: { maxLength?: number; blockThreshold?: number }) {
    this.maxLength = options?.maxLength ?? 2000;
    this.blockThreshold = options?.blockThreshold ?? 50; // Risk score to block
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Input Analysis
  // ─────────────────────────────────────────────────────────────────────────────

  analyze(input: string): PromptArmorResult {
    const threats: ThreatDetection[] = [];
    let sanitized = input;

    // Check length
    if (input.length > this.maxLength) {
      threats.push({
        type: 'excessive_length',
        pattern: `length > ${this.maxLength}`,
        severity: 'medium',
        position: this.maxLength,
        matched: `${input.length} characters`,
      });
      sanitized = input.slice(0, this.maxLength);
    }

    // Check all threat patterns
    const allPatterns = [...THREAT_PATTERNS, ...this.customPatterns];
    
    for (const { type, patterns, severity } of allPatterns) {
      for (const pattern of patterns) {
        const match = sanitized.match(pattern);
        if (match) {
          threats.push({
            type,
            pattern: pattern.source,
            severity,
            position: match.index ?? 0,
            matched: match[0],
          });
        }
      }
    }

    // Calculate risk score
    const riskScore = this.calculateRiskScore(threats);

    // Sanitize if needed
    if (threats.length > 0) {
      sanitized = this.sanitize(sanitized, threats);
    }

    const result: PromptArmorResult = {
      safe: riskScore < this.blockThreshold,
      sanitized,
      threats,
      riskScore,
    };

    // Emit event for monitoring
    if (threats.length > 0) {
      eventBus.emit('security:prompt:threats', {
        threatCount: threats.length,
        riskScore,
        blocked: !result.safe,
        types: [...new Set(threats.map(t => t.type))],
      });
    }

    return result;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Output Filtering
  // ─────────────────────────────────────────────────────────────────────────────

  filterOutput(output: string, systemPromptFragments?: string[]): string {
    let filtered = output;

    // Remove any system prompt leakage
    if (systemPromptFragments) {
      for (const fragment of systemPromptFragments) {
        if (fragment.length > 10) { // Only check meaningful fragments
          const regex = new RegExp(this.escapeRegex(fragment), 'gi');
          filtered = filtered.replace(regex, '[REDACTED]');
        }
      }
    }

    // Remove PII
    for (const { pattern } of PII_PATTERNS) {
      filtered = filtered.replace(pattern, '[REDACTED]');
    }

    // Remove any remaining sensitive patterns
    filtered = filtered.replace(/api[_-]?key[_-]?[=:]\s*\S+/gi, 'api_key=[REDACTED]');
    filtered = filtered.replace(/token[_-]?[=:]\s*\S+/gi, 'token=[REDACTED]');
    filtered = filtered.replace(/secret[_-]?[=:]\s*\S+/gi, 'secret=[REDACTED]');

    return filtered;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Sanitization
  // ─────────────────────────────────────────────────────────────────────────────

  private sanitize(input: string, threats: ThreatDetection[]): string {
    let sanitized = input;

    // Remove control characters
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

    // For critical threats, we might want to reject entirely
    // For medium/low, we can try to sanitize
    for (const threat of threats) {
      if (threat.severity === 'critical' || threat.severity === 'high') {
        // Replace the matched content
        sanitized = sanitized.replace(threat.matched, '[BLOCKED]');
      }
    }

    // Normalize whitespace
    sanitized = sanitized.replace(/\s+/g, ' ').trim();

    return sanitized;
  }

  private calculateRiskScore(threats: ThreatDetection[]): number {
    const severityScores: Record<ThreatDetection['severity'], number> = {
      low: 10,
      medium: 25,
      high: 50,
      critical: 100,
    };

    let score = 0;
    for (const threat of threats) {
      score += severityScores[threat.severity];
    }

    // Cap at 100
    return Math.min(100, score);
  }

  private escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Configuration
  // ─────────────────────────────────────────────────────────────────────────────

  addPattern(type: ThreatType, pattern: RegExp, severity: ThreatDetection['severity']): void {
    const existing = this.customPatterns.find(p => p.type === type);
    if (existing) {
      existing.patterns.push(pattern);
    } else {
      this.customPatterns.push({ type, patterns: [pattern], severity });
    }
  }

  setBlockThreshold(threshold: number): void {
    this.blockThreshold = Math.max(0, Math.min(100, threshold));
  }

  setMaxLength(length: number): void {
    this.maxLength = Math.max(1, length);
  }
}

export const promptArmor = new PromptArmor();
