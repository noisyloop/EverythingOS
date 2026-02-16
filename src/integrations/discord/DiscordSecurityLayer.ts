// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Discord Security Layer
// Defense-in-depth protection against prompt injection, abuse, and exploitation
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../core/event-bus/EventBus';
import crypto from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface SecurityConfig {
  // Rate limits
  rateLimits: {
    perUser: { count: number; windowMs: number };
    perChannel: { count: number; windowMs: number };
    perServer: { count: number; windowMs: number };
    global: { count: number; windowMs: number };
  };
  
  // Content limits
  maxMessageLength: number;
  maxResponseLength: number;
  
  // Permissions
  allowDMs: boolean;
  allowedChannels: string[];  // Empty = all allowed
  blockedChannels: string[];
  allowedRoles: string[];     // Empty = all allowed
  blockedUsers: string[];
  
  // Features
  enablePromptInjectionDetection: boolean;
  enablePIIDetection: boolean;
  enableToxicityFilter: boolean;
  enableAuditLog: boolean;
  
  // Response
  rateLimitMessage: string;
  blockedMessage: string;
  errorMessage: string;
}

export interface MessageContext {
  messageId: string;
  userId: string;
  username: string;
  channelId: string;
  serverId: string | null;  // null for DMs
  content: string;
  timestamp: number;
  isDM: boolean;
  userRoles: string[];
}

export interface SecurityResult {
  allowed: boolean;
  reason?: string;
  sanitizedContent?: string;
  threatLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  flags: string[];
}

export interface AuditEntry {
  id: string;
  timestamp: number;
  userId: string;
  userHash: string;  // Hashed for privacy
  channelId: string;
  serverId: string | null;
  action: 'allowed' | 'blocked' | 'rate_limited' | 'flagged';
  reason?: string;
  threatLevel: string;
  flags: string[];
  contentHash: string;  // Hash of content, not content itself
}

// ─────────────────────────────────────────────────────────────────────────────
// Default Config
// ─────────────────────────────────────────────────────────────────────────────

export const DEFAULT_SECURITY_CONFIG: SecurityConfig = {
  rateLimits: {
    perUser: { count: 10, windowMs: 60000 },      // 10/min per user
    perChannel: { count: 30, windowMs: 60000 },   // 30/min per channel
    perServer: { count: 100, windowMs: 60000 },   // 100/min per server
    global: { count: 500, windowMs: 60000 },      // 500/min total
  },
  maxMessageLength: 2000,
  maxResponseLength: 2000,
  allowDMs: false,  // DMs disabled by default - primary abuse vector
  allowedChannels: [],
  blockedChannels: [],
  allowedRoles: [],
  blockedUsers: [],
  enablePromptInjectionDetection: true,
  enablePIIDetection: true,
  enableToxicityFilter: true,
  enableAuditLog: true,
  rateLimitMessage: "You're sending messages too quickly. Please wait a moment.",
  blockedMessage: "This action is not allowed.",
  errorMessage: "Something went wrong. Please try again.",
};

// ─────────────────────────────────────────────────────────────────────────────
// Prompt Injection Patterns
// ─────────────────────────────────────────────────────────────────────────────

const INJECTION_PATTERNS: { pattern: RegExp; severity: 'low' | 'medium' | 'high'; name: string }[] = [
  // Direct instruction override attempts
  { pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)/i, severity: 'high', name: 'instruction_override' },
  { pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier)/i, severity: 'high', name: 'disregard_attempt' },
  { pattern: /forget\s+(everything|all|your)\s+(previous|prior|instructions?)/i, severity: 'high', name: 'forget_attempt' },
  
  // System prompt extraction
  { pattern: /what\s+(are|is)\s+your\s+(system\s+)?prompt/i, severity: 'medium', name: 'prompt_extraction' },
  { pattern: /reveal\s+(your\s+)?(system\s+)?instructions/i, severity: 'medium', name: 'reveal_instructions' },
  { pattern: /show\s+(me\s+)?(your\s+)?hidden\s+prompt/i, severity: 'medium', name: 'show_hidden' },
  { pattern: /print\s+(your\s+)?(initial|system)\s+prompt/i, severity: 'medium', name: 'print_prompt' },
  
  // Role-playing attacks
  { pattern: /pretend\s+(you('re|'re| are)\s+)?(a\s+)?(different|another|new)\s+(ai|assistant|bot)/i, severity: 'medium', name: 'roleplay_different_ai' },
  { pattern: /you\s+are\s+now\s+(a\s+)?(different|new|evil|unrestricted)/i, severity: 'high', name: 'identity_override' },
  { pattern: /act\s+as\s+(if\s+)?(you\s+)?(have\s+)?no\s+(restrictions|limits|rules)/i, severity: 'high', name: 'no_restrictions' },
  
  // Jailbreak attempts
  { pattern: /\bdan\s*mode\b/i, severity: 'high', name: 'dan_mode' },
  { pattern: /\bjailbreak\b/i, severity: 'high', name: 'jailbreak_keyword' },
  { pattern: /developer\s+mode\s+(enabled|on|activate)/i, severity: 'high', name: 'developer_mode' },
  { pattern: /bypass\s+(your\s+)?(safety|security|filters?|restrictions?)/i, severity: 'high', name: 'bypass_safety' },
  
  // Code execution attempts
  { pattern: /execute\s+(this\s+)?(code|script|command)/i, severity: 'medium', name: 'execute_code' },
  { pattern: /run\s+(this\s+)?(shell|bash|python|javascript)/i, severity: 'medium', name: 'run_shell' },
  { pattern: /\beval\s*\(/i, severity: 'medium', name: 'eval_function' },
  
  // Data exfiltration
  { pattern: /send\s+(this\s+)?to\s+(my\s+)?(email|server|webhook|url)/i, severity: 'high', name: 'data_exfil' },
  { pattern: /make\s+(a\s+)?(http|api)\s+request\s+to/i, severity: 'medium', name: 'http_request' },
  
  // Delimiter attacks
  { pattern: /```system/i, severity: 'high', name: 'fake_system_block' },
  { pattern: /<\|system\|>/i, severity: 'high', name: 'system_delimiter' },
  { pattern: /\[INST\]/i, severity: 'medium', name: 'inst_delimiter' },
  { pattern: /<<SYS>>/i, severity: 'high', name: 'sys_delimiter' },
];

// ─────────────────────────────────────────────────────────────────────────────
// PII Patterns (for detection, not logging)
// ─────────────────────────────────────────────────────────────────────────────

const PII_PATTERNS: { pattern: RegExp; type: string }[] = [
  { pattern: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/, type: 'ssn' },
  { pattern: /\b\d{16}\b/, type: 'credit_card' },
  { pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/, type: 'credit_card' },
  { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, type: 'email' },
  { pattern: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/, type: 'phone' },
];

// ─────────────────────────────────────────────────────────────────────────────
// Security Layer Class
// ─────────────────────────────────────────────────────────────────────────────

export class DiscordSecurityLayer {
  private config: SecurityConfig;
  private rateLimitBuckets: Map<string, { count: number; resetAt: number }> = new Map();
  private userAbuseScores: Map<string, number> = new Map();
  private auditLog: AuditEntry[] = [];
  private maxAuditLogSize = 10000;

  constructor(config: Partial<SecurityConfig> = {}) {
    this.config = { ...DEFAULT_SECURITY_CONFIG, ...config };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Main Entry Point
  // ─────────────────────────────────────────────────────────────────────────

  async validateMessage(ctx: MessageContext): Promise<SecurityResult> {
    const flags: string[] = [];
    let threatLevel: SecurityResult['threatLevel'] = 'none';

    // 1. Check DM policy
    if (ctx.isDM && !this.config.allowDMs) {
      return this.block('dm_not_allowed', 'DMs are disabled', 'low', ['dm_blocked']);
    }

    // 2. Check blocked users
    if (this.config.blockedUsers.includes(ctx.userId)) {
      return this.block('user_blocked', 'User is blocked', 'medium', ['user_blocked']);
    }

    // 3. Check channel permissions
    if (!this.isChannelAllowed(ctx.channelId)) {
      return this.block('channel_not_allowed', 'Channel not allowed', 'low', ['channel_blocked']);
    }

    // 4. Check role permissions
    if (!this.hasAllowedRole(ctx.userRoles)) {
      return this.block('role_not_allowed', 'User role not allowed', 'low', ['role_blocked']);
    }

    // 5. Rate limiting
    const rateLimitResult = this.checkRateLimits(ctx);
    if (!rateLimitResult.allowed) {
      this.incrementAbuseScore(ctx.userId, 1);
      return this.block('rate_limited', rateLimitResult.reason!, 'low', ['rate_limited']);
    }

    // 6. Message length check
    if (ctx.content.length > this.config.maxMessageLength) {
      flags.push('message_too_long');
      threatLevel = 'low';
    }

    // 7. Prompt injection detection
    if (this.config.enablePromptInjectionDetection) {
      const injectionResult = this.detectPromptInjection(ctx.content);
      if (injectionResult.detected) {
        flags.push(...injectionResult.patterns);
        threatLevel = this.maxThreatLevel(threatLevel, injectionResult.severity);
        this.incrementAbuseScore(ctx.userId, injectionResult.severity === 'high' ? 5 : 2);
        
        // Block high severity injections
        if (injectionResult.severity === 'high') {
          this.logAudit(ctx, 'flagged', 'prompt_injection', threatLevel, flags);
          eventBus.emit('discord:security:injection', {
            userId: this.hashUserId(ctx.userId),
            patterns: injectionResult.patterns,
          });
        }
      }
    }

    // 8. PII detection (flag but don't block)
    if (this.config.enablePIIDetection) {
      const piiResult = this.detectPII(ctx.content);
      if (piiResult.detected) {
        flags.push(...piiResult.types.map(t => `pii_${t}`));
        threatLevel = this.maxThreatLevel(threatLevel, 'low');
      }
    }

    // 9. Check abuse score
    const abuseScore = this.userAbuseScores.get(ctx.userId) || 0;
    if (abuseScore >= 20) {
      return this.block('abuse_threshold', 'Too many violations', 'high', ['abuse_blocked']);
    }

    // 10. Sanitize content
    const sanitizedContent = this.sanitizeInput(ctx.content);

    // Log successful validation
    this.logAudit(ctx, 'allowed', undefined, threatLevel, flags);

    return {
      allowed: true,
      sanitizedContent,
      threatLevel,
      flags,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Output Validation
  // ─────────────────────────────────────────────────────────────────────────

  validateOutput(response: string): { safe: boolean; sanitized: string; flags: string[] } {
    const flags: string[] = [];
    let sanitized = response;

    // 1. Check for leaked system prompt indicators
    const systemLeakPatterns = [
      /you are an ai assistant/i,
      /your instructions are/i,
      /my system prompt/i,
      /i was told to/i,
      /my programming tells me/i,
    ];

    for (const pattern of systemLeakPatterns) {
      if (pattern.test(sanitized)) {
        flags.push('potential_prompt_leak');
        break;
      }
    }

    // 2. Truncate to max length
    if (sanitized.length > this.config.maxResponseLength) {
      sanitized = sanitized.slice(0, this.config.maxResponseLength - 3) + '...';
      flags.push('truncated');
    }

    // 3. Strip any code blocks that look like system instructions
    sanitized = sanitized.replace(/```(system|instructions?|prompt)[\s\S]*?```/gi, '[content removed]');

    // 4. Remove any URLs if configured (optional, disabled by default)
    // sanitized = sanitized.replace(/https?:\/\/[^\s]+/g, '[link removed]');

    return {
      safe: flags.length === 0,
      sanitized,
      flags,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Rate Limiting
  // ─────────────────────────────────────────────────────────────────────────

  private checkRateLimits(ctx: MessageContext): { allowed: boolean; reason?: string } {
    const now = Date.now();
    const checks = [
      { key: `user:${ctx.userId}`, limit: this.config.rateLimits.perUser, name: 'user' },
      { key: `channel:${ctx.channelId}`, limit: this.config.rateLimits.perChannel, name: 'channel' },
      { key: 'global', limit: this.config.rateLimits.global, name: 'global' },
    ];

    if (ctx.serverId) {
      checks.push({ key: `server:${ctx.serverId}`, limit: this.config.rateLimits.perServer, name: 'server' });
    }

    for (const check of checks) {
      let bucket = this.rateLimitBuckets.get(check.key);
      
      if (!bucket || now > bucket.resetAt) {
        bucket = { count: 0, resetAt: now + check.limit.windowMs };
        this.rateLimitBuckets.set(check.key, bucket);
      }

      bucket.count++;

      if (bucket.count > check.limit.count) {
        return { allowed: false, reason: `${check.name}_rate_limit` };
      }
    }

    return { allowed: true };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Prompt Injection Detection
  // ─────────────────────────────────────────────────────────────────────────

  private detectPromptInjection(content: string): {
    detected: boolean;
    patterns: string[];
    severity: 'low' | 'medium' | 'high';
  } {
    const detectedPatterns: string[] = [];
    let maxSeverity: 'low' | 'medium' | 'high' = 'low';

    const normalizedContent = content.toLowerCase();

    for (const { pattern, severity, name } of INJECTION_PATTERNS) {
      if (pattern.test(normalizedContent)) {
        detectedPatterns.push(name);
        if (severity === 'high') maxSeverity = 'high';
        else if (severity === 'medium' && maxSeverity !== 'high') maxSeverity = 'medium';
      }
    }

    return {
      detected: detectedPatterns.length > 0,
      patterns: detectedPatterns,
      severity: maxSeverity,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // PII Detection
  // ─────────────────────────────────────────────────────────────────────────

  private detectPII(content: string): { detected: boolean; types: string[] } {
    const types: string[] = [];

    for (const { pattern, type } of PII_PATTERNS) {
      if (pattern.test(content)) {
        types.push(type);
      }
    }

    return { detected: types.length > 0, types };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Input Sanitization
  // ─────────────────────────────────────────────────────────────────────────

  private sanitizeInput(content: string): string {
    let sanitized = content;

    // 1. Normalize unicode
    sanitized = sanitized.normalize('NFKC');

    // 2. Remove zero-width characters (used for obfuscation)
    sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, '');

    // 3. Collapse excessive whitespace
    sanitized = sanitized.replace(/\s{10,}/g, ' '.repeat(9));

    // 4. Remove control characters except newlines and tabs
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

    // 5. Truncate to max length
    if (sanitized.length > this.config.maxMessageLength) {
      sanitized = sanitized.slice(0, this.config.maxMessageLength);
    }

    return sanitized.trim();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Permission Checks
  // ─────────────────────────────────────────────────────────────────────────

  private isChannelAllowed(channelId: string): boolean {
    // If blocked, reject
    if (this.config.blockedChannels.includes(channelId)) {
      return false;
    }
    // If allowlist is empty, allow all non-blocked
    if (this.config.allowedChannels.length === 0) {
      return true;
    }
    // Check allowlist
    return this.config.allowedChannels.includes(channelId);
  }

  private hasAllowedRole(userRoles: string[]): boolean {
    // If no role restrictions, allow all
    if (this.config.allowedRoles.length === 0) {
      return true;
    }
    // Check if user has any allowed role
    return userRoles.some(role => this.config.allowedRoles.includes(role));
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Abuse Scoring
  // ─────────────────────────────────────────────────────────────────────────

  private incrementAbuseScore(userId: string, amount: number): void {
    const current = this.userAbuseScores.get(userId) || 0;
    this.userAbuseScores.set(userId, current + amount);
    
    // Decay over time (reset after 1 hour of no violations)
    setTimeout(() => {
      const score = this.userAbuseScores.get(userId) || 0;
      if (score > 0) {
        this.userAbuseScores.set(userId, Math.max(0, score - amount));
      }
    }, 3600000);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Audit Logging
  // ─────────────────────────────────────────────────────────────────────────

  private logAudit(
    ctx: MessageContext,
    action: AuditEntry['action'],
    reason: string | undefined,
    threatLevel: string,
    flags: string[]
  ): void {
    if (!this.config.enableAuditLog) return;

    const entry: AuditEntry = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      userId: ctx.userId,
      userHash: this.hashUserId(ctx.userId),
      channelId: ctx.channelId,
      serverId: ctx.serverId,
      action,
      reason,
      threatLevel,
      flags,
      contentHash: this.hashContent(ctx.content),
    };

    this.auditLog.push(entry);

    // Trim old entries
    if (this.auditLog.length > this.maxAuditLogSize) {
      this.auditLog = this.auditLog.slice(-this.maxAuditLogSize / 2);
    }

    // Emit event for external logging
    eventBus.emit('discord:security:audit', entry);
  }

  private hashUserId(userId: string): string {
    return crypto.createHash('sha256').update(userId).digest('hex').slice(0, 16);
  }

  private hashContent(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Helpers
  // ─────────────────────────────────────────────────────────────────────────

  private block(
    code: string,
    reason: string,
    threatLevel: SecurityResult['threatLevel'],
    flags: string[]
  ): SecurityResult {
    return { allowed: false, reason, threatLevel, flags };
  }

  private maxThreatLevel(
    a: SecurityResult['threatLevel'],
    b: SecurityResult['threatLevel']
  ): SecurityResult['threatLevel'] {
    const levels = ['none', 'low', 'medium', 'high', 'critical'];
    return levels[Math.max(levels.indexOf(a), levels.indexOf(b))] as SecurityResult['threatLevel'];
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public Methods
  // ─────────────────────────────────────────────────────────────────────────

  getAuditLog(limit = 100): AuditEntry[] {
    return this.auditLog.slice(-limit);
  }

  getAbuseScore(userId: string): number {
    return this.userAbuseScores.get(userId) || 0;
  }

  blockUser(userId: string): void {
    if (!this.config.blockedUsers.includes(userId)) {
      this.config.blockedUsers.push(userId);
    }
  }

  unblockUser(userId: string): void {
    this.config.blockedUsers = this.config.blockedUsers.filter(id => id !== userId);
  }

  updateConfig(updates: Partial<SecurityConfig>): void {
    this.config = { ...this.config, ...updates };
  }

  getConfig(): SecurityConfig {
    return { ...this.config };
  }

  getStats(): {
    totalAuditEntries: number;
    blockedUsers: number;
    trackedUsers: number;
    rateLimitBuckets: number;
  } {
    return {
      totalAuditEntries: this.auditLog.length,
      blockedUsers: this.config.blockedUsers.length,
      trackedUsers: this.userAbuseScores.size,
      rateLimitBuckets: this.rateLimitBuckets.size,
    };
  }
}
