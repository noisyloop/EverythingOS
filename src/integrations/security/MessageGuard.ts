// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Message Guard
// The main security pipeline for all incoming channel messages
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../core/event-bus/EventBus';
import { ChannelRateLimiter, RateLimitResult } from './ChannelRateLimiter';
import { PromptArmor, PromptArmorResult, ThreatType } from './PromptArmor';
import * as crypto from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface IncomingMessage {
  id: string;
  userId: string;
  username: string;
  channelId: string;
  channelType: 'discord' | 'telegram' | 'whatsapp' | 'slack' | 'terminal';
  content: string;
  timestamp: number;
  replyToId?: string;
  attachments?: { type: string; url: string }[];
  metadata?: Record<string, unknown>;
}

export interface GuardResult {
  allowed: boolean;
  message: IncomingMessage;
  sanitizedContent: string;
  
  // Detailed results
  rateLimit: RateLimitResult;
  promptArmor: PromptArmorResult;
  permissions: PermissionResult;
  
  // If blocked
  blockReason?: BlockReason;
  blockMessage?: string;
}

export interface PermissionResult {
  allowed: boolean;
  userAllowed: boolean;
  channelAllowed: boolean;
  commandAllowed: boolean;
  reason?: string;
}

export type BlockReason = 
  | 'rate_limited'
  | 'prompt_injection'
  | 'user_banned'
  | 'channel_not_whitelisted'
  | 'command_not_allowed'
  | 'content_policy'
  | 'attachment_blocked';

export interface AuditLogEntry {
  id: string;
  timestamp: number;
  messageId: string;
  userId: string;
  channelId: string;
  channelType: string;
  contentHash: string;  // SHA-256 hash, not actual content
  action: 'allowed' | 'blocked';
  blockReason?: BlockReason;
  riskScore: number;
  threats: ThreatType[];
  responseTime: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface MessageGuardConfig {
  // Rate limiting
  rateLimiting?: {
    enabled?: boolean;
    userLimit?: number;     // per minute
    channelLimit?: number;  // per minute
    globalLimit?: number;   // per minute
  };
  
  // Prompt protection
  promptProtection?: {
    enabled?: boolean;
    blockThreshold?: number;  // 0-100
    maxMessageLength?: number;
  };
  
  // Access control
  accessControl?: {
    enabled?: boolean;
    defaultAllow?: boolean;
    whitelistedChannels?: string[];
    blacklistedChannels?: string[];
    whitelistedUsers?: string[];
    blacklistedUsers?: string[];
    adminUsers?: string[];  // Can bypass restrictions
  };
  
  // Audit logging
  auditLogging?: {
    enabled?: boolean;
    logAllowed?: boolean;   // Log allowed messages too
    retentionDays?: number;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Message Guard
// ─────────────────────────────────────────────────────────────────────────────

export class MessageGuard {
  private rateLimiter: ChannelRateLimiter;
  private promptArmor: PromptArmor;
  private config: Required<MessageGuardConfig>;
  private auditLog: AuditLogEntry[] = [];
  private maxAuditEntries = 10000;

  constructor(config?: MessageGuardConfig) {
    this.config = this.mergeConfig(config);
    
    // Initialize rate limiter with custom rules if provided
    this.rateLimiter = new ChannelRateLimiter([
      { 
        key: 'user', 
        maxRequests: this.config.rateLimiting.userLimit, 
        windowMs: 60000,
        blockDurationMs: 300000,
      },
      { 
        key: 'channel', 
        maxRequests: this.config.rateLimiting.channelLimit, 
        windowMs: 60000,
        blockDurationMs: 60000,
      },
      { 
        key: 'global', 
        maxRequests: this.config.rateLimiting.globalLimit, 
        windowMs: 60000,
        blockDurationMs: 30000,
      },
    ]);

    // Initialize prompt armor
    this.promptArmor = new PromptArmor({
      maxLength: this.config.promptProtection.maxMessageLength,
      blockThreshold: this.config.promptProtection.blockThreshold,
    });
  }

  private mergeConfig(config?: MessageGuardConfig): Required<MessageGuardConfig> {
    return {
      rateLimiting: {
        enabled: config?.rateLimiting?.enabled ?? true,
        userLimit: config?.rateLimiting?.userLimit ?? 10,
        channelLimit: config?.rateLimiting?.channelLimit ?? 30,
        globalLimit: config?.rateLimiting?.globalLimit ?? 100,
      },
      promptProtection: {
        enabled: config?.promptProtection?.enabled ?? true,
        blockThreshold: config?.promptProtection?.blockThreshold ?? 50,
        maxMessageLength: config?.promptProtection?.maxMessageLength ?? 2000,
      },
      accessControl: {
        enabled: config?.accessControl?.enabled ?? true,
        defaultAllow: config?.accessControl?.defaultAllow ?? true,
        whitelistedChannels: config?.accessControl?.whitelistedChannels ?? [],
        blacklistedChannels: config?.accessControl?.blacklistedChannels ?? [],
        whitelistedUsers: config?.accessControl?.whitelistedUsers ?? [],
        blacklistedUsers: config?.accessControl?.blacklistedUsers ?? [],
        adminUsers: config?.accessControl?.adminUsers ?? [],
      },
      auditLogging: {
        enabled: config?.auditLogging?.enabled ?? true,
        logAllowed: config?.auditLogging?.logAllowed ?? false,
        retentionDays: config?.auditLogging?.retentionDays ?? 30,
      },
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Main Processing
  // ─────────────────────────────────────────────────────────────────────────────

  async process(message: IncomingMessage): Promise<GuardResult> {
    const startTime = Date.now();
    
    // Check if user is admin (bypass most checks)
    const isAdmin = this.config.accessControl.adminUsers.includes(message.userId);

    // Step 1: Check permissions
    const permissions = this.checkPermissions(message, isAdmin);
    if (!permissions.allowed) {
      return this.createBlockedResult(message, permissions, 'user_banned', startTime);
    }

    // Step 2: Rate limiting (admins bypass)
    let rateLimit: RateLimitResult = { allowed: true, remaining: 999, resetMs: 0, blocked: false };
    if (this.config.rateLimiting.enabled && !isAdmin) {
      rateLimit = this.rateLimiter.check({
        userId: message.userId,
        channelId: message.channelId,
      });
      
      if (!rateLimit.allowed) {
        const result = this.createBlockedResult(message, permissions, 'rate_limited', startTime);
        result.rateLimit = rateLimit;
        result.blockMessage = `Rate limited. Try again in ${Math.ceil(rateLimit.resetMs / 1000)} seconds.`;
        return result;
      }
    }

    // Step 3: Prompt armor analysis
    let promptArmorResult: PromptArmorResult = { 
      safe: true, 
      sanitized: message.content, 
      threats: [], 
      riskScore: 0 
    };
    
    if (this.config.promptProtection.enabled) {
      promptArmorResult = this.promptArmor.analyze(message.content);
      
      if (!promptArmorResult.safe) {
        const result = this.createBlockedResult(message, permissions, 'prompt_injection', startTime);
        result.promptArmor = promptArmorResult;
        result.blockMessage = 'Your message was blocked for security reasons.';
        return result;
      }
    }

    // All checks passed
    const result: GuardResult = {
      allowed: true,
      message,
      sanitizedContent: promptArmorResult.sanitized,
      rateLimit,
      promptArmor: promptArmorResult,
      permissions,
    };

    // Audit log
    if (this.config.auditLogging.enabled && this.config.auditLogging.logAllowed) {
      this.logAudit(message, 'allowed', undefined, promptArmorResult.riskScore, promptArmorResult.threats.map(t => t.type), startTime);
    }

    eventBus.emit('security:message:allowed', {
      messageId: message.id,
      userId: message.userId,
      channelId: message.channelId,
      riskScore: promptArmorResult.riskScore,
    });

    return result;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Permission Checking
  // ─────────────────────────────────────────────────────────────────────────────

  private checkPermissions(message: IncomingMessage, isAdmin: boolean): PermissionResult {
    if (!this.config.accessControl.enabled || isAdmin) {
      return { allowed: true, userAllowed: true, channelAllowed: true, commandAllowed: true };
    }

    // Check user blacklist
    if (this.config.accessControl.blacklistedUsers.includes(message.userId)) {
      return { 
        allowed: false, 
        userAllowed: false, 
        channelAllowed: true, 
        commandAllowed: true,
        reason: 'User is blacklisted',
      };
    }

    // Check channel blacklist
    if (this.config.accessControl.blacklistedChannels.includes(message.channelId)) {
      return { 
        allowed: false, 
        userAllowed: true, 
        channelAllowed: false, 
        commandAllowed: true,
        reason: 'Channel is blacklisted',
      };
    }

    // If whitelist mode and channel not whitelisted
    if (this.config.accessControl.whitelistedChannels.length > 0) {
      if (!this.config.accessControl.whitelistedChannels.includes(message.channelId)) {
        return { 
          allowed: false, 
          userAllowed: true, 
          channelAllowed: false, 
          commandAllowed: true,
          reason: 'Channel not whitelisted',
        };
      }
    }

    // Default allow/deny
    if (!this.config.accessControl.defaultAllow) {
      const userWhitelisted = this.config.accessControl.whitelistedUsers.includes(message.userId);
      if (!userWhitelisted) {
        return { 
          allowed: false, 
          userAllowed: false, 
          channelAllowed: true, 
          commandAllowed: true,
          reason: 'User not whitelisted (default deny mode)',
        };
      }
    }

    return { allowed: true, userAllowed: true, channelAllowed: true, commandAllowed: true };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Output Filtering
  // ─────────────────────────────────────────────────────────────────────────────

  filterOutput(output: string, systemPromptFragments?: string[]): string {
    return this.promptArmor.filterOutput(output, systemPromptFragments);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Audit Logging
  // ─────────────────────────────────────────────────────────────────────────────

  private logAudit(
    message: IncomingMessage, 
    action: 'allowed' | 'blocked',
    blockReason: BlockReason | undefined,
    riskScore: number,
    threats: ThreatType[],
    startTime: number
  ): void {
    const entry: AuditLogEntry = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      messageId: message.id,
      userId: message.userId,
      channelId: message.channelId,
      channelType: message.channelType,
      contentHash: this.hashContent(message.content),
      action,
      blockReason,
      riskScore,
      threats,
      responseTime: Date.now() - startTime,
    };

    this.auditLog.push(entry);

    // Trim old entries
    if (this.auditLog.length > this.maxAuditEntries) {
      this.auditLog = this.auditLog.slice(-this.maxAuditEntries / 2);
    }

    eventBus.emit('security:audit:logged', entry);
  }

  private hashContent(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Helper Methods
  // ─────────────────────────────────────────────────────────────────────────────

  private createBlockedResult(
    message: IncomingMessage,
    permissions: PermissionResult,
    blockReason: BlockReason,
    startTime: number
  ): GuardResult {
    // Log to audit
    if (this.config.auditLogging.enabled) {
      this.logAudit(message, 'blocked', blockReason, 100, [], startTime);
    }

    eventBus.emit('security:message:blocked', {
      messageId: message.id,
      userId: message.userId,
      channelId: message.channelId,
      reason: blockReason,
    });

    return {
      allowed: false,
      message,
      sanitizedContent: '',
      rateLimit: { allowed: true, remaining: 0, resetMs: 0, blocked: false },
      promptArmor: { safe: false, sanitized: '', threats: [], riskScore: 100 },
      permissions,
      blockReason,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Management
  // ─────────────────────────────────────────────────────────────────────────────

  banUser(userId: string): void {
    if (!this.config.accessControl.blacklistedUsers.includes(userId)) {
      this.config.accessControl.blacklistedUsers.push(userId);
      eventBus.emit('security:user:banned', { userId });
    }
  }

  unbanUser(userId: string): void {
    const index = this.config.accessControl.blacklistedUsers.indexOf(userId);
    if (index > -1) {
      this.config.accessControl.blacklistedUsers.splice(index, 1);
      this.rateLimiter.unblock(userId);
      eventBus.emit('security:user:unbanned', { userId });
    }
  }

  addAdmin(userId: string): void {
    if (!this.config.accessControl.adminUsers.includes(userId)) {
      this.config.accessControl.adminUsers.push(userId);
      eventBus.emit('security:admin:added', { userId });
    }
  }

  whitelistChannel(channelId: string): void {
    if (!this.config.accessControl.whitelistedChannels.includes(channelId)) {
      this.config.accessControl.whitelistedChannels.push(channelId);
      eventBus.emit('security:channel:whitelisted', { channelId });
    }
  }

  blacklistChannel(channelId: string): void {
    if (!this.config.accessControl.blacklistedChannels.includes(channelId)) {
      this.config.accessControl.blacklistedChannels.push(channelId);
      eventBus.emit('security:channel:blacklisted', { channelId });
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Stats & Reporting
  // ─────────────────────────────────────────────────────────────────────────────

  getStats(): {
    rateLimiter: ReturnType<ChannelRateLimiter['getStats']>;
    auditLog: { total: number; blocked: number; allowed: number; last24h: number };
    blockedUsers: number;
    whitelistedChannels: number;
  } {
    const now = Date.now();
    const day = 24 * 60 * 60 * 1000;

    return {
      rateLimiter: this.rateLimiter.getStats(),
      auditLog: {
        total: this.auditLog.length,
        blocked: this.auditLog.filter(e => e.action === 'blocked').length,
        allowed: this.auditLog.filter(e => e.action === 'allowed').length,
        last24h: this.auditLog.filter(e => e.timestamp > now - day).length,
      },
      blockedUsers: this.config.accessControl.blacklistedUsers.length,
      whitelistedChannels: this.config.accessControl.whitelistedChannels.length,
    };
  }

  getAuditLog(options?: { 
    limit?: number; 
    action?: 'allowed' | 'blocked';
    userId?: string;
    channelId?: string;
    since?: number;
  }): AuditLogEntry[] {
    let entries = [...this.auditLog];

    if (options?.action) {
      entries = entries.filter(e => e.action === options.action);
    }
    if (options?.userId) {
      entries = entries.filter(e => e.userId === options.userId);
    }
    if (options?.channelId) {
      entries = entries.filter(e => e.channelId === options.channelId);
    }
    if (options?.since) {
      entries = entries.filter(e => e.timestamp >= options.since);
    }

    // Sort by timestamp descending
    entries.sort((a, b) => b.timestamp - a.timestamp);

    if (options?.limit) {
      entries = entries.slice(0, options.limit);
    }

    return entries;
  }

  shutdown(): void {
    this.rateLimiter.shutdown();
  }
}

export const messageGuard = new MessageGuard();
