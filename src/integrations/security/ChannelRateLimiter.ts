// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Channel Rate Limiter
// Sliding window rate limiting for messaging channels
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../core/event-bus/EventBus';

export interface RateLimitRule {
  key: string;           // e.g., 'user', 'channel', 'global'
  maxRequests: number;   // Max requests in window
  windowMs: number;      // Window size in milliseconds
  blockDurationMs?: number; // How long to block after exceeding (default: windowMs)
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetMs: number;
  blocked: boolean;
  blockedUntil?: number;
}

interface WindowEntry {
  timestamps: number[];
  blockedUntil?: number;
}

export class ChannelRateLimiter {
  private windows: Map<string, WindowEntry> = new Map();
  private rules: RateLimitRule[];
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor(rules?: RateLimitRule[]) {
    this.rules = rules ?? [
      // Default rules - conservative
      { key: 'user', maxRequests: 10, windowMs: 60000, blockDurationMs: 300000 },      // 10/min per user, 5 min block
      { key: 'channel', maxRequests: 30, windowMs: 60000, blockDurationMs: 60000 },    // 30/min per channel
      { key: 'global', maxRequests: 100, windowMs: 60000, blockDurationMs: 30000 },    // 100/min global
    ];

    // Cleanup old entries every minute
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Core Rate Limiting
  // ─────────────────────────────────────────────────────────────────────────────

  check(identifiers: { userId: string; channelId: string }): RateLimitResult {
    const now = Date.now();
    const results: RateLimitResult[] = [];

    for (const rule of this.rules) {
      const key = this.buildKey(rule.key, identifiers);
      const result = this.checkRule(key, rule, now);
      results.push(result);

      // If any rule blocks, return immediately
      if (!result.allowed) {
        eventBus.emit('security:ratelimit:blocked', {
          rule: rule.key,
          key,
          ...identifiers,
          blockedUntil: result.blockedUntil,
        });
        return result;
      }
    }

    // All rules passed - record the request
    for (const rule of this.rules) {
      const key = this.buildKey(rule.key, identifiers);
      this.recordRequest(key, now);
    }

    // Return the most restrictive result
    const mostRestrictive = results.reduce((a, b) => 
      a.remaining < b.remaining ? a : b
    );

    return mostRestrictive;
  }

  private checkRule(key: string, rule: RateLimitRule, now: number): RateLimitResult {
    const entry = this.windows.get(key) ?? { timestamps: [] };

    // Check if currently blocked
    if (entry.blockedUntil && now < entry.blockedUntil) {
      return {
        allowed: false,
        remaining: 0,
        resetMs: entry.blockedUntil - now,
        blocked: true,
        blockedUntil: entry.blockedUntil,
      };
    }

    // Clear block if expired
    if (entry.blockedUntil && now >= entry.blockedUntil) {
      entry.blockedUntil = undefined;
      entry.timestamps = [];
    }

    // Filter timestamps within window
    const windowStart = now - rule.windowMs;
    const recentTimestamps = entry.timestamps.filter(t => t > windowStart);
    entry.timestamps = recentTimestamps;

    const count = recentTimestamps.length;
    const remaining = Math.max(0, rule.maxRequests - count);

    if (count >= rule.maxRequests) {
      // Exceeded - apply block
      const blockDuration = rule.blockDurationMs ?? rule.windowMs;
      entry.blockedUntil = now + blockDuration;
      this.windows.set(key, entry);

      return {
        allowed: false,
        remaining: 0,
        resetMs: blockDuration,
        blocked: true,
        blockedUntil: entry.blockedUntil,
      };
    }

    this.windows.set(key, entry);

    // Calculate reset time (when oldest entry expires)
    const oldestTimestamp = recentTimestamps[0] ?? now;
    const resetMs = Math.max(0, (oldestTimestamp + rule.windowMs) - now);

    return {
      allowed: true,
      remaining: remaining - 1, // Account for this request
      resetMs,
      blocked: false,
    };
  }

  private recordRequest(key: string, timestamp: number): void {
    const entry = this.windows.get(key) ?? { timestamps: [] };
    entry.timestamps.push(timestamp);
    this.windows.set(key, entry);
  }

  private buildKey(ruleKey: string, identifiers: { userId: string; channelId: string }): string {
    switch (ruleKey) {
      case 'user': return `user:${identifiers.userId}`;
      case 'channel': return `channel:${identifiers.channelId}`;
      case 'global': return 'global';
      default: return `${ruleKey}:${identifiers.userId}:${identifiers.channelId}`;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Management
  // ─────────────────────────────────────────────────────────────────────────────

  unblock(identifier: string): void {
    for (const [key, entry] of this.windows) {
      if (key.includes(identifier)) {
        entry.blockedUntil = undefined;
        entry.timestamps = [];
        this.windows.set(key, entry);
      }
    }
    eventBus.emit('security:ratelimit:unblocked', { identifier });
  }

  getStatus(identifier: string): { blocked: boolean; remaining: number; blockedUntil?: number }[] {
    const status: { rule: string; blocked: boolean; remaining: number; blockedUntil?: number }[] = [];
    const now = Date.now();

    for (const rule of this.rules) {
      for (const [key, entry] of this.windows) {
        if (key.includes(identifier)) {
          const windowStart = now - rule.windowMs;
          const recentCount = entry.timestamps.filter(t => t > windowStart).length;
          
          status.push({
            rule: rule.key,
            blocked: entry.blockedUntil ? now < entry.blockedUntil : false,
            remaining: Math.max(0, rule.maxRequests - recentCount),
            blockedUntil: entry.blockedUntil,
          });
        }
      }
    }

    return status;
  }

  private cleanup(): void {
    const now = Date.now();
    const maxWindow = Math.max(...this.rules.map(r => r.windowMs));

    for (const [key, entry] of this.windows) {
      // Remove old timestamps
      entry.timestamps = entry.timestamps.filter(t => t > now - maxWindow);
      
      // Clear expired blocks
      if (entry.blockedUntil && now >= entry.blockedUntil) {
        entry.blockedUntil = undefined;
      }

      // Remove empty entries
      if (entry.timestamps.length === 0 && !entry.blockedUntil) {
        this.windows.delete(key);
      }
    }
  }

  shutdown(): void {
    clearInterval(this.cleanupInterval);
    this.windows.clear();
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Stats
  // ─────────────────────────────────────────────────────────────────────────────

  getStats(): {
    totalEntries: number;
    blockedUsers: number;
    requestsLastMinute: number;
  } {
    const now = Date.now();
    let blockedUsers = 0;
    let requestsLastMinute = 0;

    for (const [key, entry] of this.windows) {
      if (key.startsWith('user:') && entry.blockedUntil && now < entry.blockedUntil) {
        blockedUsers++;
      }
      if (key === 'global') {
        requestsLastMinute = entry.timestamps.filter(t => t > now - 60000).length;
      }
    }

    return {
      totalEntries: this.windows.size,
      blockedUsers,
      requestsLastMinute,
    };
  }
}

export const channelRateLimiter = new ChannelRateLimiter();
