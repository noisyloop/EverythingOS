/**
 * Agent Authentication & EventBus Access Control
 *
 * NIST AI RMF 1.0 — MANAGE Function (MG-2.2), GOVERN Function (GV-2)
 * NIST AI 600-1 — Cybersecurity Attacks, Accountability
 *
 * Issues HMAC-signed tokens to agents at registration. All EventBus publish
 * calls must present a valid token. The token encodes the agent's declared
 * channel permissions, which are enforced at publish and subscribe time.
 *
 * Usage:
 *   import { AgentAuthManager } from '../security/agent-auth';
 *
 *   // At agent registration:
 *   const token = AgentAuthManager.issueToken(agentId, riskConfig);
 *
 *   // Before EventBus publish:
 *   const allowed = AgentAuthManager.canPublish(token, 'discord:message');
 *
 *   // Before EventBus subscribe:
 *   const allowed = AgentAuthManager.canSubscribe(token, 'user:*');
 */

import { createHmac, randomBytes } from 'crypto';
import { AuditLogger } from './audit-log';
import { AgentRiskConfig, AgentRiskTier } from '../types/agent-risk';

// ─────────────────────────────────────────────────────────────────────────────
// Secret Key — load from environment, never hardcode
// ─────────────────────────────────────────────────────────────────────────────

const SECRET_KEY: string = (() => {
  const key = process.env.EOS_AGENT_SECRET;
  if (!key) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        '[AgentAuth] EOS_AGENT_SECRET environment variable is required in production. ' +
        'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
      );
    }
    // Development fallback — warn loudly
    const devKey = randomBytes(32).toString('hex');
    console.warn(
      '[AgentAuth] WARNING: EOS_AGENT_SECRET not set. Using ephemeral key. ' +
      'All tokens will be invalidated on restart. Set EOS_AGENT_SECRET in .env for stability.'
    );
    return devKey;
  }
  return key;
})();

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface AgentToken {
  /** The raw HMAC token string to present on EventBus calls */
  token: string;
  /** Agent ID this token belongs to */
  agentId: string;
  /** Risk tier declared at registration */
  tier: AgentRiskTier;
  /** Channels this agent may publish to */
  allowedPublishChannels: string[];
  /** Channels this agent may subscribe to (supports wildcards) */
  allowedSubscribeChannels: string[];
  /** Unix timestamp when this token was issued */
  issuedAt: number;
  /** Unix timestamp when this token expires (0 = no expiry) */
  expiresAt: number;
  /** Whether this token has been revoked */
  revoked: boolean;
}

export interface TokenValidationResult {
  valid: boolean;
  token?: AgentToken;
  reason?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Token Registry (in-memory, survives for process lifetime)
// ─────────────────────────────────────────────────────────────────────────────

const tokenRegistry = new Map<string, AgentToken>();

// ─────────────────────────────────────────────────────────────────────────────
// HMAC Helpers
// ─────────────────────────────────────────────────────────────────────────────

function sign(agentId: string, issuedAt: number): string {
  const payload = `${agentId}:${issuedAt}`;
  return createHmac('sha256', SECRET_KEY).update(payload).digest('hex');
}

function verify(agentId: string, issuedAt: number, token: string): boolean {
  const expected = sign(agentId, issuedAt);
  // Constant-time comparison to prevent timing attacks
  if (expected.length !== token.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ token.charCodeAt(i);
  }
  return diff === 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Wildcard Channel Matching
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Checks if a channel matches a pattern, supporting wildcards.
 * 'user:*' matches 'user:message', 'user:join', etc.
 * '*' matches everything.
 */
function channelMatches(pattern: string, channel: string): boolean {
  if (pattern === '*') return true;
  if (!pattern.includes('*')) return pattern === channel;

  // Convert glob pattern to regex
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`).test(channel);
}

function isChannelAllowed(allowedPatterns: string[], channel: string): boolean {
  return allowedPatterns.some((p) => channelMatches(p, channel));
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentAuthManager
// ─────────────────────────────────────────────────────────────────────────────

export const AgentAuthManager = {
  /**
   * Issue a new HMAC token for an agent at registration time.
   * The token encodes the agent's declared channel permissions.
   *
   * @param agentId - Unique agent identifier
   * @param riskConfig - The agent's risk configuration (from AgentRiskConfig)
   * @param ttlMs - Token time-to-live in ms. 0 = no expiry. Default: 24 hours.
   */
  issueToken(
    agentId: string,
    riskConfig: AgentRiskConfig,
    ttlMs: number = 24 * 60 * 60 * 1000,
  ): AgentToken {
    const issuedAt = Date.now();
    const token = sign(agentId, issuedAt);
    const expiresAt = ttlMs > 0 ? issuedAt + ttlMs : 0;

    const agentToken: AgentToken = {
      token,
      agentId,
      tier: riskConfig.tier,
      allowedPublishChannels: riskConfig.allowedPublishChannels,
      allowedSubscribeChannels: riskConfig.allowedSubscribeChannels,
      issuedAt,
      expiresAt,
      revoked: false,
    };

    tokenRegistry.set(agentId, agentToken);

    AuditLogger.log({
      agentId,
      event: 'auth.token_issued',
      metadata: {
        tier: riskConfig.tier,
        publishChannels: riskConfig.allowedPublishChannels,
        subscribeChannels: riskConfig.allowedSubscribeChannels,
        expiresAt,
      },
    });

    return agentToken;
  },

  /**
   * Validates a token string for a given agentId.
   * Returns the stored token record if valid.
   */
  validateToken(agentId: string, tokenStr: string): TokenValidationResult {
    const stored = tokenRegistry.get(agentId);

    if (!stored) {
      AuditLogger.log({ agentId, event: 'auth.token_rejected', metadata: { reason: 'not_registered' } });
      return { valid: false, reason: 'Agent not registered' };
    }

    if (stored.revoked) {
      AuditLogger.log({ agentId, event: 'auth.token_rejected', metadata: { reason: 'revoked' } });
      return { valid: false, reason: 'Token revoked' };
    }

    if (stored.expiresAt > 0 && Date.now() > stored.expiresAt) {
      AuditLogger.log({ agentId, event: 'auth.token_rejected', metadata: { reason: 'expired' } });
      return { valid: false, reason: 'Token expired' };
    }

    if (!verify(agentId, stored.issuedAt, tokenStr)) {
      AuditLogger.log({ agentId, event: 'auth.token_rejected', metadata: { reason: 'invalid_signature' } });
      return { valid: false, reason: 'Invalid token signature' };
    }

    AuditLogger.log({ agentId, event: 'auth.token_validated' });
    return { valid: true, token: stored };
  },

  /**
   * Checks if an agent (identified by agentId) is allowed to publish to a channel.
   * The agent's token must be valid AND the channel must be in allowedPublishChannels.
   *
   * @param agentId - Agent requesting to publish
   * @param tokenStr - The agent's HMAC token
   * @param channel - EventBus channel to publish to
   */
  canPublish(agentId: string, tokenStr: string, channel: string): boolean {
    const validation = this.validateToken(agentId, tokenStr);

    if (!validation.valid || !validation.token) {
      AuditLogger.log({
        agentId,
        event: 'eventbus.publish_blocked',
        metadata: { channel, reason: validation.reason ?? 'invalid_token' },
      });
      return false;
    }

    const allowed = isChannelAllowed(validation.token.allowedPublishChannels, channel);

    if (!allowed) {
      AuditLogger.log({
        agentId,
        event: 'agent.permission_denied',
        metadata: {
          action: 'publish',
          channel,
          allowedChannels: validation.token.allowedPublishChannels,
        },
      });
    }

    return allowed;
  },

  /**
   * Checks if an agent is allowed to subscribe to a channel.
   *
   * @param agentId - Agent requesting to subscribe
   * @param tokenStr - The agent's HMAC token
   * @param channel - EventBus channel to subscribe to
   */
  canSubscribe(agentId: string, tokenStr: string, channel: string): boolean {
    const validation = this.validateToken(agentId, tokenStr);

    if (!validation.valid || !validation.token) {
      return false;
    }

    const allowed = isChannelAllowed(validation.token.allowedSubscribeChannels, channel);

    if (!allowed) {
      AuditLogger.log({
        agentId,
        event: 'agent.permission_denied',
        metadata: {
          action: 'subscribe',
          channel,
          allowedChannels: validation.token.allowedSubscribeChannels,
        },
      });
    }

    return allowed;
  },

  /**
   * Revoke an agent's token immediately.
   * All subsequent EventBus operations from this agent will be blocked.
   */
  revokeToken(agentId: string, revokedBy: string = 'system'): boolean {
    const stored = tokenRegistry.get(agentId);
    if (!stored) return false;

    stored.revoked = true;
    AuditLogger.log({
      agentId,
      event: 'auth.token_revoked',
      metadata: { revokedBy },
    });

    return true;
  },

  /**
   * Revoke all tokens and re-issue them.
   * Use after a security incident or credential rotation.
   *
   * @param riskConfigs - Map of agentId to riskConfig for re-issuance
   */
  rotateAll(riskConfigs: Map<string, AgentRiskConfig>): void {
    for (const [agentId, config] of riskConfigs) {
      this.revokeToken(agentId, 'key_rotation');
      this.issueToken(agentId, config);
    }
  },

  /**
   * List all registered tokens and their status.
   * For admin/audit use only.
   */
  listTokens(): Array<Omit<AgentToken, 'token'>> {
    return Array.from(tokenRegistry.values()).map(({ token: _, ...rest }) => rest);
  },
};
