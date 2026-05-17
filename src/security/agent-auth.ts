/**
 * Agent Authentication & EventBus Access Control
 *
 * NIST AI RMF 1.0 — MANAGE Function (MG-2.2), GOVERN Function (GV-2)
 * NIST AI 600-1 — Cybersecurity Attacks, Accountability
 *
 * Security model:
 *   1. Each agent gets a session token (HMAC of agentId:issuedAt) at registration.
 *   2. Every individual publish/subscribe call must present a per-call signature
 *      derived from a per-agent callSigningKey, a fresh nonce, and a timestamp.
 *      This prevents replay of captured tokens within their TTL window.
 *   3. Used nonces are tracked in a 5-minute sliding window — exact replay is
 *      immediately detected regardless of TTL.
 *   4. Revocations are persisted to disk so they survive process restarts.
 *      A quarantined agent cannot re-register after a crash.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { appendFileSync, existsSync, readFileSync } from 'fs';
import { resolve } from 'path';
import { AuditLogger } from './audit-log';
import { AgentRiskConfig, AgentRiskTier } from '../types/agent-risk';

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

// ─────────────────────────────────────────────────────────────────────────────
// Master secret — signs session tokens at registration
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
// Revocation persistence — survives process restarts
// ─────────────────────────────────────────────────────────────────────────────

const REVOCATION_LOG_PATH = resolve(
  process.env.AGENT_REVOCATION_LOG ?? './agent-revocations.jsonl'
);

// Hash chain state for the revocation log
let lastRevocationHash = 'GENESIS';

interface RevocationRecord {
  agentId: string;
  revokedBy: string;
  revokedAt: number;
  previousHash: string;
  entryHash: string;
}

function persistRevocation(agentId: string, revokedBy: string): void {
  const partial = { agentId, revokedBy, revokedAt: Date.now(), previousHash: lastRevocationHash };
  const entryHash = sha256(JSON.stringify(partial));
  const record = JSON.stringify({ ...partial, entryHash });
  try {
    appendFileSync(REVOCATION_LOG_PATH, record + '\n', 'utf8');
    lastRevocationHash = entryHash;
  } catch (err) {
    console.error('[AgentAuth] Failed to persist revocation:', err);
  }
}

function loadPersistentRevocations(): Set<string> {
  const revoked = new Set<string>();
  if (!existsSync(REVOCATION_LOG_PATH)) return revoked;

  let lines: string[];
  try {
    lines = readFileSync(REVOCATION_LOG_PATH, 'utf8').split('\n').filter(Boolean);
  } catch {
    console.error('[AgentAuth] CRITICAL: Failed to read revocation log. All revocations may be lost.');
    return revoked;
  }

  let chainHash = 'GENESIS';
  let legacyEntries = 0;
  let chainBroken = false;

  for (let i = 0; i < lines.length; i++) {
    let entry: Partial<RevocationRecord>;
    try {
      entry = JSON.parse(lines[i]) as Partial<RevocationRecord>;
    } catch {
      // Parse failure — treat as critical security event and skip
      console.error(`[AgentAuth] CRITICAL: Revocation log line ${i + 1} failed to parse. File may be tampered.`);
      AuditLogger.log({
        agentId: 'agent-auth',
        event: 'security.injection_detected',
        metadata: { type: 'revocation_log_parse_error', line: i + 1 },
      });
      continue;
    }

    if (!entry.agentId) continue;

    if (entry.entryHash && entry.previousHash !== undefined) {
      // New chain-verified format
      if (!chainBroken) {
        if (entry.previousHash !== chainHash) {
          chainBroken = true;
          console.error(`[AgentAuth] CRITICAL: Revocation log chain broken at line ${i + 1}. File may have been tampered.`);
          AuditLogger.log({
            agentId: 'agent-auth',
            event: 'security.injection_detected',
            metadata: { type: 'revocation_chain_broken', line: i + 1, agentId: entry.agentId },
          });
        } else {
          const { entryHash, ...rest } = entry as RevocationRecord;
          const expected = sha256(JSON.stringify(rest));
          if (expected !== entryHash) {
            chainBroken = true;
            console.error(`[AgentAuth] CRITICAL: Revocation entry hash mismatch at line ${i + 1} for agent ${entry.agentId}.`);
            AuditLogger.log({
              agentId: 'agent-auth',
              event: 'security.injection_detected',
              metadata: { type: 'revocation_entry_tampered', line: i + 1, agentId: entry.agentId },
            });
          } else {
            chainHash = entryHash;
          }
        }
      }
    } else {
      legacyEntries++;
    }

    revoked.add(entry.agentId);
  }

  if (legacyEntries > 0) {
    console.warn(`[AgentAuth] WARNING: ${legacyEntries} legacy revocation entries without hash chain. Run a migration to upgrade.`);
  }
  if (chainBroken) {
    console.error('[AgentAuth] CRITICAL: Revocation log integrity check failed. Review agent-revocations.jsonl before proceeding.');
  }

  lastRevocationHash = chainHash;
  return revoked;
}

const persistentlyRevokedAgents: Set<string> = loadPersistentRevocations();

// ─────────────────────────────────────────────────────────────────────────────
// Per-call nonce cache — prevents replay within TTL window
// ─────────────────────────────────────────────────────────────────────────────

const NONCE_WINDOW_MS = 5 * 60 * 1000;    // 5 minutes
const MAX_CLOCK_SKEW_MS = 60 * 1000;       // tolerate 1 minute clock drift

const usedNonces = new Map<string, number>(); // nonce -> expiry timestamp

function purgeExpiredNonces(): void {
  const now = Date.now();
  for (const [nonce, expiry] of usedNonces) {
    if (now > expiry) usedNonces.delete(nonce);
  }
}

function consumeNonce(nonce: string): boolean {
  purgeExpiredNonces();
  if (usedNonces.has(nonce)) return false;
  usedNonces.set(nonce, Date.now() + NONCE_WINDOW_MS);
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface AgentToken {
  /** HMAC session token — proves identity at registration time */
  token: string;
  /**
   * Per-agent call signing key — used to sign individual EventBus calls.
   * Never expose this outside the agent. Never log it.
   */
  callSigningKey: string;
  agentId: string;
  tier: AgentRiskTier;
  allowedPublishChannels: string[];
  allowedSubscribeChannels: string[];
  issuedAt: number;
  expiresAt: number;
  revoked: boolean;
}

export interface TokenValidationResult {
  valid: boolean;
  token?: AgentToken;
  reason?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Token registry (in-memory; revocations are also persisted to disk)
// ─────────────────────────────────────────────────────────────────────────────

const tokenRegistry = new Map<string, AgentToken>();

// ─────────────────────────────────────────────────────────────────────────────
// Crypto helpers
// ─────────────────────────────────────────────────────────────────────────────

function signSession(agentId: string, issuedAt: number): string {
  const payload = `${agentId}:${issuedAt}`;
  return createHmac('sha256', SECRET_KEY).update(payload).digest('hex');
}

function verifySession(agentId: string, issuedAt: number, token: string): boolean {
  const expected = signSession(agentId, issuedAt);
  if (expected.length !== 64 || token.length !== 64) return false;
  return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(token, 'hex'));
}

/**
 * Sign an individual EventBus call. Called by the agent before each publish/subscribe.
 * The server independently recomputes the signature from its stored callSigningKey.
 *
 * @param callSigningKey - The per-agent secret from AgentToken.callSigningKey
 * @param agentId        - Agent making the call
 * @param channel        - EventBus channel being accessed
 * @param nonce          - Fresh random nonce (randomBytes(8).toString('hex'))
 * @param ts             - Current timestamp in ms (Date.now())
 */
export function signCall(
  callSigningKey: string,
  agentId: string,
  channel: string,
  nonce: string,
  ts: number,
): string {
  const payload = `${agentId}:${channel}:${nonce}:${ts}`;
  return createHmac('sha256', callSigningKey).update(payload).digest('hex');
}

function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== 64 || b.length !== 64) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

// ─────────────────────────────────────────────────────────────────────────────
// Wildcard channel matching
// ─────────────────────────────────────────────────────────────────────────────

function channelMatches(pattern: string, channel: string): boolean {
  if (pattern === '*') return true;
  if (!pattern.includes('*')) return pattern === channel;
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`).test(channel);
}

function isChannelAllowed(allowedPatterns: string[], channel: string): boolean {
  return allowedPatterns.some((p) => channelMatches(p, channel));
}

// ─────────────────────────────────────────────────────────────────────────────
// Core validation — shared by canPublish and canSubscribe
// ─────────────────────────────────────────────────────────────────────────────

interface CallValidationResult {
  allowed: boolean;
  stored?: AgentToken;
  reason?: string;
}

function validateCall(
  agentId: string,
  sig: string,
  channel: string,
  nonce: string,
  ts: number,
  action: 'publish' | 'subscribe',
): CallValidationResult {
  const stored = tokenRegistry.get(agentId);

  if (!stored) {
    AuditLogger.log({ agentId, event: 'auth.token_rejected', metadata: { reason: 'not_registered', action } });
    return { allowed: false, reason: 'Agent not registered' };
  }

  if (stored.revoked) {
    AuditLogger.log({ agentId, event: 'auth.token_rejected', metadata: { reason: 'revoked', action } });
    return { allowed: false, reason: 'Token revoked' };
  }

  if (stored.expiresAt > 0 && Date.now() > stored.expiresAt) {
    AuditLogger.log({ agentId, event: 'auth.token_rejected', metadata: { reason: 'expired', action } });
    return { allowed: false, reason: 'Token expired' };
  }

  // Reject calls with timestamps too far from server clock
  const skew = Math.abs(Date.now() - ts);
  if (skew > MAX_CLOCK_SKEW_MS) {
    AuditLogger.log({ agentId, event: 'auth.token_rejected', metadata: { reason: 'clock_skew', skewMs: skew, action } });
    return { allowed: false, reason: 'Call timestamp outside acceptable window' };
  }

  // Verify per-call signature using server-stored callSigningKey (never client-supplied)
  const expectedSig = signCall(stored.callSigningKey, agentId, channel, nonce, ts);
  if (!constantTimeHexEqual(sig, expectedSig)) {
    AuditLogger.log({ agentId, event: 'auth.token_rejected', metadata: { reason: 'invalid_call_signature', action } });
    return { allowed: false, reason: 'Invalid call signature' };
  }

  // Deduplicate nonces — exact replay is rejected
  if (!consumeNonce(nonce)) {
    AuditLogger.log({ agentId, event: 'security.injection_detected', metadata: { type: 'token_replay', agentId, channel, action } });
    return { allowed: false, reason: 'Nonce already used (replay attack)' };
  }

  return { allowed: true, stored };
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentAuthManager
// ─────────────────────────────────────────────────────────────────────────────

export const AgentAuthManager = {
  /**
   * Issue a session token + per-agent call signing key at registration.
   * Throws if the agent has been persistently revoked.
   */
  issueToken(
    agentId: string,
    riskConfig: AgentRiskConfig,
    ttlMs: number = 24 * 60 * 60 * 1000,
  ): AgentToken {
    if (persistentlyRevokedAgents.has(agentId)) {
      throw new Error(
        `[AgentAuth] Agent "${agentId}" has been persistently revoked and cannot be re-registered. ` +
        `Clear ${REVOCATION_LOG_PATH} after a security review to re-enable.`
      );
    }

    const issuedAt = Date.now();
    const token = signSession(agentId, issuedAt);
    const callSigningKey = randomBytes(32).toString('hex');
    const expiresAt = ttlMs > 0 ? issuedAt + ttlMs : 0;

    const agentToken: AgentToken = {
      token,
      callSigningKey,
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
   * Check whether an agent may publish to a channel.
   * Validates the per-call HMAC signature and deduplicates the nonce.
   *
   * @param agentId - Agent requesting to publish
   * @param sig     - Per-call HMAC: signCall(token.callSigningKey, agentId, channel, nonce, ts)
   * @param channel - EventBus channel to publish to
   * @param nonce   - Fresh random string, e.g. randomBytes(8).toString('hex')
   * @param ts      - Call timestamp in ms (Date.now())
   */
  canPublish(agentId: string, sig: string, channel: string, nonce: string, ts: number): boolean {
    const result = validateCall(agentId, sig, channel, nonce, ts, 'publish');

    if (!result.allowed) {
      AuditLogger.log({
        agentId,
        event: 'eventbus.publish_blocked',
        metadata: { channel, reason: result.reason },
      });
      return false;
    }

    const channelAllowed = isChannelAllowed(result.stored!.allowedPublishChannels, channel);
    if (!channelAllowed) {
      AuditLogger.log({
        agentId,
        event: 'agent.permission_denied',
        metadata: { action: 'publish', channel, allowedChannels: result.stored!.allowedPublishChannels },
      });
    }
    return channelAllowed;
  },

  /**
   * Check whether an agent may subscribe to a channel.
   * Same signature verification as canPublish.
   */
  canSubscribe(agentId: string, sig: string, channel: string, nonce: string, ts: number): boolean {
    const result = validateCall(agentId, sig, channel, nonce, ts, 'subscribe');

    if (!result.allowed) return false;

    const channelAllowed = isChannelAllowed(result.stored!.allowedSubscribeChannels, channel);
    if (!channelAllowed) {
      AuditLogger.log({
        agentId,
        event: 'agent.permission_denied',
        metadata: { action: 'subscribe', channel, allowedChannels: result.stored!.allowedSubscribeChannels },
      });
    }
    return channelAllowed;
  },

  /**
   * Revoke a token immediately. Persists the revocation to disk so it
   * survives restarts — the agent cannot re-register after revocation.
   */
  revokeToken(agentId: string, revokedBy: string = 'system'): boolean {
    const stored = tokenRegistry.get(agentId);
    if (!stored) return false;

    stored.revoked = true;
    persistentlyRevokedAgents.add(agentId);
    persistRevocation(agentId, revokedBy);

    AuditLogger.log({
      agentId,
      event: 'auth.token_revoked',
      metadata: { revokedBy },
    });

    return true;
  },

  /**
   * Validate the session-level token (identity check only, not a call credential).
   * Use canPublish/canSubscribe for per-call authorization.
   */
  validateToken(agentId: string, tokenStr: string): TokenValidationResult {
    const stored = tokenRegistry.get(agentId);

    if (!stored) {
      return { valid: false, reason: 'Agent not registered' };
    }
    if (stored.revoked) {
      return { valid: false, reason: 'Token revoked' };
    }
    if (stored.expiresAt > 0 && Date.now() > stored.expiresAt) {
      return { valid: false, reason: 'Token expired' };
    }
    if (!verifySession(agentId, stored.issuedAt, tokenStr)) {
      return { valid: false, reason: 'Invalid token signature' };
    }

    return { valid: true, token: stored };
  },

  /** Revoke all tokens and re-issue (use after key compromise) */
  rotateAll(riskConfigs: Map<string, AgentRiskConfig>): void {
    for (const [agentId, config] of riskConfigs) {
      const stored = tokenRegistry.get(agentId);
      if (stored) stored.revoked = true;
      this.issueToken(agentId, config);
    }
  },

  /** List token metadata for admin/audit use. Never includes secrets. */
  listTokens(): Array<Omit<AgentToken, 'token' | 'callSigningKey'>> {
    return Array.from(tokenRegistry.values()).map(
      ({ token: _t, callSigningKey: _k, ...rest }) => rest
    );
  },
};

// Purge expired tokens and stale nonces every 5 minutes to prevent unbounded memory growth
setInterval(() => {
  const now = Date.now();
  for (const [agentId, token] of tokenRegistry) {
    if (token.expiresAt > 0 && now > token.expiresAt) tokenRegistry.delete(agentId);
  }
  purgeExpiredNonces();
}, 5 * 60 * 1000).unref();
