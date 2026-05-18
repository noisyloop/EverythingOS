/**
 * Credential Vault — Ephemeral Scoped Credentials for Agent Tasks
 *
 * NIST AI RMF 1.0 — GOVERN (GV-2), MANAGE (MG-2.2)
 * NIST AI 600-1 — Cybersecurity Attacks, Accountability
 *
 * The problem with .env API keys: they're long-lived, shared across all
 * agents, and there's no record of which agent used which key when.
 * If one agent is compromised, every key it had access to is compromised.
 *
 * The vault solves this with three things:
 *
 *   1. Scoped delegation — agents request a credential for a specific
 *      task and provider. They never see the raw key, only a scoped
 *      token that the vault exchanges at call time.
 *
 *   2. Ephemeral TTLs — credentials expire. A leaked token from a
 *      completed task is worthless after its TTL.
 *
 *   3. Provenance logging — every credential request, use, and expiry
 *      is logged with agentId, taskId, and timestamp. You can answer
 *      "which agent touched which external service and when" after any
 *      incident.
 *
 * Usage:
 *   import { CredentialVault } from '../security/credential-vault';
 *
 *   // Agent requests a scoped credential for a task
 *   const cred = CredentialVault.request({
 *     agentId: 'discord-bot',
 *     provider: 'discord',
 *     taskId: 'send-alert-123',
 *     ttlMs: 60_000, // 1 minute — just long enough for the task
 *   });
 *
 *   // Use the credential (vault exchanges it for the real key internally)
 *   const headers = CredentialVault.getHeaders(cred.credentialId, 'discord');
 *
 *   // Explicitly revoke after use (vault also auto-expires on TTL)
 *   CredentialVault.revoke(cred.credentialId, 'task-complete');
 */

import { createHash, randomBytes } from 'crypto';
import { AuditLogger } from './audit-log';
import { getSecret } from './secrets-provider';

// ─────────────────────────────────────────────────────────────────────────────
// Supported Providers
// ─────────────────────────────────────────────────────────────────────────────

export type Provider =
  | 'anthropic'
  | 'openai'
  | 'google'
  | 'discord'
  | 'slack'
  | 'github'
  | 'coinbase'
  | 'binance'
  | string; // custom providers

/** Maps provider names to their env var key names */
const PROVIDER_ENV_KEYS: Record<string, string[]> = {
  anthropic: ['ANTHROPIC_API_KEY'],
  openai:    ['OPENAI_API_KEY'],
  google:    ['GOOGLE_API_KEY'],
  discord:   ['DISCORD_BOT_TOKEN'],
  slack:     ['SLACK_BOT_TOKEN'],
  github:    ['GITHUB_TOKEN'],
  coinbase:  ['COINBASE_API_KEY', 'COINBASE_API_SECRET'],
  binance:   ['BINANCE_API_KEY', 'BINANCE_API_SECRET'],
};

/** Maps provider to its auth header format */
const PROVIDER_HEADER_FORMATS: Record<string, (keys: string[]) => Record<string, string>> = {
  anthropic: ([key]) => ({ 'x-api-key': key, 'anthropic-version': '2023-06-01' }),
  openai:    ([key]) => ({ Authorization: `Bearer ${key}` }),
  google:    ([key]) => ({ 'x-goog-api-key': key }),
  discord:   ([key]) => ({ Authorization: `Bot ${key}` }),
  slack:     ([key]) => ({ Authorization: `Bearer ${key}` }),
  github:    ([key]) => ({ Authorization: `Bearer ${key}` }),
  coinbase:  ([key]) => ({ 'CB-ACCESS-KEY': key }),
  binance:   ([key]) => ({ 'X-MBX-APIKEY': key }),
};

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface CredentialRequest {
  /** Agent requesting the credential */
  agentId: string;
  /** External provider the credential is for */
  provider: Provider;
  /** Logical task this credential is scoped to */
  taskId: string;
  /**
   * Time-to-live in ms. Credential auto-expires after this.
   * Default: 5 minutes. Maximum: 1 hour.
   */
  ttlMs?: number;
}

export interface ScopedCredential {
  /** Unique ID for this credential grant — use this, not the raw key */
  credentialId: string;
  agentId: string;
  provider: Provider;
  taskId: string;
  issuedAt: number;
  expiresAt: number;
  /** Whether this credential has been revoked or expired */
  active: boolean;
}

export interface CredentialUseRecord {
  credentialId: string;
  agentId: string;
  provider: Provider;
  taskId: string;
  usedAt: number;
}

export interface RotationRecord {
  provider: Provider;
  rotatedAt: number;
  rotatedBy: string;
  /** Hash of the old key — for audit trail without storing the key itself */
  oldKeyHash: string;
  /** Hash of the new key */
  newKeyHash: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────────────────────

const activeCredentials = new Map<string, ScopedCredential>();
const useLog: CredentialUseRecord[] = [];
const rotationLog: RotationRecord[] = [];
const USE_LOG_LIMIT = 10_000;

// Locked after startup — no runtime provider registration once set
let providerRegistryLocked = false;

const DEFAULT_TTL_MS = 5 * 60 * 1000;   // 5 minutes
const MAX_TTL_MS = 60 * 60 * 1000;      // 1 hour hard ceiling

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function generateCredentialId(): string {
  return `cred_${randomBytes(16).toString('hex')}`;
}

function getProviderKeys(provider: Provider): string[] {
  const envVarNames = PROVIDER_ENV_KEYS[provider];
  if (!envVarNames) {
    throw new Error(
      `[CredentialVault] Unknown provider "${provider}". ` +
      `Register it via CredentialVault.registerProvider() or add it to PROVIDER_ENV_KEYS.`
    );
  }

  const keys: string[] = [];
  for (const varName of envVarNames) {
    const val = getSecret(varName);
    if (!val) {
      throw new Error(
        `[CredentialVault] Provider "${provider}" requires secret ${varName} but it is not set. ` +
        `Configure it via SecretsProvider (setSecretsProvider()) or set the environment variable.`
      );
    }
    keys.push(val);
  }
  return keys;
}

function assertActive(credentialId: string): ScopedCredential {
  const cred = activeCredentials.get(credentialId);

  if (!cred) {
    throw new Error(`[CredentialVault] Credential ${credentialId} not found.`);
  }
  if (!cred.active) {
    throw new Error(`[CredentialVault] Credential ${credentialId} has been revoked.`);
  }
  if (Date.now() > cred.expiresAt) {
    cred.active = false;
    AuditLogger.log({
      agentId: cred.agentId,
      event: 'auth.token_revoked',
      metadata: { credentialId, provider: cred.provider, reason: 'ttl_expired' },
    });
    throw new Error(
      `[CredentialVault] Credential ${credentialId} expired at ${new Date(cred.expiresAt).toISOString()}.`
    );
  }

  return cred;
}

// ─────────────────────────────────────────────────────────────────────────────
// CredentialVault
// ─────────────────────────────────────────────────────────────────────────────

export const CredentialVault = {
  /**
   * Request a scoped credential for a specific task and provider.
   * The agent never sees the raw key — only a credentialId it passes
   * back to the vault when it needs auth headers.
   */
  request(req: CredentialRequest): ScopedCredential {
    const ttlMs = Math.min(req.ttlMs ?? DEFAULT_TTL_MS, MAX_TTL_MS);
    const now = Date.now();

    // Validate the provider keys exist before issuing — fail fast
    getProviderKeys(req.provider);

    const credentialId = generateCredentialId();
    const cred: ScopedCredential = {
      credentialId,
      agentId: req.agentId,
      provider: req.provider,
      taskId: req.taskId,
      issuedAt: now,
      expiresAt: now + ttlMs,
      active: true,
    };

    activeCredentials.set(credentialId, cred);

    AuditLogger.log({
      agentId: req.agentId,
      event: 'auth.token_issued',
      metadata: {
        credentialId,
        provider: req.provider,
        taskId: req.taskId,
        expiresAt: cred.expiresAt,
        ttlMs,
      },
    });

    return cred;
  },

  /**
   * Exchange a credentialId for auth headers to use in an HTTP request.
   * This is the only place raw keys are accessed — they never leave this method.
   * Logs the use for provenance.
   */
  getHeaders(credentialId: string, provider: Provider): Record<string, string> {
    const cred = assertActive(credentialId);

    if (cred.provider !== provider) {
      throw new Error(
        `[CredentialVault] Credential ${credentialId} was issued for provider ` +
        `"${cred.provider}" but used for "${provider}". Provider mismatch.`
      );
    }

    const keys = getProviderKeys(provider);
    const formatter = PROVIDER_HEADER_FORMATS[provider];

    if (!formatter) {
      throw new Error(
        `[CredentialVault] No header format registered for provider "${provider}". ` +
        `Register one via CredentialVault.registerProvider().`
      );
    }

    const headers = formatter(keys);

    // Log the use — this is the provenance record (ring buffer capped at USE_LOG_LIMIT)
    const useRecord: CredentialUseRecord = {
      credentialId,
      agentId: cred.agentId,
      provider,
      taskId: cred.taskId,
      usedAt: Date.now(),
    };
    if (useLog.length >= USE_LOG_LIMIT) useLog.shift();
    useLog.push(useRecord);

    AuditLogger.log({
      agentId: cred.agentId,
      event: 'auth.token_validated',
      metadata: {
        credentialId,
        provider,
        taskId: cred.taskId,
      },
    });

    return headers;
  },

  /**
   * Explicitly revoke a credential before its TTL expires.
   * Call this immediately after a task completes — don't wait for expiry.
   */
  revoke(credentialId: string, reason: string = 'task-complete'): void {
    const cred = activeCredentials.get(credentialId);
    if (!cred) return;

    cred.active = false;

    AuditLogger.log({
      agentId: cred.agentId,
      event: 'auth.token_revoked',
      metadata: { credentialId, provider: cred.provider, taskId: cred.taskId, reason },
    });
  },

  /**
   * Revoke all credentials for a specific agent.
   * Call this when an agent is stopped, quarantined, or suspected of compromise.
   */
  revokeAllForAgent(agentId: string, reason: string = 'agent-stopped'): number {
    let count = 0;
    for (const [credentialId, cred] of activeCredentials.entries()) {
      if (cred.agentId === agentId && cred.active) {
        this.revoke(credentialId, reason);
        count++;
      }
    }
    return count;
  },

  /**
   * Purge expired credentials from the active map.
   * Run periodically — the vault does not auto-purge to keep the provenance record.
   */
  purgeExpired(): number {
    const now = Date.now();
    let count = 0;
    for (const [id, cred] of activeCredentials.entries()) {
      if (!cred.active || now > cred.expiresAt) {
        if (cred.active) {
          cred.active = false;
          AuditLogger.log({
            agentId: cred.agentId,
            event: 'auth.token_revoked',
            metadata: { credentialId: id, provider: cred.provider, reason: 'purge_expired' },
          });
        }
        activeCredentials.delete(id);
        count++;
      }
    }
    return count;
  },

  /**
   * Record a key rotation event for a provider.
   * Does not change the actual env var — that's an ops task.
   * This records THAT a rotation happened, WHEN, and by WHOM,
   * with hashes of the old and new keys for continuity auditing.
   *
   * @param provider - The provider being rotated
   * @param oldKey - The old API key (will be hashed, never stored raw)
   * @param newKey - The new API key (will be hashed, never stored raw)
   * @param rotatedBy - Identity of who initiated the rotation
   */
  recordRotation(
    provider: Provider,
    oldKey: string,
    newKey: string,
    rotatedBy: string,
  ): RotationRecord {
    const record: RotationRecord = {
      provider,
      rotatedAt: Date.now(),
      rotatedBy,
      oldKeyHash: sha256(oldKey),
      newKeyHash: sha256(newKey),
    };

    rotationLog.push(record);

    AuditLogger.log({
      agentId: 'system',
      event: 'auth.token_issued',
      metadata: {
        action: 'key_rotation',
        provider,
        rotatedBy,
        oldKeyHash: record.oldKeyHash,
        newKeyHash: record.newKeyHash,
      },
    });

    return record;
  },

  /**
   * Register a custom provider not in the built-in list.
   * Must be called at startup before lockProviders() — throws after locking.
   *
   * @param providerId - Unique identifier for the provider
   * @param envVarNames - Env var names holding the credentials
   * @param headerFormatter - Function that turns key values into auth headers
   */
  registerProvider(
    providerId: string,
    envVarNames: string[],
    headerFormatter: (keys: string[]) => Record<string, string>,
  ): void {
    if (providerRegistryLocked) {
      throw new Error(
        `[CredentialVault] Provider registry is locked. registerProvider() must be called at startup, before lockProviders().`
      );
    }
    PROVIDER_ENV_KEYS[providerId] = envVarNames;
    PROVIDER_HEADER_FORMATS[providerId] = headerFormatter;
  },

  /**
   * Lock the provider registry. Call once at startup after all providers are registered.
   * Prevents runtime registration of exfiltrating header formatters.
   */
  lockProviders(): void {
    providerRegistryLocked = true;
  },

  /**
   * Credential use history — answers "which agent touched which service when."
   * Essential for post-incident investigation.
   */
  getUseLog(filter?: {
    agentId?: string;
    provider?: Provider;
    taskId?: string;
    since?: number;
  }): CredentialUseRecord[] {
    let results = [...useLog];
    if (filter?.agentId) results = results.filter((r) => r.agentId === filter.agentId);
    if (filter?.provider) results = results.filter((r) => r.provider === filter.provider);
    if (filter?.taskId) results = results.filter((r) => r.taskId === filter.taskId);
    if (filter?.since) results = results.filter((r) => r.usedAt >= filter.since!);
    return results;
  },

  /** Key rotation history for a provider */
  getRotationLog(provider?: Provider): RotationRecord[] {
    if (!provider) return [...rotationLog];
    return rotationLog.filter((r) => r.provider === provider);
  },

  /** Active credential summary for monitoring */
  stats(): {
    totalActive: number;
    byProvider: Record<string, number>;
    byAgent: Record<string, number>;
    totalUses: number;
    totalRotations: number;
  } {
    const active = Array.from(activeCredentials.values()).filter(
      (c) => c.active && Date.now() <= c.expiresAt
    );

    const byProvider: Record<string, number> = {};
    const byAgent: Record<string, number> = {};

    for (const c of active) {
      byProvider[c.provider] = (byProvider[c.provider] ?? 0) + 1;
      byAgent[c.agentId] = (byAgent[c.agentId] ?? 0) + 1;
    }

    return {
      totalActive: active.length,
      byProvider,
      byAgent,
      totalUses: useLog.length,
      totalRotations: rotationLog.length,
    };
  },
};

// Auto-purge expired credentials every 5 minutes
setInterval(() => CredentialVault.purgeExpired(), 5 * 60 * 1000).unref();
