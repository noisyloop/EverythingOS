/**
 * Append-Only Tamper-Evident Audit Logger
 *
 * NIST AI RMF 1.0 — MANAGE Function (MG-2.2), MEASURE Function (MS-2.6)
 * NIST AI 600-1 — Accountability, Explainability
 *
 * Produces a hash-chained log where each entry includes the SHA-256 hash
 * of the previous entry. This means tampering with any entry invalidates
 * all subsequent hashes and is detectable via verifyChain().
 *
 * Usage:
 *   import { AuditLogger } from '../security/audit-log';
 *
 *   AuditLogger.log({
 *     agentId: 'my-agent',
 *     action: 'llm.call',
 *     inputHash: hash,
 *     outputHash: hash,
 *     metadata: { channel: 'discord:message' }
 *   });
 */

import { createHash } from 'crypto';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'fs';
import { resolve } from 'path';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type AuditEventType =
  | 'agent.registered'
  | 'agent.started'
  | 'agent.stopped'
  | 'agent.error'
  | 'auth.token_issued'
  | 'auth.token_validated'
  | 'auth.token_rejected'
  | 'auth.token_revoked'
  | 'eventbus.publish'
  | 'eventbus.publish_blocked'
  | 'eventbus.subscribe'
  | 'llm.call'
  | 'llm.response'
  | 'llm.rate_limited'
  | 'security.injection_detected'
  | 'security.pii_scrubbed'
  | 'security.input_truncated'
  | 'content_filter.blocked'
  | 'content_filter.flagged'
  | 'approval.requested'
  | 'approval.granted'
  | 'approval.denied'
  | 'approval.timeout'
  | 'agent.permission_denied'
  | 'safety.violation'
  | 'safety.emergency_stop'
  | 'incident.detected';

export interface AuditEntry {
  /** Monotonically increasing sequence number */
  seq: number;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Unix timestamp in ms for precise ordering */
  timestampMs: number;
  /** Agent that generated this event */
  agentId: string;
  /** Event category */
  event: AuditEventType;
  /** SHA-256 hash of input content (never log raw content) */
  inputHash?: string;
  /** SHA-256 hash of output content */
  outputHash?: string;
  /** Additional structured metadata */
  metadata?: Record<string, unknown>;
  /** Hash of the previous audit entry — chain link */
  previousHash: string;
  /** Hash of this entry (computed after all other fields are set) */
  entryHash: string;
}

export interface AuditLogInput {
  agentId: string;
  event: AuditEventType;
  inputHash?: string;
  outputHash?: string;
  metadata?: Record<string, unknown>;
}

export interface ChainVerificationResult {
  valid: boolean;
  totalEntries: number;
  brokenAt?: number;
  reason?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// In-Memory Store (ring buffer for runtime queries)
// ─────────────────────────────────────────────────────────────────────────────

const IN_MEMORY_LIMIT = 10_000;
const auditLog: AuditEntry[] = [];
let sequenceCounter = 0;
let lastHash = 'GENESIS';

const LOG_FILE_PATH = resolve(process.env.AUDIT_LOG_PATH ?? './everythingos-audit.jsonl');

// ─────────────────────────────────────────────────────────────────────────────
// Core Logger
// ─────────────────────────────────────────────────────────────────────────────

function computeEntryHash(entry: Omit<AuditEntry, 'entryHash'>): string {
  const content = JSON.stringify(entry);
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Hash a string value for inclusion in the audit log.
 * Use this to log input/output content without storing the raw content.
 */
export function hashContent(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

export const AuditLogger = {
  /**
   * Append an entry to the audit log.
   * This is the primary logging function — all security-relevant events
   * should flow through here.
   */
  log(input: AuditLogInput): AuditEntry {
    const now = new Date();
    const partial: Omit<AuditEntry, 'entryHash'> = {
      seq: ++sequenceCounter,
      timestamp: now.toISOString(),
      timestampMs: now.getTime(),
      agentId: input.agentId,
      event: input.event,
      inputHash: input.inputHash,
      outputHash: input.outputHash,
      metadata: input.metadata,
      previousHash: lastHash,
    };

    const entryHash = computeEntryHash(partial);
    const entry: AuditEntry = { ...partial, entryHash };

    // Update chain
    lastHash = entryHash;

    // In-memory ring buffer
    if (auditLog.length >= IN_MEMORY_LIMIT) {
      auditLog.shift();
    }
    auditLog.push(entry);

    // Append to file (append-only — never overwrite)
    try {
      appendFileSync(LOG_FILE_PATH, JSON.stringify(entry) + '\n', { encoding: 'utf8' });
    } catch (err) {
      // Log to stderr but don't throw — audit log failure must not crash the system
      console.error('[AuditLogger] Failed to write to log file:', err);
    }

    return entry;
  },

  /**
   * Query the in-memory log with optional filters.
   * For larger historical queries, read from the log file directly.
   */
  query(filter: {
    agentId?: string;
    event?: AuditEventType;
    since?: number;
    until?: number;
    limit?: number;
  }): AuditEntry[] {
    let results = [...auditLog];

    if (filter.agentId) {
      results = results.filter((e) => e.agentId === filter.agentId);
    }
    if (filter.event) {
      results = results.filter((e) => e.event === filter.event);
    }
    if (filter.since) {
      results = results.filter((e) => e.timestampMs >= filter.since!);
    }
    if (filter.until) {
      results = results.filter((e) => e.timestampMs <= filter.until!);
    }
    if (filter.limit) {
      results = results.slice(-filter.limit);
    }

    return results;
  },

  /**
   * Verify the integrity of the on-disk audit log.
   * Returns true if the hash chain is unbroken.
   * A broken chain indicates tampering or corruption.
   */
  verifyChain(filePath?: string): ChainVerificationResult {
    const path = filePath ?? LOG_FILE_PATH;

    if (!existsSync(path)) {
      return { valid: true, totalEntries: 0 };
    }

    const lines = readFileSync(path, 'utf8')
      .split('\n')
      .filter((l) => l.trim().length > 0);

    let previousHash = 'GENESIS';

    for (let i = 0; i < lines.length; i++) {
      let entry: AuditEntry;
      try {
        entry = JSON.parse(lines[i]) as AuditEntry;
      } catch {
        return {
          valid: false,
          totalEntries: lines.length,
          brokenAt: i,
          reason: `JSON parse error at line ${i + 1}`,
        };
      }

      // Verify previous hash link
      if (entry.previousHash !== previousHash) {
        return {
          valid: false,
          totalEntries: lines.length,
          brokenAt: i,
          reason: `Hash chain broken at entry ${i + 1} (seq: ${entry.seq}): previousHash mismatch`,
        };
      }

      // Verify entry hash
      const { entryHash, ...rest } = entry;
      const expectedHash = computeEntryHash(rest);
      if (expectedHash !== entryHash) {
        return {
          valid: false,
          totalEntries: lines.length,
          brokenAt: i,
          reason: `Entry hash mismatch at entry ${i + 1} (seq: ${entry.seq}): content was modified`,
        };
      }

      previousHash = entryHash;
    }

    return { valid: true, totalEntries: lines.length };
  },

  /**
   * Returns a summary of log statistics for monitoring dashboards.
   */
  stats(): {
    totalInMemory: number;
    lastSequence: number;
    securityEvents: number;
    injectionAttempts: number;
    blockedPublishes: number;
  } {
    return {
      totalInMemory: auditLog.length,
      lastSequence: sequenceCounter,
      securityEvents: auditLog.filter((e) =>
        e.event.startsWith('security.') ||
        e.event.startsWith('auth.') ||
        e.event === 'content_filter.blocked' ||
        e.event === 'agent.permission_denied'
      ).length,
      injectionAttempts: auditLog.filter((e) => e.event === 'security.injection_detected').length,
      blockedPublishes: auditLog.filter((e) => e.event === 'eventbus.publish_blocked').length,
    };
  },

  /**
   * Initialize the logger — loads the last hash from disk to continue the chain
   * across process restarts. Call this once at startup before any agents start.
   */
  initialize(): void {
    if (!existsSync(LOG_FILE_PATH)) {
      writeFileSync(LOG_FILE_PATH, '', { encoding: 'utf8' });
      lastHash = 'GENESIS';
      sequenceCounter = 0;
      return;
    }

    const content = readFileSync(LOG_FILE_PATH, 'utf8');
    const lines = content.split('\n').filter((l) => l.trim().length > 0);

    if (lines.length === 0) {
      lastHash = 'GENESIS';
      sequenceCounter = 0;
      return;
    }

    try {
      const lastEntry = JSON.parse(lines[lines.length - 1]) as AuditEntry;
      lastHash = lastEntry.entryHash;
      sequenceCounter = lastEntry.seq;
    } catch {
      console.error('[AuditLogger] Could not parse last log entry. Starting new chain.');
      lastHash = 'GENESIS';
      sequenceCounter = 0;
    }
  },
};

// Auto-initialize on import
AuditLogger.initialize();
