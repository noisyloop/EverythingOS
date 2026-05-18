/**
 * Append-Only Tamper-Evident Audit Logger
 *
 * NIST AI RMF 1.0 — MANAGE Function (MG-2.2), MEASURE Function (MS-2.6)
 * NIST AI 600-1 — Accountability, Explainability
 *
 * Produces a hash-chained log where each entry includes the SHA-256 hash
 * of the previous entry. Tampering with any entry invalidates all subsequent
 * hashes and is detectable via verifyChain().
 *
 * Disk writes are fully async (WriteStream) to prevent blocking the Node.js
 * event loop under audit load. Call flushAuditLog() before verifyChain() or
 * process exit to ensure all pending writes reach disk.
 */

import { createHash } from 'crypto';
import { createInterface } from 'readline';
import { createReadStream, createWriteStream, existsSync, ReadStream, readFileSync, WriteStream, writeFileSync } from 'fs';
import { resolve } from 'path';
import { scrubPII } from './sanitize';

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
  | 'incident.detected'
  | 'security.glasswally_rate_limited'
  | 'security.glasswally_line_buffer_overflow'
  | 'security.ioc_bundle_tampered';

export interface AuditEntry {
  seq: number;
  timestamp: string;
  timestampMs: number;
  agentId: string;
  event: AuditEventType;
  inputHash?: string;
  outputHash?: string;
  metadata?: Record<string, unknown>;
  previousHash: string;
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
// In-memory store (ring buffer for runtime queries)
// ─────────────────────────────────────────────────────────────────────────────

const IN_MEMORY_LIMIT = 10_000;
const auditLog: AuditEntry[] = [];
let sequenceCounter = 0;
let lastHash = 'GENESIS';

const LOG_FILE_PATH = resolve(process.env.AUDIT_LOG_PATH ?? './everythingos-audit.jsonl');

// ─────────────────────────────────────────────────────────────────────────────
// Async write stream — non-blocking disk I/O
// ─────────────────────────────────────────────────────────────────────────────

let logStream: WriteStream | null = null;

function getLogStream(): WriteStream {
  if (!logStream || logStream.destroyed) {
    logStream = createWriteStream(LOG_FILE_PATH, { flags: 'a', encoding: 'utf8' });
    logStream.on('error', (err) => {
      // Never throw from the audit stream error handler — log to stderr instead
      console.error('[AuditLogger] Write stream error:', err);
    });
  }
  return logStream;
}

/**
 * Flush all pending audit writes to disk.
 * Call before process exit or before running verifyChain() on a live system.
 */
export function flushAuditLog(): Promise<void> {
  return new Promise((res) => {
    if (!logStream || logStream.destroyed) {
      res();
      return;
    }
    logStream.end(() => {
      logStream = null;
      res();
    });
  });
}

// Flush on clean shutdown
process.once('exit', () => { if (logStream && !logStream.destroyed) logStream.end(); });
process.once('SIGINT', async () => { await flushAuditLog(); process.exit(0); });
process.once('SIGTERM', async () => { await flushAuditLog(); process.exit(0); });

// ─────────────────────────────────────────────────────────────────────────────
// Core logger
// ─────────────────────────────────────────────────────────────────────────────

function computeEntryHash(entry: Omit<AuditEntry, 'entryHash'>): string {
  return createHash('sha256').update(JSON.stringify(entry)).digest('hex');
}

export function hashContent(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

/** Recursively scrub PII from metadata string values before they reach the audit log (STRIDE I-3). */
function scrubMetadata(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string') {
      out[k] = scrubPII(v).scrubbed;
    } else if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      out[k] = scrubMetadata(v as Record<string, unknown>);
    } else {
      out[k] = v;
    }
  }
  return out;
}

export const AuditLogger = {
  /**
   * Append an entry to the audit log.
   * In-memory bookkeeping is synchronous; disk write is async (non-blocking).
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
      metadata: input.metadata ? scrubMetadata(input.metadata) : undefined,
      previousHash: lastHash,
    };

    const entryHash = computeEntryHash(partial);
    const entry: AuditEntry = { ...partial, entryHash };

    lastHash = entryHash;

    if (auditLog.length >= IN_MEMORY_LIMIT) {
      auditLog.shift();
    }
    auditLog.push(entry);

    // Non-blocking async disk write
    const stream = getLogStream();
    stream.write(JSON.stringify(entry) + '\n', (err) => {
      if (err) console.error('[AuditLogger] Failed to write audit entry seq=' + entry.seq + ':', err);
    });

    return entry;
  },

  query(filter: {
    agentId?: string;
    event?: AuditEventType;
    since?: number;
    until?: number;
    limit?: number;
  }): AuditEntry[] {
    let results = [...auditLog];
    if (filter.agentId) results = results.filter((e) => e.agentId === filter.agentId);
    if (filter.event)   results = results.filter((e) => e.event === filter.event);
    if (filter.since)   results = results.filter((e) => e.timestampMs >= filter.since!);
    if (filter.until)   results = results.filter((e) => e.timestampMs <= filter.until!);
    if (filter.limit)   results = results.slice(-filter.limit);
    return results;
  },

  /**
   * Verify the on-disk audit log's hash chain.
   * Streams the file line-by-line to avoid loading the full log into memory (STRIDE D-4).
   * Always call flushAuditLog() first on a live system to ensure all writes are flushed.
   */
  async verifyChain(filePath?: string): Promise<ChainVerificationResult> {
    const path = filePath ?? LOG_FILE_PATH;

    if (!existsSync(path)) {
      return { valid: true, totalEntries: 0 };
    }

    let previousHash = 'GENESIS';
    let totalEntries = 0;

    const rl = createInterface({
      input: createReadStream(path, { encoding: 'utf8' }) as ReadStream,
      crlfDelay: Infinity,
    });

    for await (const rawLine of rl) {
      const line = rawLine.trim();
      if (!line) continue;

      let entry: AuditEntry;
      try {
        entry = JSON.parse(line) as AuditEntry;
      } catch {
        return { valid: false, totalEntries, brokenAt: totalEntries, reason: `JSON parse error at line ${totalEntries + 1}` };
      }

      if (entry.previousHash !== previousHash) {
        return {
          valid: false,
          totalEntries,
          brokenAt: totalEntries,
          reason: `Hash chain broken at entry ${totalEntries + 1} (seq: ${entry.seq}): previousHash mismatch`,
        };
      }

      const { entryHash, ...rest } = entry;
      const expectedHash = computeEntryHash(rest);
      if (expectedHash !== entryHash) {
        return {
          valid: false,
          totalEntries,
          brokenAt: totalEntries,
          reason: `Entry hash mismatch at entry ${totalEntries + 1} (seq: ${entry.seq}): content was modified`,
        };
      }

      previousHash = entryHash;
      totalEntries++;
    }

    return { valid: true, totalEntries };
  },

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
   * Resume the hash chain from the last persisted entry.
   * Verifies chain integrity at startup — logs CRITICAL alert if tampered.
   * Call once at startup before any agents start.
   *
   * The sync part (state replay from last entry) runs immediately.
   * The async part (full chain verification) resolves when complete — await
   * the returned Promise if you need to confirm integrity before proceeding.
   */
  async initialize(): Promise<void> {
    // Close any open stream so subsequent writes go to the (re)created file,
    // not a stale file descriptor pointing to a deleted inode.
    if (logStream && !logStream.destroyed) {
      logStream.end();
      logStream = null;
    }

    if (!existsSync(LOG_FILE_PATH)) {
      writeFileSync(LOG_FILE_PATH, '', { encoding: 'utf8' });
      lastHash = 'GENESIS';
      sequenceCounter = 0;
      return;
    }

    // Replay state from the last line synchronously so log() works immediately
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

    // Full chain verification — streaming, non-blocking (STRIDE D-4)
    const verifyResult = await AuditLogger.verifyChain(LOG_FILE_PATH);
    if (!verifyResult.valid) {
      console.error(
        `[AuditLogger] CRITICAL: Audit log chain integrity check FAILED. ` +
        `Reason: ${verifyResult.reason}. The log may have been tampered with. ` +
        `Review ${LOG_FILE_PATH} before proceeding.`
      );
    }
  },
};

AuditLogger.initialize().catch((err) => {
  console.error('[AuditLogger] Initialization error:', err);
});
