/**
 * Crash Flush Handlers — Flush audit and decision logs on unhandled errors
 *
 * NIST AI RMF 1.0 — MANAGE (MG-2.2), MEASURE (MS-2.6)
 *
 * Import this module once at the process entry point (before any agents start).
 * It registers handlers for uncaughtException and unhandledRejection to ensure
 * the audit log and decision ledger reach disk even when the process crashes
 * unexpectedly. Without this, pending async writes are lost on crash.
 *
 * Usage (in your main entry point):
 *   import '../security/shutdown'; // side-effect import — registers handlers
 */

import { flushAuditLog } from './audit-log';
import { flushDecisionLedger } from './decision-ledger';

async function emergencyFlush(reason: string, err?: unknown): Promise<void> {
  try {
    console.error(
      `[EverythingOS] ${reason} — flushing logs before exit`,
      err instanceof Error ? err.stack : String(err ?? '')
    );
    await Promise.allSettled([flushAuditLog(), flushDecisionLedger()]);
  } catch {
    // Best-effort only — never throw from a shutdown handler
  }
}

process.on('uncaughtException', async (err: Error) => {
  await emergencyFlush('uncaughtException', err);
  process.exit(1);
});

process.on('unhandledRejection', async (reason: unknown) => {
  await emergencyFlush('unhandledRejection', reason);
  process.exit(1);
});
