/**
 * Crash Flush Handlers & Startup Finalization
 *
 * NIST AI RMF 1.0 — MANAGE (MG-2.2), MEASURE (MS-2.6)
 *
 * Import this module once at the process entry point (before any agents start).
 * It registers handlers for uncaughtException and unhandledRejection to ensure
 * the audit log and decision ledger reach disk even when the process crashes
 * unexpectedly. Without this, pending async writes are lost on crash.
 *
 * Call finalizeStartup() once all agents are registered to engage all security
 * locks atomically: token issuance, model allowlist, secrets provider, and
 * per-supervisor policy store (via SupervisorAgent.start()).
 *
 * Usage (in your main entry point):
 *   import '../security/shutdown'; // side-effect import — registers handlers
 *   // ... register all agents ...
 *   finalizeStartup();             // lock everything
 */

import { flushAuditLog } from './audit-log';
import { flushDecisionLedger } from './decision-ledger';
import { AgentAuthManager } from './agent-auth';
import { ModelGuard } from './model-guard';
import { lockSecretsProvider, sealSecrets } from './secrets-provider';
import { AuditLogger } from './audit-log';

/**
 * Engage all startup security locks atomically.
 *
 * STRIDE I-2  — lockSecretsProvider(): runtime provider swaps are rejected
 * STRIDE E-2  — AgentAuthManager.lockIssuance(): no new tokens minted at runtime
 * STRIDE E-4  — ModelGuard.lockModels(): allowlist is frozen after startup
 *
 * Call once, after all startup agents have received tokens and all approved
 * models have been registered, but before any agent begins processing.
 * SupervisorAgent.start() handles STRIDE E-3 (policy store lock) independently.
 */
export function finalizeStartup(): void {
  // Seal credentials out of process.env BEFORE locking the provider
  // (prod-gated). After this, in-process code/plugins cannot read raw keys
  // via process.env — only the gated getSecret()/requireSecret() resolve them.
  const seal = sealSecrets();
  lockSecretsProvider();
  AgentAuthManager.lockIssuance();
  ModelGuard.lockModels();
  AuditLogger.log({
    agentId: 'system',
    event: 'agent.started',
    metadata: {
      action: 'startup_finalized',
      locks: ['secrets_provider', 'token_issuance', 'model_allowlist'],
      secretsSealed: seal.enabled ? seal.sealed.length : 0,
    },
  });
}

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
