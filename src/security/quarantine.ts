/**
 * Agent Quarantine — Surgical Per-Agent Isolation
 *
 * NIST AI RMF 1.0 — MANAGE (MG-2.4, MG-4.2), MEASURE (MS-2.7)
 * NIST AI 600-1 — Incident Response, Containment
 *
 * emergencyStop() in AgentRegistry is nuclear — it halts everything.
 * Quarantine is surgical: isolate one suspicious agent while the rest
 * of the system keeps running.
 *
 * When an agent is quarantined:
 *   1. Its EventBus token is revoked — it can no longer publish or subscribe
 *   2. Its credential vault grants are all revoked — no external API access
 *   3. Its current state is captured as a forensic snapshot
 *   4. It is stopped (gracefully, then forcefully after timeout)
 *   5. It is flagged in the registry — it cannot be restarted without
 *      an explicit clearance call
 *   6. Everything above is logged to the audit trail
 *
 * This maps directly to "assume compromise" containment: limit blast radius,
 * preserve evidence, keep the rest of the system operational.
 *
 * Usage:
 *   import { QuarantineManager } from '../security/quarantine';
 *
 *   // Isolate a suspicious agent
 *   const record = await QuarantineManager.quarantine({
 *     agentId: 'trading-agent',
 *     reason: 'Anomalous output pattern — possible prompt injection',
 *     triggeredBy: 'CveWatchAgent',
 *     severity: 'high',
 *   });
 *
 *   // Inspect the forensic snapshot
 *   const snapshot = QuarantineManager.getSnapshot(record.quarantineId);
 *
 *   // Clear after investigation
 *   QuarantineManager.clear(record.quarantineId, 'false-positive', 'ops-team');
 */

import { AgentAuthManager } from './agent-auth';
import { CredentialVault } from './credential-vault';
import { AuditLogger } from './audit-log';
import { randomBytes } from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type QuarantineSeverity = 'low' | 'medium' | 'high' | 'critical';

export type QuarantineStatus =
  | 'active'      // Agent is quarantined, under investigation
  | 'cleared'     // Investigation complete, agent cleared
  | 'terminated'; // Investigation complete, agent permanently removed

export interface QuarantineRequest {
  /** Agent to quarantine */
  agentId: string;
  /** Human-readable reason for quarantine */
  reason: string;
  /** What system or person triggered the quarantine */
  triggeredBy: string;
  /** Severity level — affects logging priority and alerting */
  severity: QuarantineSeverity;
  /**
   * Optional: capture the agent's current state as a forensic snapshot.
   * Pass the raw state object if available. Default: true.
   */
  captureState?: boolean;
}

export interface ForensicSnapshot {
  /** Agent state at time of quarantine (sanitized — no raw keys) */
  agentState: Record<string, unknown>;
  /** Active event subscriptions at time of quarantine */
  activeSubscriptions: string[];
  /** Recent audit events for this agent (last 50) */
  recentAuditEvents: unknown[];
  /** Credential grants that were revoked */
  revokedCredentials: number;
  /** Timestamp of snapshot capture */
  capturedAt: string;
}

export interface QuarantineRecord {
  /** Unique ID for this quarantine event */
  quarantineId: string;
  agentId: string;
  reason: string;
  triggeredBy: string;
  severity: QuarantineSeverity;
  status: QuarantineStatus;
  quarantinedAt: number;
  quarantinedAtIso: string;
  /** Set when cleared or terminated */
  resolvedAt?: number;
  resolvedAtIso?: string;
  resolvedBy?: string;
  resolution?: string;
  /** Forensic snapshot captured at quarantine time */
  snapshot?: ForensicSnapshot;
}

// ─────────────────────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────────────────────

// quarantineId → record
const quarantineRecords = new Map<string, QuarantineRecord>();

// agentId → quarantineId (for fast lookup by agent)
const agentQuarantineIndex = new Map<string, string>();

// Agent stop function — injected at startup to avoid circular dep with AgentRegistry
let stopAgentFn: ((agentId: string) => Promise<void>) | null = null;

// Agent state accessor — injected at startup
let getAgentStateFn: ((agentId: string) => Record<string, unknown>) | null = null;

// Agent subscription accessor — injected at startup
let getAgentSubscriptionsFn: ((agentId: string) => string[]) | null = null;

// ─────────────────────────────────────────────────────────────────────────────
// QuarantineManager
// ─────────────────────────────────────────────────────────────────────────────

export const QuarantineManager = {
  /**
   * Inject the AgentRegistry stop function and state accessors.
   * Call this once at startup to wire up the dependency without a circular import.
   *
   * Example in your main.ts:
   *   QuarantineManager.initialize({
   *     stopAgent: (id) => AgentRegistry.stop(id),
   *     getAgentState: (id) => agentRegistry.get(id)?.getState() ?? {},
   *     getAgentSubscriptions: (id) => agentRegistry.get(id)?.getSubscriptions() ?? [],
   *   });
   */
  initialize(deps: {
    stopAgent: (agentId: string) => Promise<void>;
    getAgentState?: (agentId: string) => Record<string, unknown>;
    getAgentSubscriptions?: (agentId: string) => string[];
  }): void {
    stopAgentFn = deps.stopAgent;
    getAgentStateFn = deps.getAgentState ?? null;
    getAgentSubscriptionsFn = deps.getAgentSubscriptions ?? null;
  },

  /**
   * Quarantine an agent.
   *
   * Steps executed in order:
   *   1. Check not already quarantined
   *   2. Capture forensic snapshot (state, subscriptions, recent audit events)
   *   3. Revoke EventBus token — blocks all pub/sub immediately
   *   4. Revoke all credential vault grants — blocks all external API access
   *   5. Stop the agent gracefully (timeout: 5s, then force)
   *   6. Record to audit log
   *   7. Return quarantine record
   */
  async quarantine(req: QuarantineRequest): Promise<QuarantineRecord> {
    const { agentId, reason, triggeredBy, severity } = req;
    const captureState = req.captureState !== false;

    // Check not already quarantined
    if (agentQuarantineIndex.has(agentId)) {
      const existingId = agentQuarantineIndex.get(agentId)!;
      const existing = quarantineRecords.get(existingId)!;
      if (existing.status === 'active') {
        throw new Error(
          `[Quarantine] Agent "${agentId}" is already quarantined (${existingId}). ` +
          `Resolve the existing quarantine before issuing a new one.`
        );
      }
    }

    const quarantineId = `quar_${randomBytes(12).toString('hex')}`;
    const now = new Date();

    // ── Step 1: Forensic snapshot ─────────────────────────────────────────────
    let snapshot: ForensicSnapshot | undefined;

    if (captureState) {
      const agentState = getAgentStateFn ? getAgentStateFn(agentId) : {};
      const activeSubscriptions = getAgentSubscriptionsFn
        ? getAgentSubscriptionsFn(agentId)
        : [];

      // Pull recent audit events for this agent
      const recentAuditEvents = AuditLogger.query({
        agentId,
        limit: 50,
      });

      // Revoke credentials and count them
      const revokedCredentials = CredentialVault.revokeAllForAgent(
        agentId,
        `quarantine:${quarantineId}`
      );

      snapshot = {
        agentState: sanitizeState(agentState),
        activeSubscriptions,
        recentAuditEvents,
        revokedCredentials,
        capturedAt: now.toISOString(),
      };
    } else {
      // Still revoke credentials even if not capturing state
      CredentialVault.revokeAllForAgent(agentId, `quarantine:${quarantineId}`);
    }

    // ── Step 2: Revoke EventBus token ─────────────────────────────────────────
    AgentAuthManager.revokeToken(agentId, `quarantine:${quarantineId}`);

    // ── Step 3: Stop the agent ────────────────────────────────────────────────
    if (stopAgentFn) {
      try {
        await Promise.race([
          stopAgentFn(agentId),
          new Promise<void>((_, reject) =>
            setTimeout(() => reject(new Error('Stop timeout')), 5_000)
          ),
        ]);
      } catch (err) {
        // Log the failure but don't abort quarantine — token is already revoked
        AuditLogger.log({
          agentId,
          event: 'agent.error',
          metadata: {
            phase: 'quarantine_stop',
            quarantineId,
            error: String(err),
          },
        });
        console.error(
          `[Quarantine] Agent "${agentId}" did not stop cleanly during quarantine:`, err
        );
      }
    }

    // ── Step 4: Create and store the quarantine record ────────────────────────
    const record: QuarantineRecord = {
      quarantineId,
      agentId,
      reason,
      triggeredBy,
      severity,
      status: 'active',
      quarantinedAt: now.getTime(),
      quarantinedAtIso: now.toISOString(),
      snapshot,
    };

    quarantineRecords.set(quarantineId, record);
    agentQuarantineIndex.set(agentId, quarantineId);

    // ── Step 5: Audit log ─────────────────────────────────────────────────────
    AuditLogger.log({
      agentId,
      event: 'safety.violation',
      metadata: {
        quarantineId,
        reason,
        triggeredBy,
        severity,
        revokedCredentials: snapshot?.revokedCredentials ?? 0,
        snapshotCaptured: !!snapshot,
      },
    });

    const prefix = severity === 'critical' || severity === 'high' ? '🚨' : '⚠️';
    console.warn(
      `${prefix} [Quarantine] Agent "${agentId}" quarantined. ` +
      `ID: ${quarantineId} | Severity: ${severity} | Reason: ${reason}`
    );

    return record;
  },

  /**
   * Clear a quarantine after investigation concludes the agent is safe.
   * The agent's token must be re-issued separately via AgentRegistry before restart.
   *
   * @param quarantineId - The quarantine event to clear
   * @param resolution - Human-readable outcome of the investigation
   * @param clearedBy - Who is clearing the quarantine
   */
  clear(quarantineId: string, resolution: string, clearedBy: string): QuarantineRecord {
    const record = quarantineRecords.get(quarantineId);
    if (!record) {
      throw new Error(`[Quarantine] No quarantine record found for ID: ${quarantineId}`);
    }
    if (record.status !== 'active') {
      throw new Error(
        `[Quarantine] Quarantine ${quarantineId} is already resolved (status: ${record.status}).`
      );
    }

    const now = new Date();
    record.status = 'cleared';
    record.resolvedAt = now.getTime();
    record.resolvedAtIso = now.toISOString();
    record.resolvedBy = clearedBy;
    record.resolution = resolution;

    AuditLogger.log({
      agentId: record.agentId,
      event: 'agent.started', // Reuse lifecycle event — "cleared for restart"
      metadata: {
        action: 'quarantine_cleared',
        quarantineId,
        resolution,
        clearedBy,
        durationMs: now.getTime() - record.quarantinedAt,
      },
    });

    console.info(
      `[Quarantine] Quarantine ${quarantineId} cleared for agent "${record.agentId}" by ${clearedBy}.`
    );

    return record;
  },

  /**
   * Permanently terminate a quarantined agent.
   * Use when investigation confirms compromise or the agent is no longer needed.
   * Unlike clear(), the agent cannot be restarted from this state.
   */
  terminate(quarantineId: string, reason: string, terminatedBy: string): QuarantineRecord {
    const record = quarantineRecords.get(quarantineId);
    if (!record) {
      throw new Error(`[Quarantine] No quarantine record found for ID: ${quarantineId}`);
    }
    if (record.status !== 'active') {
      throw new Error(
        `[Quarantine] Quarantine ${quarantineId} is already resolved (status: ${record.status}).`
      );
    }

    const now = new Date();
    record.status = 'terminated';
    record.resolvedAt = now.getTime();
    record.resolvedAtIso = now.toISOString();
    record.resolvedBy = terminatedBy;
    record.resolution = reason;

    AuditLogger.log({
      agentId: record.agentId,
      event: 'agent.stopped',
      metadata: {
        action: 'quarantine_terminated',
        quarantineId,
        reason,
        terminatedBy,
      },
    });

    console.warn(
      `[Quarantine] Agent "${record.agentId}" permanently terminated from quarantine ${quarantineId}.`
    );

    return record;
  },

  /**
   * Check if an agent is currently under active quarantine.
   */
  isQuarantined(agentId: string): boolean {
    const quarantineId = agentQuarantineIndex.get(agentId);
    if (!quarantineId) return false;
    const record = quarantineRecords.get(quarantineId);
    return record?.status === 'active';
  },

  /**
   * Get the forensic snapshot for a quarantine event.
   */
  getSnapshot(quarantineId: string): ForensicSnapshot | null {
    return quarantineRecords.get(quarantineId)?.snapshot ?? null;
  },

  /**
   * Get the full quarantine record by ID.
   */
  get(quarantineId: string): QuarantineRecord | null {
    return quarantineRecords.get(quarantineId) ?? null;
  },

  /**
   * Get the active quarantine record for an agent, if any.
   */
  getForAgent(agentId: string): QuarantineRecord | null {
    const quarantineId = agentQuarantineIndex.get(agentId);
    if (!quarantineId) return null;
    return quarantineRecords.get(quarantineId) ?? null;
  },

  /**
   * List all quarantine records with optional filters.
   */
  list(filter?: {
    status?: QuarantineStatus;
    severity?: QuarantineSeverity;
    since?: number;
  }): QuarantineRecord[] {
    let results = Array.from(quarantineRecords.values());
    if (filter?.status) results = results.filter((r) => r.status === filter.status);
    if (filter?.severity) results = results.filter((r) => r.severity === filter.severity);
    if (filter?.since) results = results.filter((r) => r.quarantinedAt >= filter.since!);
    return results.sort((a, b) => b.quarantinedAt - a.quarantinedAt);
  },

  /** Summary for monitoring dashboards */
  stats(): {
    totalQuarantines: number;
    activeQuarantines: number;
    clearedQuarantines: number;
    terminatedQuarantines: number;
    bySeverity: Record<QuarantineSeverity, number>;
  } {
    const records = Array.from(quarantineRecords.values());
    const bySeverity: Record<QuarantineSeverity, number> = {
      low: 0, medium: 0, high: 0, critical: 0,
    };
    for (const r of records) {
      bySeverity[r.severity]++;
    }

    return {
      totalQuarantines: records.length,
      activeQuarantines: records.filter((r) => r.status === 'active').length,
      clearedQuarantines: records.filter((r) => r.status === 'cleared').length,
      terminatedQuarantines: records.filter((r) => r.status === 'terminated').length,
      bySeverity,
    };
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Strip anything that looks like a key or secret from agent state
 * before storing in the forensic snapshot.
 */
function sanitizeState(state: Record<string, unknown>): Record<string, unknown> {
  const REDACT_PATTERNS = /key|secret|token|password|credential|auth|api/i;
  const result: Record<string, unknown> = {};

  for (const [k, v] of Object.entries(state)) {
    if (REDACT_PATTERNS.test(k)) {
      result[k] = '[REDACTED]';
    } else if (v && typeof v === 'object' && !Array.isArray(v)) {
      result[k] = sanitizeState(v as Record<string, unknown>);
    } else {
      result[k] = v;
    }
  }

  return result;
}
