/**
 * EverythingOS — Compliance Status API
 *
 * NIST AI RMF 1.0 — MEASURE (MS-2.6), MANAGE (MG-4)
 *
 * Exposes a single endpoint that gives a real-time view of the
 * compliance posture of the running system. Wire this into your
 * existing REST API server at GET /api/compliance/status.
 *
 * Usage (Express example):
 *   import { complianceStatusHandler } from '../api/compliance';
 *   app.get('/api/compliance/status', complianceStatusHandler);
 *   app.post('/api/compliance/emergency-stop', emergencyStopHandler);
 *   app.get('/api/compliance/audit', auditQueryHandler);
 *   app.get('/api/compliance/audit/verify', auditVerifyHandler);
 */

import { agentRegistry } from '../core/registry/AgentRegistry';
import { AuditLogger } from '../security/audit-log';
import { AgentRiskTier } from '../types/agent-risk';

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/compliance/status
// ─────────────────────────────────────────────────────────────────────────────

export async function complianceStatusHandler(
  _req: unknown,
  res: { json: (data: unknown) => void; status: (code: number) => { json: (data: unknown) => void } }
): Promise<void> {
  const status = agentRegistry.complianceStatus();
  const auditVerification = await AuditLogger.verifyChain();

  const highRiskWithoutApprovalGate =
    status.tierBreakdown[AgentRiskTier.HIGH] > 0 && !status.approvalGateActive;

  const overallCompliant =
    auditVerification.valid &&
    !highRiskWithoutApprovalGate;

  const report = {
    timestamp: new Date().toISOString(),
    compliant: overallCompliant,
    issues: [] as string[],

    agents: {
      total: status.totalAgents,
      running: status.runningAgents,
      byTier: status.tierBreakdown,
    },

    controls: {
      approvalGateActive: status.approvalGateActive,
      auditLogIntact: auditVerification.valid,
      auditLogEntries: auditVerification.totalEntries,
    },

    security: {
      injectionAttemptsDetected: status.auditStats.injectionAttempts,
      blockedPublishAttempts: status.auditStats.blockedPublishes,
      securityEventsTotal: status.auditStats.securityEvents,
      activeTokens: status.tokenStatus.filter((t) => !t.revoked).length,
      revokedTokens: status.tokenStatus.filter((t) => t.revoked).length,
    },

    nistAlignment: {
      govern: {
        status: 'active',
        notes: 'Policies: SECURITY.md, AI_USAGE_POLICY.md, AI_ETHICS.md, INCIDENT_RESPONSE.md',
      },
      map: {
        status: 'active',
        notes: `${status.totalAgents} agents classified by risk tier`,
      },
      measure: {
        status: auditVerification.valid ? 'active' : 'degraded',
        notes: auditVerification.valid
          ? `Audit log chain valid (${auditVerification.totalEntries} entries)`
          : `Audit log chain broken at entry ${auditVerification.brokenAt}: ${auditVerification.reason}`,
      },
      manage: {
        status: overallCompliant ? 'active' : 'attention_required',
        notes: overallCompliant
          ? 'All controls operational'
          : 'See issues array for required actions',
      },
    },
  };

  // Populate issues
  if (!auditVerification.valid) {
    report.issues.push(
      `CRITICAL: Audit log chain broken at entry ${auditVerification.brokenAt}. ` +
      `Possible tampering. Follow INCIDENT_RESPONSE.md.`
    );
  }

  if (highRiskWithoutApprovalGate) {
    report.issues.push(
      `HIGH: ${status.tierBreakdown[AgentRiskTier.HIGH]} HIGH risk agent(s) running without ` +
      `ApprovalGateAgent. NIST requires human-in-the-loop for HIGH risk tier.`
    );
  }

  if (status.auditStats.injectionAttempts > 0) {
    report.issues.push(
      `INFO: ${status.auditStats.injectionAttempts} prompt injection attempt(s) detected ` +
      `since last restart. Review audit log for details.`
    );
  }

  const statusCode = overallCompliant ? 200 : 409;
  res.status(statusCode).json(report);
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/compliance/emergency-stop
// ─────────────────────────────────────────────────────────────────────────────

export async function emergencyStopHandler(
  req: { body?: { triggeredBy?: string } },
  res: { json: (data: unknown) => void }
): Promise<void> {
  const triggeredBy = req.body?.triggeredBy ?? 'api_request';
  await agentRegistry.emergencyStop(triggeredBy);
  res.json({ success: true, message: 'Emergency stop executed. All agents halted.', triggeredBy });
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/compliance/audit
// ─────────────────────────────────────────────────────────────────────────────

export function auditQueryHandler(
  req: { query?: { agentId?: string; event?: string; since?: string; limit?: string } },
  res: { json: (data: unknown) => void }
): void {
  const { agentId, event, since, limit } = req.query ?? {};

  const results = AuditLogger.query({
    agentId: agentId as string | undefined,
    event: event as Parameters<typeof AuditLogger.query>[0]['event'],
    since: since ? Number(since) : undefined,
    limit: limit ? Number(limit) : 100,
  });

  res.json({ count: results.length, entries: results });
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/compliance/audit/verify
// ─────────────────────────────────────────────────────────────────────────────

export async function auditVerifyHandler(
  _req: unknown,
  res: { json: (data: unknown) => void }
): Promise<void> {
  const result = await AuditLogger.verifyChain();
  res.json(result);
}
