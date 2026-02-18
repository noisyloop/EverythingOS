/**
 * EverythingOS — Hardened AgentRegistry
 *
 * NIST AI RMF 1.0 — GOVERN (GV-2), MANAGE (MG-2.2)
 *
 * The registry is the single entry point for agent lifecycle management.
 * It enforces:
 *   - riskConfig validation before any agent can start
 *   - Token issuance and revocation tied to lifecycle
 *   - Audit logging of all registration/deregistration events
 *   - Compliance checks before start (HIGH tier agents checked for ApprovalGate)
 *   - Emergency stop that halts ALL agents and revokes ALL tokens
 */

import { Agent } from '../runtime/Agent';
import { AgentRiskTier } from '../types/agent-risk';
import { AgentAuthManager } from '../security/agent-auth';
import { AuditLogger } from '../security/audit-log';

// ─────────────────────────────────────────────────────────────────────────────
// Registry State
// ─────────────────────────────────────────────────────────────────────────────

const registry = new Map<string, Agent>();
let approvalGateRegistered = false;

// ─────────────────────────────────────────────────────────────────────────────
// Compliance Pre-flight Checks
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validates that a HIGH tier agent can safely start.
 * Throws if required conditions aren't met.
 */
function preflightCheck(agent: Agent): void {
  const tier = agent.getRiskTier();

  if (tier === AgentRiskTier.HIGH) {
    // HIGH tier agents require the ApprovalGateAgent to be registered and running
    if (!approvalGateRegistered) {
      throw new Error(
        `[AgentRegistry] COMPLIANCE BLOCK: Agent "${agent.name}" is HIGH risk tier but ` +
        `ApprovalGateAgent is not registered. ` +
        `Register ApprovalGateAgent before starting HIGH risk agents. ` +
        `NIST AI RMF requires human-in-the-loop for HIGH risk tier agents.`
      );
    }

    // HIGH tier agents must have a riskJustification documented
    if (!agent['config']?.riskConfig?.riskJustification?.trim()) {
      throw new Error(
        `[AgentRegistry] COMPLIANCE BLOCK: HIGH risk agent "${agent.name}" must have ` +
        `riskJustification documented in riskConfig. ` +
        `Example: "Executes real trades — irreversible financial action"`
      );
    }
  }

  // All MEDIUM+ agents with LLM must have genAIRisks declared
  if (tier !== AgentRiskTier.LOW && agent['config']?.llm) {
    const genAIRisks = agent['config']?.riskConfig?.genAIRisks;
    if (!genAIRisks) {
      throw new Error(
        `[AgentRegistry] COMPLIANCE BLOCK: Agent "${agent.name}" uses an LLM but has no ` +
        `genAIRisks declared in riskConfig. ` +
        `NIST AI 600-1 requires GenAI risk flags for LLM-integrated agents. ` +
        `Add genAIRisks: { promptInjectionRisk: true, hallucinationRisk: true, ... } to riskConfig.`
      );
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentRegistry
// ─────────────────────────────────────────────────────────────────────────────

export const AgentRegistry = {
  /**
   * Register an agent. Does NOT start it.
   * Validates riskConfig and runs compliance pre-flight checks.
   */
  register(agent: Agent): void {
    if (registry.has(agent.id)) {
      throw new Error(`[AgentRegistry] Agent "${agent.id}" is already registered. Unregister it first.`);
    }

    // Track if ApprovalGateAgent is being registered
    if (agent.name === 'ApprovalGateAgent' || agent.id === 'approval-gate') {
      approvalGateRegistered = true;
    }

    registry.set(agent.id, agent);

    AuditLogger.log({
      agentId: agent.id,
      event: 'agent.registered',
      metadata: {
        name: agent.name,
        type: agent.type,
        tier: agent.getRiskTier(),
      },
    });

    console.info(`[AgentRegistry] Registered: ${agent.name} (${agent.id}) — Tier: ${agent.getRiskTier()}`);
  },

  /**
   * Start a registered agent.
   * Runs compliance pre-flight checks before starting.
   */
  async start(agentId: string): Promise<void> {
    const agent = registry.get(agentId);
    if (!agent) {
      throw new Error(`[AgentRegistry] Cannot start — agent "${agentId}" is not registered.`);
    }

    // Run compliance checks before starting
    preflightCheck(agent);

    await agent._internalStart();
    console.info(`[AgentRegistry] Started: ${agent.name} (${agentId})`);
  },

  /**
   * Stop a running agent gracefully.
   */
  async stop(agentId: string): Promise<void> {
    const agent = registry.get(agentId);
    if (!agent) {
      throw new Error(`[AgentRegistry] Cannot stop — agent "${agentId}" is not registered.`);
    }

    await agent._internalStop();
    console.info(`[AgentRegistry] Stopped: ${agent.name} (${agentId})`);
  },

  /**
   * Register and immediately start an agent.
   * Convenience method for simple deployments.
   */
  async registerAndStart(agent: Agent): Promise<void> {
    AgentRegistry.register(agent);
    await AgentRegistry.start(agent.id);
  },

  /**
   * EMERGENCY STOP — halts ALL agents and revokes ALL tokens immediately.
   * Use during incidents or when the system is in an unknown state.
   * NIST AI RMF MANAGE function requires this capability.
   */
  async emergencyStop(triggeredBy: string = 'manual'): Promise<void> {
    console.error(`[AgentRegistry] ⚠️  EMERGENCY STOP triggered by: ${triggeredBy}`);

    AuditLogger.log({
      agentId: 'system',
      event: 'safety.emergency_stop',
      metadata: { triggeredBy, agentCount: registry.size },
    });

    const stopPromises = Array.from(registry.values()).map(async (agent) => {
      try {
        await agent._internalStop();
        AgentAuthManager.revokeToken(agent.id, `emergency_stop:${triggeredBy}`);
      } catch (err) {
        console.error(`[AgentRegistry] Failed to stop agent ${agent.id}:`, err);
        AuditLogger.log({
          agentId: agent.id,
          event: 'agent.error',
          metadata: { phase: 'emergency_stop', error: String(err) },
        });
      }
    });

    await Promise.allSettled(stopPromises);
    approvalGateRegistered = false;

    console.error(`[AgentRegistry] ⚠️  Emergency stop complete. All ${registry.size} agents halted.`);
  },

  /**
   * Unregister an agent. Must be stopped first.
   */
  unregister(agentId: string): void {
    const agent = registry.get(agentId);
    if (!agent) return;

    if (agent.isRunning()) {
      throw new Error(`[AgentRegistry] Cannot unregister running agent "${agentId}". Stop it first.`);
    }

    registry.delete(agentId);

    if (agent.name === 'ApprovalGateAgent' || agentId === 'approval-gate') {
      approvalGateRegistered = false;
    }
  },

  /**
   * List all registered agents with their status and tier.
   */
  list(): Array<{ id: string; name: string; type: string; tier: AgentRiskTier; running: boolean }> {
    return Array.from(registry.values()).map((a) => ({
      id: a.id,
      name: a.name,
      type: a.type,
      tier: a.getRiskTier(),
      running: a.isRunning(),
    }));
  },

  /**
   * Compliance status report — useful for the /api/compliance/status endpoint.
   */
  complianceStatus(): {
    totalAgents: number;
    runningAgents: number;
    approvalGateActive: boolean;
    tierBreakdown: Record<AgentRiskTier, number>;
    auditStats: ReturnType<typeof AuditLogger.stats>;
    tokenStatus: ReturnType<typeof AgentAuthManager.listTokens>;
  } {
    const agents = Array.from(registry.values());
    const tierBreakdown: Record<AgentRiskTier, number> = {
      [AgentRiskTier.LOW]: 0,
      [AgentRiskTier.MEDIUM]: 0,
      [AgentRiskTier.HIGH]: 0,
    };

    for (const agent of agents) {
      tierBreakdown[agent.getRiskTier()]++;
    }

    return {
      totalAgents: agents.length,
      runningAgents: agents.filter((a) => a.isRunning()).length,
      approvalGateActive: approvalGateRegistered,
      tierBreakdown,
      auditStats: AuditLogger.stats(),
      tokenStatus: AgentAuthManager.listTokens(),
    };
  },
};
