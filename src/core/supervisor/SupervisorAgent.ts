// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Supervisor Agent
// Monitors and manages agent health and policies
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../event-bus/EventBus';
import { agentRegistry } from '../registry/AgentRegistry';
import { PolicyEngine, Policy, PolicyDecision } from './PolicyEngine';

export interface AgentHealth {
  agentId: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  lastCheck: number;
  errorCount: number;
  metrics: {
    executionCount: number;
    avgLatency: number;
    errorRate: number;
  };
}

export class SupervisorAgent {
  private health: Map<string, AgentHealth> = new Map();
  private policyEngine: PolicyEngine;
  private checkInterval: ReturnType<typeof setInterval> | null = null;
  private errorThreshold = 5;
  private checkIntervalMs = 30000;

  constructor() {
    this.policyEngine = new PolicyEngine();
    this.setupEventListeners();
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────────

  start(): void {
    this.checkInterval = setInterval(() => this.performHealthChecks(), this.checkIntervalMs);
    eventBus.emit('supervisor:started', {});
  }

  stop(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
    eventBus.emit('supervisor:stopped', {});
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Health Monitoring
  // ─────────────────────────────────────────────────────────────────────────────

  private setupEventListeners(): void {
    eventBus.on('agent:registered', (event) => {
      const { agentId } = event.payload as { agentId: string };
      this.initializeHealth(agentId);
    });

    eventBus.on('agent:unregistered', (event) => {
      const { agentId } = event.payload as { agentId: string };
      this.health.delete(agentId);
    });

    eventBus.on('agent:error', (event) => {
      const { agentId, error } = event.payload as { agentId: string; error: string };
      this.recordError(agentId, error);
    });

    eventBus.on('agent:action:completed', (event) => {
      const { agentId, duration } = event.payload as { agentId: string; duration: number };
      this.recordExecution(agentId, duration, true);
    });

    eventBus.on('agent:action:failed', (event) => {
      const { agentId, duration } = event.payload as { agentId: string; duration: number };
      this.recordExecution(agentId, duration, false);
    });
  }

  private initializeHealth(agentId: string): void {
    this.health.set(agentId, {
      agentId,
      status: 'unknown',
      lastCheck: Date.now(),
      errorCount: 0,
      metrics: {
        executionCount: 0,
        avgLatency: 0,
        errorRate: 0,
      },
    });
  }

  private recordError(agentId: string, error: string): void {
    const health = this.health.get(agentId);
    if (health) {
      health.errorCount++;
      this.updateHealthStatus(health);
      
      if (health.errorCount >= this.errorThreshold) {
        this.handleUnhealthyAgent(agentId, error);
      }
    }
  }

  private recordExecution(agentId: string, duration: number, success: boolean): void {
    const health = this.health.get(agentId);
    if (health) {
      const { metrics } = health;
      metrics.executionCount++;
      metrics.avgLatency = (metrics.avgLatency * (metrics.executionCount - 1) + duration) / metrics.executionCount;
      if (!success) {
        metrics.errorRate = (metrics.errorRate * (metrics.executionCount - 1) + 1) / metrics.executionCount;
      }
      this.updateHealthStatus(health);
    }
  }

  private updateHealthStatus(health: AgentHealth): void {
    const { metrics } = health;
    
    if (metrics.errorRate > 0.5 || health.errorCount >= this.errorThreshold) {
      health.status = 'unhealthy';
    } else if (metrics.errorRate > 0.1 || metrics.avgLatency > 5000) {
      health.status = 'degraded';
    } else {
      health.status = 'healthy';
    }
    
    health.lastCheck = Date.now();
  }

  private async performHealthChecks(): Promise<void> {
    for (const agent of agentRegistry.getAll()) {
      let health = this.health.get(agent.id);
      if (!health) {
        this.initializeHealth(agent.id);
        health = this.health.get(agent.id)!;
      }

      // Check if agent is responsive
      if (agent.getStatus() === 'running') {
        // TODO: Implement ping/health check
        health.lastCheck = Date.now();
      }

      this.updateHealthStatus(health);
    }

    eventBus.emit('supervisor:health:checked', {
      agents: Array.from(this.health.values()),
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Policy Enforcement
  // ─────────────────────────────────────────────────────────────────────────────

  addPolicy(policy: Policy): void {
    this.policyEngine.addPolicy(policy);
  }

  removePolicy(policyId: string): boolean {
    return this.policyEngine.removePolicy(policyId);
  }

  /**
   * Lock the policy store after startup. Prevents runtime policy injection
   * by compromised in-process agents. Call once all startup policies are loaded.
   */
  lockPolicies(): void {
    this.policyEngine.lock();
  }

  async evaluateAction(agentId: string, action: string, context: Record<string, unknown>): Promise<PolicyDecision> {
    return this.policyEngine.evaluate(agentId, action, context);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Intervention
  // ─────────────────────────────────────────────────────────────────────────────

  private async handleUnhealthyAgent(agentId: string, reason: string): Promise<void> {
    eventBus.emit('supervisor:agent:unhealthy', { agentId, reason });

    const decision = await this.policyEngine.evaluate(agentId, 'unhealthy', { reason });
    
    switch (decision.action) {
      case 'restart':
        await this.restartAgent(agentId);
        break;
      case 'stop':
        await this.stopAgent(agentId);
        break;
      case 'alert':
        eventBus.emit('supervisor:alert', { agentId, reason, severity: 'high' });
        break;
    }
  }

  async restartAgent(agentId: string): Promise<void> {
    const health = this.health.get(agentId);
    if (health) {
      health.errorCount = 0;
    }

    await agentRegistry.stopAgent(agentId);
    await agentRegistry.startAgent(agentId);
    eventBus.emit('supervisor:agent:restarted', { agentId });
  }

  async stopAgent(agentId: string): Promise<void> {
    await agentRegistry.stopAgent(agentId);
    eventBus.emit('supervisor:agent:stopped', { agentId });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Query
  // ─────────────────────────────────────────────────────────────────────────────

  getHealth(agentId: string): AgentHealth | undefined {
    return this.health.get(agentId);
  }

  getAllHealth(): AgentHealth[] {
    return Array.from(this.health.values());
  }

  getUnhealthyAgents(): AgentHealth[] {
    return this.getAllHealth().filter(h => h.status === 'unhealthy');
  }
}

export const supervisor = new SupervisorAgent();
