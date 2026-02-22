// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Agent Registry
// Agent lifecycle management
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../event-bus/EventBus';
import type { Agent, AgentConfig, AgentStatus } from '../../runtime/Agent';

export class AgentRegistry {
  private agents: Map<string, Agent> = new Map();

  // ─────────────────────────────────────────────────────────────────────────────
  // Registration
  // ─────────────────────────────────────────────────────────────────────────────

  register(agent: Agent): void {
    if (this.agents.has(agent.id)) {
      throw new Error(`Agent already registered: ${agent.id}`);
    }
    this.agents.set(agent.id, agent);
    eventBus.emit('agent:registered', { agentId: agent.id, config: agent.getConfig() });
  }

  unregister(agentId: string): boolean {
    const agent = this.agents.get(agentId);
    if (!agent) return false;

    if (agent.getStatus() === 'running') {
      agent.stop();
    }
    this.agents.delete(agentId);
    eventBus.emit('agent:unregistered', { agentId });
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Query
  // ─────────────────────────────────────────────────────────────────────────────

  get(agentId: string): Agent | undefined {
    return this.agents.get(agentId);
  }

  getAll(): Agent[] {
    return Array.from(this.agents.values());
  }

  find(filter: {
    type?: string;
    status?: AgentStatus;
    tags?: string[];
  }): Agent[] {
    let results = this.getAll();
    
    if (filter.type) {
      results = results.filter(a => a.getConfig().type === filter.type);
    }
    if (filter.status) {
      results = results.filter(a => a.getStatus() === filter.status);
    }
    if (filter.tags) {
      results = results.filter(a =>
        filter.tags!.some(t => a.getConfig().tags?.includes(t))
      );
    }
    
    return results;
  }

  has(agentId: string): boolean {
    return this.agents.has(agentId);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────────

  async startAgent(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    if (!agent) throw new Error(`Agent not found: ${agentId}`);
    await agent._internalStart();
  }

  async stopAgent(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    if (!agent) throw new Error(`Agent not found: ${agentId}`);
    await agent.stop();
  }

  async startAll(): Promise<void> {
    const agents = this.getAll();
    await Promise.all(agents.map(a => a._internalStart()));
  }

  async stopAll(): Promise<void> {
    const agents = this.getAll().filter(a => a.getStatus() === 'running');
    await Promise.all(agents.map(a => a.stop()));
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Stats
  // ─────────────────────────────────────────────────────────────────────────────

  getStats(): {
    total: number;
    byStatus: Record<AgentStatus, number>;
    byType: Record<string, number>;
  } {
    const agents = this.getAll();
    const byStatus: Record<string, number> = {};
    const byType: Record<string, number> = {};

    for (const agent of agents) {
      byStatus[agent.getStatus()] = (byStatus[agent.getStatus()] || 0) + 1;
      byType[agent.getConfig().type] = (byType[agent.getConfig().type] || 0) + 1;
    }

    return {
      total: agents.length,
      byStatus: byStatus as Record<AgentStatus, number>,
      byType,
    };
  }
}

export const agentRegistry = new AgentRegistry();
