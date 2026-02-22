// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - World State
// Global state management for the system
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../event-bus/EventBus';

export class WorldState {
  private global: Map<string, unknown> = new Map();
  private agents: Map<string, Map<string, unknown>> = new Map();
  private tick = 0;

  // ─────────────────────────────────────────────────────────────────────────────
  // Global State
  // ─────────────────────────────────────────────────────────────────────────────

  setGlobal<T>(key: string, value: T): void {
    const oldValue = this.global.get(key);
    this.global.set(key, value);
    eventBus.emit('state:global:changed', { key, oldValue, newValue: value });
  }

  getGlobal<T>(key: string): T | undefined {
    return this.global.get(key) as T | undefined;
  }

  deleteGlobal(key: string): boolean {
    const existed = this.global.delete(key);
    if (existed) {
      eventBus.emit('state:global:deleted', { key });
    }
    return existed;
  }

  getAllGlobal(): Record<string, unknown> {
    return Object.fromEntries(this.global);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Agent State
  // ─────────────────────────────────────────────────────────────────────────────

  setAgentState<T>(agentId: string, key: string, value: T): void {
    if (!this.agents.has(agentId)) {
      this.agents.set(agentId, new Map());
    }
    const agentState = this.agents.get(agentId)!;
    const oldValue = agentState.get(key);
    agentState.set(key, value);
    eventBus.emit('state:agent:changed', { agentId, key, oldValue, newValue: value });
  }

  getAgentState<T>(agentId: string, key: string): T | undefined {
    return this.agents.get(agentId)?.get(key) as T | undefined;
  }

  getAllAgentState(agentId: string): Record<string, unknown> {
    const state = this.agents.get(agentId);
    return state ? Object.fromEntries(state) : {};
  }

  clearAgentState(agentId: string): void {
    this.agents.delete(agentId);
    eventBus.emit('state:agent:cleared', { agentId });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Tick Management
  // ─────────────────────────────────────────────────────────────────────────────

  incrementTick(): number {
    this.tick++;
    eventBus.emit('state:tick', { tick: this.tick });
    return this.tick;
  }

  getTick(): number {
    return this.tick;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Serialization
  // ─────────────────────────────────────────────────────────────────────────────

  export(): StateSnapshot {
    return {
      tick: this.tick,
      timestamp: Date.now(),
      global: Object.fromEntries(this.global),
      agents: Object.fromEntries(
        Array.from(this.agents.entries()).map(([id, state]) => [id, Object.fromEntries(state)])
      ),
    };
  }

  import(snapshot: StateSnapshot): void {
    this.tick = snapshot.tick;
    this.global = new Map(Object.entries(snapshot.global));
    this.agents = new Map(
      Object.entries(snapshot.agents).map(([id, state]) => [id, new Map(Object.entries(state))])
    );
    eventBus.emit('state:restored', { tick: this.tick });
  }

  clear(): void {
    this.global.clear();
    this.agents.clear();
    this.tick = 0;
    eventBus.emit('state:cleared', {});
  }
}

export interface StateSnapshot {
  tick: number;
  timestamp: number;
  global: Record<string, unknown>;
  agents: Record<string, Record<string, unknown>>;
}

export const worldState = new WorldState();
