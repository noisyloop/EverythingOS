// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Agent Registry
// Agent lifecycle management with auto-discovery and manifest-aware querying
// ═══════════════════════════════════════════════════════════════════════════════

import { readdir } from 'fs/promises';
import { existsSync } from 'fs';
import { join, resolve } from 'path';
import { eventBus } from '../event-bus/EventBus';
import { AuditLogger } from '../../security/audit-log';
import type { Agent, AgentConfig, AgentStatus, HealthStatus } from '../../runtime/Agent';
import { AgentManifest, validateManifest, AgentCapability, AgentCategory } from '../../types/agent-manifest';

// ─────────────────────────────────────────────────────────────────────────────
// Extended agent record — stores manifest alongside the instance
// ─────────────────────────────────────────────────────────────────────────────

interface AgentRecord {
  agent: Agent;
  manifest?: AgentManifest;
  loadedFrom?: string;
}

export class AgentRegistry {
  private records: Map<string, AgentRecord> = new Map();

  // ─────────────────────────────────────────────────────────────────────────────
  // Registration
  // ─────────────────────────────────────────────────────────────────────────────

  register(agent: Agent, manifest?: AgentManifest): void {
    if (this.records.has(agent.id)) {
      throw new Error(`[AgentRegistry] Agent already registered: ${agent.id}`);
    }
    this.records.set(agent.id, { agent, manifest });
    eventBus.emit('agent:registered', {
      agentId: agent.id,
      config: agent.getConfig(),
      manifest,
    });
    AuditLogger.log({
      agentId: agent.id,
      event: 'agent.registered',
      metadata: {
        category: manifest?.category,
        capabilities: manifest?.capabilities,
        trustLevel: manifest?.trustLevel,
      },
    });
  }

  unregister(agentId: string): boolean {
    const record = this.records.get(agentId);
    if (!record) return false;

    if (record.agent.getStatus() === 'running') {
      record.agent.stop();
    }
    this.records.delete(agentId);
    eventBus.emit('agent:unregistered', { agentId });
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Auto-discovery
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Scan a directory for agent modules and register them automatically.
   *
   * Conventions expected:
   *   - Each subdirectory (not starting with '_') is a potential agent module.
   *   - The module must export a `MANIFEST` constant that passes validateManifest().
   *   - The module's default export must be a class that extends Agent and
   *     can be instantiated with `new AgentClass()`.
   *
   * Modules that fail manifest validation or instantiation are skipped with
   * a warning — a bad plugin cannot prevent other agents from loading.
   *
   * @param dir  Absolute path to the agents directory to scan.
   * @returns    Number of agents successfully loaded.
   */
  async loadFromDirectory(dir: string): Promise<number> {
    const absDir = resolve(dir);
    if (!existsSync(absDir)) {
      console.warn(`[AgentRegistry] Directory not found, skipping auto-discovery: ${absDir}`);
      return 0;
    }

    let entries;
    try {
      entries = await readdir(absDir, { withFileTypes: true });
    } catch (err) {
      console.warn(`[AgentRegistry] Cannot read agent directory ${absDir}:`, err);
      return 0;
    }

    let loaded = 0;

    for (const entry of entries) {
      // Skip scaffolds, hidden directories, and non-directories
      if (!entry.isDirectory() || entry.name.startsWith('_') || entry.name.startsWith('.')) {
        continue;
      }

      const agentDir = join(absDir, entry.name);

      // Look for index.ts, index.js, or a file matching the directory name
      const candidates = [
        join(agentDir, 'index.ts'),
        join(agentDir, 'index.js'),
        join(agentDir, `${entry.name}.ts`),
        join(agentDir, `${entry.name}.js`),
      ];

      const modulePath = candidates.find(existsSync);
      if (!modulePath) {
        console.warn(`[AgentRegistry] No entry point found in ${agentDir} — skipping`);
        continue;
      }

      try {
        // Dynamic import — works with ts-node and compiled JS
        const mod = await import(modulePath) as Record<string, unknown>;

        if (!('MANIFEST' in mod)) {
          console.warn(`[AgentRegistry] ${modulePath} has no MANIFEST export — skipping`);
          continue;
        }

        let manifest: AgentManifest;
        try {
          manifest = validateManifest(mod.MANIFEST);
        } catch (err) {
          console.error(`[AgentRegistry] Invalid manifest in ${modulePath}:`, err);
          continue;
        }

        const AgentClass = (mod.default ?? mod[manifest.name.replace(/\s/g, '')]) as
          (new () => Agent) | undefined;

        if (!AgentClass || typeof AgentClass !== 'function') {
          console.warn(`[AgentRegistry] No default export (Agent class) in ${modulePath} — skipping`);
          continue;
        }

        // Avoid double-registration if already registered (e.g. explicit + auto-discovery)
        if (this.records.has(manifest.id)) {
          console.info(`[AgentRegistry] Agent "${manifest.id}" already registered, skipping auto-discovered duplicate`);
          continue;
        }

        const instance = new AgentClass();
        this.records.set(manifest.id, { agent: instance, manifest, loadedFrom: modulePath });

        eventBus.emit('agent:registered', {
          agentId: manifest.id,
          config: instance.getConfig(),
          manifest,
          autoDiscovered: true,
        });

        AuditLogger.log({
          agentId: manifest.id,
          event: 'agent.registered',
          metadata: { autoDiscovered: true, loadedFrom: modulePath, category: manifest.category },
        });

        console.info(`[AgentRegistry] Auto-loaded: ${manifest.name} (${manifest.id}) v${manifest.version}`);
        loaded++;
      } catch (err) {
        console.error(`[AgentRegistry] Failed to load agent from ${modulePath}:`, err);
      }
    }

    return loaded;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Query
  // ─────────────────────────────────────────────────────────────────────────────

  get(agentId: string): Agent | undefined {
    return this.records.get(agentId)?.agent;
  }

  getManifest(agentId: string): AgentManifest | undefined {
    return this.records.get(agentId)?.manifest;
  }

  getAll(): Agent[] {
    return Array.from(this.records.values()).map((r) => r.agent);
  }

  find(filter: {
    type?: AgentConfig['type'];
    status?: AgentStatus;
    tags?: string[];
    category?: AgentCategory;
  }): Agent[] {
    let results = Array.from(this.records.values());

    if (filter.type) {
      results = results.filter((r) => r.agent.getConfig().type === filter.type);
    }
    if (filter.status) {
      results = results.filter((r) => r.agent.getStatus() === filter.status);
    }
    if (filter.tags) {
      results = results.filter((r) =>
        filter.tags!.some(
          (t) =>
            r.agent.getConfig().tags?.includes(t) ||
            r.manifest?.tags?.includes(t)
        )
      );
    }
    if (filter.category) {
      results = results.filter((r) => r.manifest?.category === filter.category);
    }

    return results.map((r) => r.agent);
  }

  /** Find agents that declare a specific capability in their manifest */
  findByCapability(capability: AgentCapability): Agent[] {
    return Array.from(this.records.values())
      .filter((r) => r.manifest?.capabilities.includes(capability))
      .map((r) => r.agent);
  }

  has(agentId: string): boolean {
    return this.records.has(agentId);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────────

  async startAgent(agentId: string): Promise<void> {
    const agent = this.records.get(agentId)?.agent;
    if (!agent) throw new Error(`[AgentRegistry] Agent not found: ${agentId}`);
    await agent._internalStart();
  }

  async stopAgent(agentId: string): Promise<void> {
    const agent = this.records.get(agentId)?.agent;
    if (!agent) throw new Error(`[AgentRegistry] Agent not found: ${agentId}`);
    await agent.stop();
  }

  async startAll(): Promise<void> {
    await Promise.all(this.getAll().map((a) => a._internalStart()));
  }

  async stopAll(): Promise<void> {
    const running = this.getAll().filter((a) => a.getStatus() === 'running');
    await Promise.all(running.map((a) => a.stop()));
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Health
  // ─────────────────────────────────────────────────────────────────────────────

  /** Poll all registered agents for health status. */
  healthCheck(): HealthStatus[] {
    return this.getAll().map((a) => a.healthCheck());
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Stats
  // ─────────────────────────────────────────────────────────────────────────────

  getStats(): {
    total: number;
    byStatus: Record<AgentStatus, number>;
    byType: Record<string, number>;
    byCategory: Record<string, number>;
    withManifest: number;
  } {
    const records = Array.from(this.records.values());
    const byStatus: Record<string, number> = {};
    const byType: Record<string, number> = {};
    const byCategory: Record<string, number> = {};

    for (const { agent, manifest } of records) {
      const status = agent.getStatus();
      byStatus[status] = (byStatus[status] ?? 0) + 1;
      const type = agent.getConfig().type;
      byType[type] = (byType[type] ?? 0) + 1;
      if (manifest?.category) {
        byCategory[manifest.category] = (byCategory[manifest.category] ?? 0) + 1;
      }
    }

    return {
      total: records.length,
      byStatus: byStatus as Record<AgentStatus, number>,
      byType,
      byCategory,
      withManifest: records.filter((r) => r.manifest !== undefined).length,
    };
  }
}

// Preserve the import alias used throughout the codebase
export type { AgentConfig };
export const agentRegistry = new AgentRegistry();
