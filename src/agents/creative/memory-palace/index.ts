// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Memory Palace
// Persistent long-term memory store with tagging, keyword search, and flush-to-disk.
// Memories survive process restarts; the store is a single JSON file.
// ═══════════════════════════════════════════════════════════════════════════════

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import { Agent, AgentConfig } from '../../../runtime/Agent';
import { AgentRiskTier } from '../../../types/agent-risk';
import { AgentManifest, validateManifest } from '../../../types/agent-manifest';

export const MANIFEST: AgentManifest = validateManifest({
  id: 'memory-palace',
  name: 'Memory Palace',
  version: '1.0.0',
  category: 'creative',
  description: 'Persistent long-term memory store with tagging, keyword search, and access tracking — memories survive process restarts.',
  capabilities: [
    'eventbus:subscribe', 'eventbus:publish',
    'filesystem:read', 'filesystem:write',
    'memory:read', 'memory:write',
  ],
  trustLevel: AgentRiskTier.MEDIUM,
  tags: ['creative', 'memory', 'persistence', 'storage'],
  author: 'EverythingOS',
});

export interface Memory {
  id: string;
  content: string;
  tags: string[];
  agentId: string;
  timestamp: number;
  accessCount: number;
}

interface DiskStore {
  memories: Memory[];
  idCounter: number;
}

export default class MemoryPalaceAgent extends Agent {
  private memories: Map<string, Memory> = new Map();
  private storePath: string;
  private dirty = false;
  private idCounter = 0;

  constructor(storePath?: string, config?: Partial<AgentConfig>) {
    super({
      id: MANIFEST.id,
      name: MANIFEST.name,
      type: 'learning',
      description: MANIFEST.description,
      tickRate: 60_000, // flush to disk every minute if dirty
      riskConfig: {
        tier: AgentRiskTier.MEDIUM,
        riskJustification: 'Writes to local filesystem only — no network calls or hardware access',
        allowedPublishChannels: ['memory:stored', 'memory:recalled', 'memory:stats'],
        allowedSubscribeChannels: ['memory:store', 'memory:recall', 'memory:forget'],
      },
      ...config,
    });
    this.storePath = resolve(storePath ?? process.env.MEMORY_PALACE_PATH ?? './memory-palace.json');
  }

  protected async onStart(): Promise<void> {
    this.loadFromDisk();

    this.subscribe<{ content: string; tags?: string[]; agentId?: string }>('memory:store', (event) => {
      const id = this.store(
        event.payload.content,
        event.payload.tags ?? [],
        event.payload.agentId ?? 'unknown',
      );
      this.emit('memory:stored', { id });
    });

    this.subscribe<{ query: string; tags?: string[]; limit?: number }>('memory:recall', (event) => {
      const results = this.recall(event.payload.query, event.payload.tags, event.payload.limit);
      this.emit('memory:recalled', { query: event.payload.query, results });
    });

    this.subscribe<{ id: string }>('memory:forget', (event) => {
      this.forget(event.payload.id);
    });

    this.log('info', `Memory palace started — ${this.memories.size} memories loaded`);
  }

  protected async onStop(): Promise<void> {
    if (this.dirty) this.flushToDisk();
    this.log('info', 'Memory palace stopped and flushed');
  }

  protected async onTick(): Promise<void> {
    if (this.dirty) this.flushToDisk();
    this.emit('memory:stats', { total: this.memories.size });
  }

  store(content: string, tags: string[], agentId: string): string {
    const id = `mem_${++this.idCounter}_${Date.now()}`;
    this.memories.set(id, { id, content, tags, agentId, timestamp: Date.now(), accessCount: 0 });
    this.dirty = true;
    return id;
  }

  recall(query: string, tags?: string[], limit = 10): Memory[] {
    const queryLower = query.toLowerCase();
    let results = Array.from(this.memories.values());

    if (tags && tags.length > 0) {
      results = results.filter((m) => tags.some((t) => m.tags.includes(t)));
    }

    results = results
      .filter((m) => m.content.toLowerCase().includes(queryLower))
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, limit);

    for (const m of results) m.accessCount++;
    if (results.length > 0) this.dirty = true;

    return results;
  }

  forget(id: string): boolean {
    const deleted = this.memories.delete(id);
    if (deleted) this.dirty = true;
    return deleted;
  }

  private loadFromDisk(): void {
    try {
      if (!existsSync(this.storePath)) return;
      const raw = readFileSync(this.storePath, 'utf-8');
      const data = JSON.parse(raw) as DiskStore;
      for (const m of data.memories) this.memories.set(m.id, m);
      this.idCounter = data.idCounter ?? 0;
    } catch (err) {
      this.log('warn', 'Could not load memory palace from disk', { error: String(err) });
    }
  }

  private flushToDisk(): void {
    try {
      const data: DiskStore = {
        memories: Array.from(this.memories.values()),
        idCounter: this.idCounter,
      };
      writeFileSync(this.storePath, JSON.stringify(data, null, 2), 'utf-8');
      this.dirty = false;
    } catch (err) {
      this.log('error', 'Could not flush memory palace to disk', { error: String(err) });
    }
  }
}
