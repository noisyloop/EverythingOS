// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Snapshot Manager
// State persistence and recovery
// ═══════════════════════════════════════════════════════════════════════════════

import { worldState, StateSnapshot } from './WorldState';
import { eventBus } from '../../event-bus/EventBus';

export interface SnapshotMetadata {
  id: string;
  name?: string;
  tick: number;
  timestamp: number;
  size: number;
  tags?: string[];
}

export class SnapshotManager {
  private snapshots: Map<string, { metadata: SnapshotMetadata; data: StateSnapshot }> = new Map();
  private maxSnapshots = 100;
  private autoSnapshotInterval: ReturnType<typeof setInterval> | null = null;

  // ─────────────────────────────────────────────────────────────────────────────
  // Create & Restore
  // ─────────────────────────────────────────────────────────────────────────────

  create(name?: string, tags?: string[]): SnapshotMetadata {
    const data = worldState.export();
    const id = this.generateId();
    
    const metadata: SnapshotMetadata = {
      id,
      name,
      tick: data.tick,
      timestamp: data.timestamp,
      size: JSON.stringify(data).length,
      tags,
    };

    this.snapshots.set(id, { metadata, data });
    this.prune();
    
    eventBus.emit('snapshot:created', { id, tick: data.tick });
    return metadata;
  }

  restore(id: string): boolean {
    const snapshot = this.snapshots.get(id);
    if (!snapshot) return false;

    worldState.import(snapshot.data);
    eventBus.emit('snapshot:restored', { id, tick: snapshot.data.tick });
    return true;
  }

  restoreToTick(tick: number): boolean {
    const snapshot = this.findByTick(tick);
    if (!snapshot) return false;
    return this.restore(snapshot.id);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Query
  // ─────────────────────────────────────────────────────────────────────────────

  get(id: string): { metadata: SnapshotMetadata; data: StateSnapshot } | undefined {
    return this.snapshots.get(id);
  }

  list(filter?: { tags?: string[]; since?: number; limit?: number }): SnapshotMetadata[] {
    let results = Array.from(this.snapshots.values()).map(s => s.metadata);
    
    if (filter?.tags) {
      results = results.filter(s => filter.tags!.some(t => s.tags?.includes(t)));
    }
    if (filter?.since) {
      results = results.filter(s => s.timestamp >= filter.since!);
    }
    
    results.sort((a, b) => b.timestamp - a.timestamp);
    
    if (filter?.limit) {
      results = results.slice(0, filter.limit);
    }
    
    return results;
  }

  findByTick(tick: number): SnapshotMetadata | undefined {
    let closest: SnapshotMetadata | undefined;
    let closestDiff = Infinity;

    for (const { metadata } of this.snapshots.values()) {
      const diff = Math.abs(metadata.tick - tick);
      if (diff < closestDiff && metadata.tick <= tick) {
        closest = metadata;
        closestDiff = diff;
      }
    }

    return closest;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Delete
  // ─────────────────────────────────────────────────────────────────────────────

  delete(id: string): boolean {
    const existed = this.snapshots.delete(id);
    if (existed) {
      eventBus.emit('snapshot:deleted', { id });
    }
    return existed;
  }

  clear(): void {
    this.snapshots.clear();
    eventBus.emit('snapshot:cleared', {});
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Auto-Snapshot
  // ─────────────────────────────────────────────────────────────────────────────

  startAutoSnapshot(intervalMs: number): void {
    this.stopAutoSnapshot();
    this.autoSnapshotInterval = setInterval(() => {
      this.create('auto', ['auto']);
    }, intervalMs);
  }

  stopAutoSnapshot(): void {
    if (this.autoSnapshotInterval) {
      clearInterval(this.autoSnapshotInterval);
      this.autoSnapshotInterval = null;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────────────────────

  private prune(): void {
    if (this.snapshots.size <= this.maxSnapshots) return;

    const sorted = Array.from(this.snapshots.entries())
      .sort((a, b) => a[1].metadata.timestamp - b[1].metadata.timestamp);

    const toRemove = sorted.slice(0, this.snapshots.size - this.maxSnapshots);
    for (const [id] of toRemove) {
      this.snapshots.delete(id);
    }
  }

  private generateId(): string {
    return `snap_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
  }

  setMaxSnapshots(max: number): void {
    this.maxSnapshots = max;
    this.prune();
  }
}

export const snapshotManager = new SnapshotManager();
