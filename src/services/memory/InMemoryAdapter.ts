// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - In-Memory Adapter
// Default memory adapter - no external dependencies
// ═══════════════════════════════════════════════════════════════════════════════

import {
  MemoryAdapter,
  MemoryEntry,
  MemoryQuery,
  MemoryResult,
  MemoryFilter,
} from './MemoryTypes';

export class InMemoryAdapter implements MemoryAdapter {
  readonly name = 'in-memory';
  private entries: Map<string, MemoryEntry> = new Map();
  private idCounter = 0;

  // ─────────────────────────────────────────────────────────────────────────────
  // CRUD Operations
  // ─────────────────────────────────────────────────────────────────────────────

  async store(entry: Omit<MemoryEntry, 'id' | 'createdAt' | 'updatedAt'>): Promise<MemoryEntry> {
    const id = this.generateId();
    const now = Date.now();
    
    const fullEntry: MemoryEntry = {
      ...entry,
      id,
      createdAt: now,
      updatedAt: now,
      metadata: {
        ...entry.metadata,
        accessCount: 0,
      },
    };
    
    this.entries.set(id, fullEntry);
    return fullEntry;
  }

  async get(id: string): Promise<MemoryEntry | null> {
    const entry = this.entries.get(id);
    if (!entry) return null;
    
    // Update access tracking
    entry.metadata.accessCount = (entry.metadata.accessCount || 0) + 1;
    entry.metadata.lastAccessedAt = Date.now();
    
    return entry;
  }

  async update(id: string, updates: Partial<MemoryEntry>): Promise<MemoryEntry | null> {
    const entry = this.entries.get(id);
    if (!entry) return null;
    
    const updated: MemoryEntry = {
      ...entry,
      ...updates,
      id, // Prevent ID change
      createdAt: entry.createdAt, // Prevent creation time change
      updatedAt: Date.now(),
      metadata: {
        ...entry.metadata,
        ...updates.metadata,
      },
    };
    
    this.entries.set(id, updated);
    return updated;
  }

  async delete(id: string): Promise<boolean> {
    return this.entries.delete(id);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Search
  // ─────────────────────────────────────────────────────────────────────────────

  async search(query: MemoryQuery): Promise<MemoryResult[]> {
    let results: MemoryResult[] = [];
    const now = Date.now();
    
    for (const entry of this.entries.values()) {
      // Skip expired unless requested
      if (!query.includeExpired && entry.expiresAt && entry.expiresAt < now) {
        continue;
      }
      
      // Apply filters
      if (query.filter && !this.matchesFilter(entry, query.filter)) {
        continue;
      }
      
      // Calculate relevance
      let relevance = 1;
      
      if (query.text) {
        // Simple text matching (in production, use embeddings)
        relevance = this.calculateTextRelevance(entry.content, query.text);
        
        if (query.minRelevance && relevance < query.minRelevance) {
          continue;
        }
      }
      
      results.push({ entry, relevance });
    }
    
    // Sort by relevance
    results.sort((a, b) => (b.relevance || 0) - (a.relevance || 0));
    
    // Apply pagination
    if (query.offset) {
      results = results.slice(query.offset);
    }
    if (query.limit) {
      results = results.slice(0, query.limit);
    }
    
    return results;
  }

  private matchesFilter(entry: MemoryEntry, filter: MemoryFilter): boolean {
    // Source filter
    if (filter.source) {
      const sources = Array.isArray(filter.source) ? filter.source : [filter.source];
      if (!sources.includes(entry.metadata.source)) return false;
    }
    
    // Type filter
    if (filter.type) {
      const types = Array.isArray(filter.type) ? filter.type : [filter.type];
      if (!types.includes(entry.metadata.type)) return false;
    }
    
    // Tags filter (any match)
    if (filter.tags && filter.tags.length > 0) {
      if (!entry.metadata.tags) return false;
      if (!filter.tags.some((t: string) => entry.metadata.tags!.includes(t))) return false;
    }
    
    // Time range
    if (filter.since && entry.createdAt < filter.since) return false;
    if (filter.until && entry.createdAt > filter.until) return false;
    
    // Importance
    if (filter.minImportance !== undefined) {
      if ((entry.metadata.importance || 0) < filter.minImportance) return false;
    }
    
    return true;
  }

  private calculateTextRelevance(content: string, query: string): number {
    const contentLower = content.toLowerCase();
    const queryLower = query.toLowerCase();
    const queryWords = queryLower.split(/\s+/);
    
    // Exact match
    if (contentLower.includes(queryLower)) {
      return 1;
    }
    
    // Word overlap
    let matches = 0;
    for (const word of queryWords) {
      if (word.length > 2 && contentLower.includes(word)) {
        matches++;
      }
    }
    
    return queryWords.length > 0 ? matches / queryWords.length : 0;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Maintenance
  // ─────────────────────────────────────────────────────────────────────────────

  async prune(filter: MemoryFilter): Promise<number> {
    let pruned = 0;
    
    for (const [id, entry] of this.entries) {
      if (this.matchesFilter(entry, filter)) {
        this.entries.delete(id);
        pruned++;
      }
    }
    
    return pruned;
  }

  async clear(): Promise<void> {
    this.entries.clear();
  }

  async count(filter?: MemoryFilter): Promise<number> {
    if (!filter) return this.entries.size;
    
    let count = 0;
    for (const entry of this.entries.values()) {
      if (this.matchesFilter(entry, filter)) count++;
    }
    return count;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────────────────────

  private generateId(): string {
    return `mem_${Date.now().toString(36)}_${(++this.idCounter).toString(36)}`;
  }

  // Export/Import for persistence
  export(): MemoryEntry[] {
    return Array.from(this.entries.values());
  }

  import(entries: MemoryEntry[]): void {
    for (const entry of entries) {
      this.entries.set(entry.id, entry);
    }
  }
}
