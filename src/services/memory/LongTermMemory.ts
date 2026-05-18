// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Long-Term Memory
// Persistent memory with vector search
// Agents access this through MemoryService, never directly
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../core/event-bus/EventBus';
import { sanitizeInput } from '../../security/sanitize';
import {
  MemoryAdapter,
  MemoryEntry,
  MemoryQuery,
  MemoryResult,
  MemoryFilter,
  MemoryType,
  EmbeddingProvider,
} from './MemoryTypes';
import { InMemoryAdapter } from './adapters/InMemoryAdapter';

// Trust assumed for an entry that carries no explicit trust (incl. legacy
// entries written before per-entry trust existed). Above the default floor
// so existing data stays retrievable.
const DEFAULT_TRUST = 0.5;
// Trust assigned when store-time injection patterns are detected.
const INJECTION_TRUST = 0.1;
// Trust assigned when an entry trips the poisoning-breadth heuristic.
const POISON_TRUST = 0.05;
// Only near-exact matches count toward breadth — a keyword-stuffed entry
// matches many distinct queries near-exactly; a normal entry does not.
const BREADTH_RELEVANCE_MIN = 0.95;

export interface LongTermMemoryConfig {
  adapter?: MemoryAdapter;
  embedding?: EmbeddingProvider;
  maxEntries?: number;
  pruneThreshold?: number;     // Prune when importance below this
  autoConsolidate?: boolean;   // Merge similar memories
  /** Entries with trust below this are excluded from retrieval. Default 0.2. */
  minTrust?: number;
  /**
   * If an entry is a near-exact match for more than this many *distinct*
   * queries, it is treated as keyword-stuffed poisoning, flagged, and
   * excluded. Default 12. Set 0 to disable the heuristic.
   */
  poisonBreadthThreshold?: number;
}

export class LongTermMemory {
  private adapter: MemoryAdapter;
  private embedding: EmbeddingProvider | null;
  private config: Required<Omit<LongTermMemoryConfig, 'adapter' | 'embedding'>>;
  // Per-entry set of distinct normalized queries it near-exactly matched.
  // Bounded: at most MAX_BREADTH_ENTRIES entries, each set capped.
  private breadthByEntry = new Map<string, Set<string>>();
  private static readonly MAX_BREADTH_ENTRIES = 5000;
  private static readonly MAX_BREADTH_QUERIES_PER_ENTRY = 64;

  constructor(config: LongTermMemoryConfig = {}) {
    this.adapter = config.adapter ?? new InMemoryAdapter();
    this.embedding = config.embedding ?? null;
    this.config = {
      maxEntries: config.maxEntries ?? 10000,
      pruneThreshold: config.pruneThreshold ?? 0.1,
      autoConsolidate: config.autoConsolidate ?? false,
      minTrust: config.minTrust ?? 0.2,
      poisonBreadthThreshold: config.poisonBreadthThreshold ?? 12,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Storage
  // ─────────────────────────────────────────────────────────────────────────────

  async store(
    content: string,
    options: {
      source: string;
      type: MemoryType;
      importance?: number;
      tags?: string[];
      associations?: string[];
      ttl?: number;
      /** Caller-asserted trust 0-1. Defaults to DEFAULT_TRUST. Auto-penalized on injection. */
      trust?: number;
      metadata?: Record<string, unknown>;
    }
  ): Promise<MemoryEntry> {
    // Store-time poisoning check. Content that carries injection patterns is
    // not refused (it may be legitimately quoting an attack) but is written
    // with low trust and flagged, so retrieval will not surface it.
    const { injectionDetected } = sanitizeInput(content, `memory-store:${options.source}`);
    let trust = Math.max(0, Math.min(1, options.trust ?? DEFAULT_TRUST));
    let flagged = false;
    if (injectionDetected) {
      trust = Math.min(trust, INJECTION_TRUST);
      flagged = true;
      eventBus.emit('memory:longterm:poisoning_suspected', {
        source: options.source,
        type: options.type,
        reason: 'injection_patterns_at_store',
      });
    }

    // Generate embedding if provider available
    let embedding: number[] | undefined;
    if (this.embedding) {
      try {
        embedding = await this.embedding.embed(content);
      } catch (error) {
        // Continue without embedding
        eventBus.emit('memory:longterm:embedding:failed', { error: String(error) });
      }
    }

    const entry = await this.adapter.store({
      content,
      embedding,
      metadata: {
        source: options.source,
        type: options.type,
        importance: options.importance ?? 0.5,
        tags: options.tags,
        associations: options.associations,
        ...options.metadata,
        // Security fields last — caller metadata cannot override trust/flag.
        trust,
        ...(flagged ? { flagged: true } : {}),
      },
      expiresAt: options.ttl ? Date.now() + options.ttl : undefined,
    });
    
    eventBus.emit('memory:longterm:stored', { id: entry.id, type: options.type });
    
    // Check if we need to prune
    const count = await this.adapter.count();
    if (count > this.config.maxEntries) {
      await this.prune();
    }
    
    return entry;
  }

  async storeFact(content: string, source: string, tags?: string[]): Promise<MemoryEntry> {
    return this.store(content, { source, type: 'fact', tags, importance: 0.7 });
  }

  async storeEvent(content: string, source: string, tags?: string[]): Promise<MemoryEntry> {
    return this.store(content, { source, type: 'event', tags, importance: 0.5 });
  }

  async storeDecision(
    content: string,
    source: string,
    context: { reasoning?: string; confidence?: number; outcome?: string }
  ): Promise<MemoryEntry> {
    return this.store(content, {
      source,
      type: 'decision',
      importance: 0.8,
      metadata: context,
    });
  }

  async storePattern(content: string, source: string, frequency: number): Promise<MemoryEntry> {
    return this.store(content, {
      source,
      type: 'pattern',
      importance: Math.min(0.5 + (frequency * 0.1), 1),
      metadata: { frequency },
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Retrieval
  // ─────────────────────────────────────────────────────────────────────────────

  async get(id: string): Promise<MemoryEntry | null> {
    return this.adapter.get(id);
  }

  async search(query: MemoryQuery): Promise<MemoryResult[]> {
    const wantLimit = query.limit;

    if (query.ignoreTrust) {
      // Maintenance/stats path — no trust filtering, original semantics.
      if (query.text && this.embedding) return this.semanticSearch(query.text, query);
      return this.adapter.search(query);
    }

    // Over-fetch so trust filtering / poisoning exclusion can drop entries
    // without starving a small result set.
    const expanded: MemoryQuery = wantLimit
      ? { ...query, limit: Math.max(wantLimit * 5, 50) }
      : query;

    const ranked =
      query.text && this.embedding
        ? await this.semanticSearch(query.text, expanded)
        : await this.adapter.search(expanded);

    if (query.text) {
      await this.detectPoisonBreadth(query.text, ranked);
    }

    const trusted = this.applyTrust(ranked, query);
    return wantLimit ? trusted.slice(0, wantLimit) : trusted;
  }

  // Weight relevance by per-entry trust and drop flagged / sub-floor entries.
  // A poisoned entry that scores high on keyword overlap but carries low
  // trust now ranks below — or is excluded entirely beneath — legitimate
  // content of equal lexical relevance.
  private applyTrust(results: MemoryResult[], query: MemoryQuery): MemoryResult[] {
    const floor = query.minTrust ?? this.config.minTrust;
    return results
      .filter((r) => r.entry.metadata.flagged !== true)
      .map((r) => {
        const trust = Math.max(0, Math.min(1, r.entry.metadata.trust ?? DEFAULT_TRUST));
        return { result: { ...r, relevance: (r.relevance ?? 1) * trust }, trust };
      })
      .filter((x) => x.trust >= floor)
      .map((x) => x.result)
      .sort((a, b) => (b.relevance ?? 0) - (a.relevance ?? 0));
  }

  private normalizeQuery(text: string): string {
    return text.toLowerCase().trim().replace(/\s+/g, ' ').slice(0, 256);
  }

  // Poisoning heuristic: an entry that is a near-exact match for many
  // *distinct* queries is keyword-stuffed to match everything. Flag it,
  // crater its trust, and persist that so it stays excluded.
  private async detectPoisonBreadth(text: string, ranked: MemoryResult[]): Promise<void> {
    const threshold = this.config.poisonBreadthThreshold;
    if (threshold <= 0 || ranked.length < 3) return;

    const top = ranked[0];
    if ((top.relevance ?? 0) < BREADTH_RELEVANCE_MIN) return;
    if (top.entry.metadata.flagged === true) return;

    const id = top.entry.id;
    let set = this.breadthByEntry.get(id);
    if (!set) {
      if (this.breadthByEntry.size >= LongTermMemory.MAX_BREADTH_ENTRIES) {
        // Evict the oldest tracked entry — bounded memory.
        const oldest = this.breadthByEntry.keys().next().value;
        if (oldest !== undefined) this.breadthByEntry.delete(oldest);
      }
      set = new Set<string>();
      this.breadthByEntry.set(id, set);
    }
    if (set.size < LongTermMemory.MAX_BREADTH_QUERIES_PER_ENTRY) {
      set.add(this.normalizeQuery(text));
    }

    if (set.size > threshold) {
      await this.adapter.update(id, {
        metadata: { ...top.entry.metadata, flagged: true, trust: POISON_TRUST },
      });
      this.breadthByEntry.delete(id);
      eventBus.emit('memory:longterm:poisoning_detected', {
        id,
        source: top.entry.metadata.source,
        distinctQueries: threshold + 1,
        reason: 'keyword_breadth',
      });
    }
  }

  private async semanticSearch(text: string, query: MemoryQuery): Promise<MemoryResult[]> {
    if (!this.embedding) {
      return this.adapter.search(query);
    }
    
    try {
      const queryEmbedding = await this.embedding.embed(text);
      
      // Get all potentially matching entries
      const candidates = await this.adapter.search({
        ...query,
        text: undefined, // Remove text, we'll do vector comparison
        limit: (query.limit || 10) * 5, // Get more candidates for re-ranking
      });
      
      // Calculate vector similarity and re-rank
      const ranked = candidates
        .map(result => {
          const distance = result.entry.embedding
            ? this.cosineSimilarity(queryEmbedding, result.entry.embedding)
            : 0;
          return {
            ...result,
            relevance: distance,
            distance: 1 - distance,
          };
        })
        .filter(r => !query.minRelevance || r.relevance >= query.minRelevance)
        .sort((a, b) => b.relevance - a.relevance)
        .slice(0, query.limit || 10);
      
      return ranked;
    } catch (error) {
      // Fallback to text search
      return this.adapter.search(query);
    }
  }

  private cosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length) return 0;
    
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    
    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    
    const denominator = Math.sqrt(normA) * Math.sqrt(normB);
    return denominator === 0 ? 0 : dotProduct / denominator;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Recall Helpers
  // ─────────────────────────────────────────────────────────────────────────────

  async recall(query: string, limit = 5): Promise<string[]> {
    const results = await this.search({ text: query, limit });
    return results.map(r => r.entry.content);
  }

  async recallByType(type: MemoryType, limit = 10): Promise<MemoryEntry[]> {
    const results = await this.search({ filter: { type }, limit });
    return results.map(r => r.entry);
  }

  async recallRecent(limit = 10): Promise<MemoryEntry[]> {
    const results = await this.search({ limit });
    return results
      .map(r => r.entry)
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, limit);
  }

  async recallBySource(source: string, limit = 10): Promise<MemoryEntry[]> {
    const results = await this.search({ filter: { source }, limit });
    return results.map(r => r.entry);
  }

  async recallRelated(entryId: string, limit = 5): Promise<MemoryEntry[]> {
    const entry = await this.get(entryId);
    if (!entry) return [];
    
    // Search by content similarity
    const results = await this.search({ text: entry.content, limit: limit + 1 });
    
    // Filter out the original entry
    return results
      .filter(r => r.entry.id !== entryId)
      .slice(0, limit)
      .map(r => r.entry);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Update & Delete
  // ─────────────────────────────────────────────────────────────────────────────

  async update(id: string, updates: { content?: string; importance?: number; tags?: string[] }): Promise<MemoryEntry | null> {
    const entry = await this.adapter.get(id);
    if (!entry) return null;
    
    const updateData: Partial<MemoryEntry> = {};
    
    if (updates.content) {
      updateData.content = updates.content;
      // Re-embed if content changed
      if (this.embedding) {
        try {
          updateData.embedding = await this.embedding.embed(updates.content);
        } catch {}
      }
    }
    
    if (updates.importance !== undefined || updates.tags) {
      updateData.metadata = {
        ...entry.metadata,
        ...(updates.importance !== undefined && { importance: updates.importance }),
        ...(updates.tags && { tags: updates.tags }),
      };
    }
    
    return this.adapter.update(id, updateData);
  }

  async reinforce(id: string, amount = 0.1): Promise<void> {
    const entry = await this.adapter.get(id);
    if (!entry) return;
    
    const newImportance = Math.min((entry.metadata.importance || 0.5) + amount, 1);
    await this.adapter.update(id, {
      metadata: { ...entry.metadata, importance: newImportance },
    });
    
    eventBus.emit('memory:longterm:reinforced', { id, importance: newImportance });
  }

  async forget(id: string): Promise<boolean> {
    const deleted = await this.adapter.delete(id);
    if (deleted) {
      eventBus.emit('memory:longterm:forgotten', { id });
    }
    return deleted;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Maintenance
  // ─────────────────────────────────────────────────────────────────────────────

  async prune(): Promise<number> {
    const pruned = await this.adapter.prune({
      minImportance: this.config.pruneThreshold,
    });
    
    eventBus.emit('memory:longterm:pruned', { count: pruned });
    return pruned;
  }

  async consolidate(): Promise<number> {
    // TODO: Implement memory consolidation
    // Find similar memories and merge them
    // This is complex and requires careful implementation
    return 0;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Stats
  // ─────────────────────────────────────────────────────────────────────────────

  async stats(): Promise<{
    total: number;
    byType: Record<MemoryType, number>;
    bySource: Record<string, number>;
  }> {
    const total = await this.adapter.count();
    
    const byType: Record<string, number> = {};
    const bySource: Record<string, number> = {};
    
    const allResults = await this.adapter.search({ limit: 10000 });
    
    for (const result of allResults) {
      const type = result.entry.metadata.type;
      const source = result.entry.metadata.source;
      
      byType[type] = (byType[type] || 0) + 1;
      bySource[source] = (bySource[source] || 0) + 1;
    }
    
    return { total, byType: byType as Record<MemoryType, number>, bySource };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Embedding Provider Management
  // ─────────────────────────────────────────────────────────────────────────────

  setEmbeddingProvider(provider: EmbeddingProvider): void {
    this.embedding = provider;
  }

  hasEmbedding(): boolean {
    return this.embedding !== null;
  }
}

// Singleton export
export const longTermMemory = new LongTermMemory();
