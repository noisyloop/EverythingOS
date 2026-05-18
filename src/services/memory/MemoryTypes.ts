// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Memory Types
// Shared interfaces for all memory systems
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Memory entry - the fundamental unit of memory
 */
export interface MemoryEntry {
  id: string;
  content: string;
  embedding?: number[];
  metadata: MemoryMetadata;
  createdAt: number;
  updatedAt: number;
  expiresAt?: number;
}

export interface MemoryMetadata {
  source: string;           // Agent or system that created this
  type: MemoryType;
  tags?: string[];
  importance?: number;      // 0-1, used for pruning
  accessCount?: number;
  lastAccessedAt?: number;
  associations?: string[];  // IDs of related memories
  /**
   * Trust score 0-1. Retrieval weights relevance by this and excludes
   * entries below the trust floor. Lowered automatically when store-time
   * injection patterns are detected or poisoning breadth is suspected.
   * Absent on legacy entries — treated as the default trust.
   */
  trust?: number;
  /** Set when the entry tripped a poisoning heuristic. Flagged entries are excluded from recall. */
  flagged?: boolean;
  [key: string]: unknown;
}

export type MemoryType = 
  | 'fact'           // Discrete piece of information
  | 'event'          // Something that happened
  | 'conversation'   // Message in a conversation
  | 'decision'       // A decision that was made
  | 'outcome'        // Result of an action
  | 'preference'     // User or system preference
  | 'pattern'        // Learned pattern
  | 'summary';       // Compressed information

/**
 * Query options for memory retrieval
 */
export interface MemoryQuery {
  text?: string;            // Semantic search
  filter?: MemoryFilter;
  limit?: number;
  offset?: number;
  minRelevance?: number;    // 0-1 threshold for semantic search
  includeExpired?: boolean;
  /** Override the configured trust floor for this query (0-1). */
  minTrust?: number;
  /** Bypass trust weighting/filtering — for maintenance/stats paths only. */
  ignoreTrust?: boolean;
}

export interface MemoryFilter {
  source?: string | string[];
  type?: MemoryType | MemoryType[];
  tags?: string[];
  since?: number;
  until?: number;
  minImportance?: number;
}

/**
 * Result from memory queries
 */
export interface MemoryResult {
  entry: MemoryEntry;
  relevance?: number;       // 0-1, how relevant to query
  distance?: number;        // Vector distance (lower = more similar)
}

/**
 * Memory adapter interface - implement this for different backends
 */
export interface MemoryAdapter {
  name: string;
  
  // CRUD
  store(entry: Omit<MemoryEntry, 'id' | 'createdAt' | 'updatedAt'>): Promise<MemoryEntry>;
  get(id: string): Promise<MemoryEntry | null>;
  update(id: string, updates: Partial<MemoryEntry>): Promise<MemoryEntry | null>;
  delete(id: string): Promise<boolean>;
  
  // Query
  search(query: MemoryQuery): Promise<MemoryResult[]>;
  
  // Maintenance
  prune(filter: MemoryFilter): Promise<number>;
  clear(): Promise<void>;
  count(filter?: MemoryFilter): Promise<number>;
}

/**
 * Embedding provider interface
 */
export interface EmbeddingProvider {
  name: string;
  dimensions: number;
  embed(text: string): Promise<number[]>;
  embedBatch(texts: string[]): Promise<number[][]>;
}

/**
 * Memory layer configuration
 */
export interface MemoryLayerConfig {
  adapter: MemoryAdapter;
  embedding?: EmbeddingProvider;
  maxEntries?: number;
  defaultTTL?: number;      // Time to live in ms
  pruneInterval?: number;   // Auto-prune interval in ms
}

/**
 * Conversation turn for episodic memory
 */
export interface ConversationTurn {
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

/**
 * Conversation summary
 */
export interface ConversationSummary {
  conversationId: string;
  summary: string;
  keyPoints: string[];
  participants: string[];
  startedAt: number;
  endedAt: number;
  turnCount: number;
}
