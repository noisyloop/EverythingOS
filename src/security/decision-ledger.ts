/**
 * Decision Ledger — Verifiable Provenance for Agent Decisions
 *
 * NIST AI RMF 1.0 — MEASURE (MS-2.5, MS-2.6), MANAGE (MG-2.2)
 * NIST AI 600-1 — Accountability, Information Integrity, Traceability
 *
 * The audit log records THAT a decision happened.
 * The decision ledger records WHAT made it: model version, prompt template
 * hash, retrieval corpus fingerprint, inference parameters, and output hash.
 *
 * Every entry is content-addressed — the ledger ID is a hash of all inputs,
 * so identical inputs always produce the same ID. This makes decisions
 * reproducible and tamper-detectable.
 *
 * An investigator can take any ledger entry and reconstruct the exact
 * context that produced a decision — even years after the fact.
 * That's what separates "we log decisions" from "we can prove decisions."
 *
 * Usage:
 *   import { DecisionLedger } from '../security/decision-ledger';
 *
 *   // Before calling LLM:
 *   const context = DecisionLedger.buildContext({
 *     modelId: 'claude-sonnet-4-20250514',
 *     promptTemplate: MY_PROMPT_TEMPLATE,
 *     retrievalCorpus: ragDocumentIds,
 *     parameters: { temperature: 0.7, maxTokens: 1000 },
 *   });
 *
 *   // After receiving response:
 *   const entry = DecisionLedger.record({
 *     agentId: 'trading-agent',
 *     decisionType: 'trade.signal',
 *     context,
 *     inputHash: hashContent(userPrompt),
 *     outputHash: hashContent(llmResponse),
 *     outcome: { action: 'buy', ticker: 'BTC', confidence: 0.82 },
 *   });
 *
 *   // Verify integrity later:
 *   const verified = DecisionLedger.verify(entry.ledgerId);
 */

import { createHash } from 'crypto';
import { createInterface } from 'readline';
import { createReadStream, createWriteStream, existsSync, readFileSync, writeFileSync, WriteStream } from 'fs';
import { resolve } from 'path';
import { AuditLogger, hashContent } from './audit-log';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type DecisionType =
  | 'llm.completion'     // Generic LLM call
  | 'agent.think'        // Agent think() pipeline call
  | 'trade.signal'       // Trading signal generation
  | 'trade.execution'    // Trade execution approval
  | 'deploy.approval'    // Deployment approval decision
  | 'robotics.command'   // Robotics motion or actuation command
  | 'content.moderation' // Content moderation decision
  | 'routing.decision'   // Agent routing or workflow branching
  | 'approval.gate'      // ApprovalGate approve/deny decision
  | 'rag.synthesis'      // RAG retrieval + synthesis decision
  | string;              // Custom decision types

/**
 * Provenance context for a single LLM call.
 * Built BEFORE the call is made, so it captures intent alongside output.
 */
export interface DecisionContext {
  /** Full model identifier as sent to the provider API */
  modelId: string;
  /** SHA-256 of modelId — stable reference, detects silent model version changes */
  modelHash: string;

  /** The prompt template (not the filled prompt — the template or a version ID) */
  promptTemplate: string;
  /** SHA-256 of the prompt template — changes are detectable across entries */
  promptTemplateHash: string;

  /**
   * For RAG-enabled agents: document IDs or chunk hashes included in context.
   * Leave as empty array if no retrieval was used.
   */
  retrievalCorpus: string[];
  /** SHA-256 of sorted corpus IDs — changes when any document in the set changes */
  retrievalCorpusHash: string;

  /** Raw inference parameters sent to the API (temperature, max_tokens, etc.) */
  parameters: Record<string, unknown>;
  /** SHA-256 of JSON.stringify(parameters) */
  parametersHash: string;

  /**
   * Policy version in effect at decision time.
   * Tie to a semantic version or git commit hash of your policy files.
   * Defaults to EOS_POLICY_VERSION env var, or 'unversioned'.
   */
  policyVersion: string;

  /** ISO 8601 timestamp when this context was built (pre-call) */
  contextBuiltAt: string;
}

export interface DecisionLedgerInput {
  agentId: string;
  decisionType: DecisionType;
  context: DecisionContext;
  /** SHA-256 of the filled prompt sent to the LLM — use hashContent() */
  inputHash: string;
  /** SHA-256 of the raw LLM response — use hashContent() */
  outputHash: string;
  /**
   * Structured outcome of the decision. Keep PII-free.
   * Examples: { action: 'buy', confidence: 0.82 }
   *           { nextAgent: 'executor', reason: 'approved' }
   */
  outcome?: Record<string, unknown>;
  /** Duration of the LLM call in ms */
  durationMs?: number;
  /** Token usage as reported by the provider */
  tokenUsage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
}

export interface LedgerEntry extends DecisionLedgerInput {
  /**
   * Content-addressed identifier.
   * SHA-256 of: agentId + decisionType + inputHash + modelHash
   *           + promptTemplateHash + retrievalCorpusHash + parametersHash + contextBuiltAt
   *
   * Identical inputs → identical ledgerId.
   * Any input change → different ledgerId. Tamper-detectable.
   */
  ledgerId: string;
  recordedAt: string;
  recordedAtMs: number;
  /**
   * Hash of the previous ledger entry, forming a tamper-evident chain
   * (STRIDE T-4). 'GENESIS' for the first entry. Deleting or reordering any
   * entry breaks the next entry's link. Absent on legacy entries written
   * before the chain existed — verifyChain() tolerates those.
   */
  previousHash: string;
  entryHash: string;
}

export interface LedgerVerificationResult {
  valid: boolean;
  ledgerId: string;
  reason?: string;
  computedHash?: string;
  storedHash?: string;
}

export interface LedgerChainResult {
  valid: boolean;
  totalEntries: number;
  /** 0-based index of the entry where the chain broke, if any */
  brokenAt?: number;
  reason?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage
// ─────────────────────────────────────────────────────────────────────────────

const LEDGER_FILE_PATH = resolve(
  process.env.DECISION_LEDGER_PATH ?? './everythingos-decisions.jsonl'
);

const INDEX_LIMIT = 50_000;
const ledgerIndex = new Map<string, LedgerEntry>();

// Head of the tamper-evident chain (STRIDE T-4). Bootstrapped from the last
// entry on disk in initialize() so appends keep chaining across restarts.
let lastEntryHash = 'GENESIS';

// ─────────────────────────────────────────────────────────────────────────────
// Async write stream — non-blocking disk I/O (mirrors audit-log.ts pattern)
// ─────────────────────────────────────────────────────────────────────────────

let ledgerStream: WriteStream | null = null;

function getLedgerStream(): WriteStream {
  if (!ledgerStream || ledgerStream.destroyed) {
    ledgerStream = createWriteStream(LEDGER_FILE_PATH, { flags: 'a', encoding: 'utf8' });
    ledgerStream.on('error', (err) => {
      console.error('[DecisionLedger] Write stream error:', err);
    });
  }
  return ledgerStream;
}

export function flushDecisionLedger(): Promise<void> {
  return new Promise((res) => {
    if (!ledgerStream || ledgerStream.destroyed) { res(); return; }
    ledgerStream.end(() => { ledgerStream = null; res(); });
  });
}

process.once('exit', () => { if (ledgerStream && !ledgerStream.destroyed) ledgerStream.end(); });
process.once('SIGINT', async () => { await flushDecisionLedger(); });
process.once('SIGTERM', async () => { await flushDecisionLedger(); });

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function computeLedgerId(input: DecisionLedgerInput): string {
  const parts = [
    input.agentId,
    input.decisionType,
    input.inputHash,
    input.context.modelHash,
    input.context.promptTemplateHash,
    input.context.retrievalCorpusHash,
    input.context.parametersHash,
    input.context.contextBuiltAt,
  ].join('|');
  return sha256(parts);
}

function computeEntryHash(entry: Omit<LedgerEntry, 'entryHash'>): string {
  return sha256(JSON.stringify(entry));
}

function persist(entry: LedgerEntry): void {
  const stream = getLedgerStream();
  stream.write(JSON.stringify(entry) + '\n', (err) => {
    if (err) console.error('[DecisionLedger] Failed to write entry seq=' + entry.ledgerId.slice(0, 8) + ':', err);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// DecisionLedger
// ─────────────────────────────────────────────────────────────────────────────

export const DecisionLedger = {
  /**
   * Build a provenance context BEFORE making an LLM call.
   * contextBuiltAt reflects when the decision was initiated, not when it resolved.
   */
  buildContext({
    modelId,
    promptTemplate,
    retrievalCorpus = [],
    parameters = {},
    policyVersion,
  }: {
    modelId: string;
    promptTemplate: string;
    retrievalCorpus?: string[];
    parameters?: Record<string, unknown>;
    policyVersion?: string;
  }): DecisionContext {
    const sortedCorpus = [...retrievalCorpus].sort();
    return {
      modelId,
      modelHash: sha256(modelId),
      promptTemplate,
      promptTemplateHash: sha256(promptTemplate),
      retrievalCorpus: sortedCorpus,
      retrievalCorpusHash: sha256(sortedCorpus.join('|')),
      parameters,
      parametersHash: sha256(JSON.stringify(parameters)),
      policyVersion: policyVersion ?? process.env.EOS_POLICY_VERSION ?? 'unversioned',
      contextBuiltAt: new Date().toISOString(),
    };
  },

  /**
   * Record a decision in the ledger.
   * Call immediately after receiving the LLM response.
   * Returns the fully resolved LedgerEntry including its content-addressed ledgerId.
   */
  record(input: DecisionLedgerInput): LedgerEntry {
    const now = new Date();
    const ledgerId = computeLedgerId(input);

    const partial: Omit<LedgerEntry, 'entryHash'> = {
      ...input,
      ledgerId,
      recordedAt: now.toISOString(),
      recordedAtMs: now.getTime(),
      previousHash: lastEntryHash,
    };

    const entry: LedgerEntry = { ...partial, entryHash: computeEntryHash(partial) };
    lastEntryHash = entry.entryHash;

    // Index in memory — evict oldest if over limit
    if (ledgerIndex.size >= INDEX_LIMIT) {
      const oldestKey = ledgerIndex.keys().next().value;
      if (oldestKey) ledgerIndex.delete(oldestKey);
    }
    ledgerIndex.set(ledgerId, entry);

    persist(entry);

    // Cross-reference with audit log — the two records link via ledgerId
    AuditLogger.log({
      agentId: input.agentId,
      event: 'llm.call',
      inputHash: input.inputHash,
      outputHash: input.outputHash,
      metadata: {
        ledgerId,
        decisionType: input.decisionType,
        modelHash: input.context.modelHash,
        promptTemplateHash: input.context.promptTemplateHash,
        policyVersion: input.context.policyVersion,
        durationMs: input.durationMs,
        totalTokens: input.tokenUsage?.totalTokens,
      },
    });

    return entry;
  },

  /**
   * Retrieve a ledger entry by its content-addressed ID.
   * Checks in-memory index first, then falls back to disk scan.
   */
  get(ledgerId: string): LedgerEntry | null {
    const cached = ledgerIndex.get(ledgerId);
    if (cached) return cached;

    if (!existsSync(LEDGER_FILE_PATH)) return null;

    const lines = readFileSync(LEDGER_FILE_PATH, 'utf8')
      .split('\n')
      .filter((l) => l.trim().length > 0);

    for (const line of lines) {
      try {
        const entry = JSON.parse(line) as LedgerEntry;
        if (entry.ledgerId === ledgerId) return entry;
      } catch {
        // Skip malformed lines
      }
    }

    return null;
  },

  /**
   * Verify the integrity of a ledger entry.
   * Recomputes entryHash from stored fields and checks it matches.
   * Also verifies ledgerId is consistent with the stored inputs.
   * A mismatch means the entry was modified after recording.
   */
  verify(ledgerId: string): LedgerVerificationResult {
    const entry = this.get(ledgerId);
    if (!entry) return { valid: false, ledgerId, reason: 'Entry not found' };

    const { entryHash, ...rest } = entry;
    const computedHash = computeEntryHash(rest);

    if (computedHash !== entryHash) {
      return {
        valid: false,
        ledgerId,
        reason: 'Entry hash mismatch — content may have been modified after recording',
        computedHash,
        storedHash: entryHash,
      };
    }

    const computedLedgerId = computeLedgerId(entry);
    if (computedLedgerId !== ledgerId) {
      return {
        valid: false,
        ledgerId,
        reason: 'LedgerId mismatch — input fields may have been altered',
      };
    }

    return { valid: true, ledgerId };
  },

  /**
   * Verify the whole-ledger tamper-evident chain (STRIDE T-4). Streams the
   * file (no OOM, STRIDE D-4) and fails closed on the first broken link:
   *   - a recomputed entryHash that doesn't match (content tampered), or
   *   - a previousHash that doesn't match the prior entry's hash (an entry
   *     was deleted, reordered, or inserted).
   * Legacy entries written before the chain existed have no `previousHash`;
   * their per-entry hash is still checked but the link check is skipped, and
   * the chain is enforced strictly from the first chained entry onward.
   */
  async verifyChain(): Promise<LedgerChainResult> {
    if (!existsSync(LEDGER_FILE_PATH)) return { valid: true, totalEntries: 0 };

    let running = 'GENESIS';
    let totalEntries = 0;

    const rl = createInterface({
      input: createReadStream(LEDGER_FILE_PATH, { encoding: 'utf8' }),
      crlfDelay: Infinity,
    });

    for await (const rawLine of rl) {
      const line = rawLine.trim();
      if (!line) continue;

      let entry: LedgerEntry;
      try {
        entry = JSON.parse(line) as LedgerEntry;
      } catch {
        rl.close();
        return {
          valid: false,
          totalEntries,
          brokenAt: totalEntries,
          reason: `JSON parse error at entry ${totalEntries + 1}`,
        };
      }

      const { entryHash, ...rest } = entry;
      if (computeEntryHash(rest) !== entryHash) {
        rl.close();
        return {
          valid: false,
          totalEntries,
          brokenAt: totalEntries,
          reason: `Entry hash mismatch at entry ${totalEntries + 1} — content modified after recording`,
        };
      }

      // Link check only for chained entries. Legacy entries (no previousHash)
      // are content-verified above; the chain resumes from their hash.
      if (typeof entry.previousHash === 'string') {
        if (entry.previousHash !== running) {
          rl.close();
          return {
            valid: false,
            totalEntries,
            brokenAt: totalEntries,
            reason: `Chain broken at entry ${totalEntries + 1} — previousHash does not match (entry deleted, reordered, or inserted)`,
          };
        }
      }

      running = entryHash;
      totalEntries++;
    }

    return { valid: true, totalEntries };
  },

  /**
   * Query the in-memory index. For full historical queries use queryDisk().
   */
  query(filter: {
    agentId?: string;
    decisionType?: DecisionType;
    modelHash?: string;
    promptTemplateHash?: string;
    policyVersion?: string;
    since?: number;
    until?: number;
    limit?: number;
  }): LedgerEntry[] {
    let results = Array.from(ledgerIndex.values());

    if (filter.agentId) results = results.filter((e) => e.agentId === filter.agentId);
    if (filter.decisionType) results = results.filter((e) => e.decisionType === filter.decisionType);
    if (filter.modelHash) results = results.filter((e) => e.context.modelHash === filter.modelHash);
    if (filter.promptTemplateHash) results = results.filter((e) => e.context.promptTemplateHash === filter.promptTemplateHash);
    if (filter.policyVersion) results = results.filter((e) => e.context.policyVersion === filter.policyVersion);
    if (filter.since) results = results.filter((e) => e.recordedAtMs >= filter.since!);
    if (filter.until) results = results.filter((e) => e.recordedAtMs <= filter.until!);

    results.sort((a, b) => b.recordedAtMs - a.recordedAtMs);
    if (filter.limit) results = results.slice(0, filter.limit);

    return results;
  },

  /**
   * Full disk scan — streams the file to avoid loading large ledgers into memory (STRIDE D-4).
   * Use for historical analysis or audit exports.
   */
  async queryDisk(filter: {
    agentId?: string;
    decisionType?: DecisionType;
    since?: number;
    until?: number;
    limit?: number;
  }): Promise<LedgerEntry[]> {
    if (!existsSync(LEDGER_FILE_PATH)) return [];

    const results: LedgerEntry[] = [];

    const rl = createInterface({
      input: createReadStream(LEDGER_FILE_PATH, { encoding: 'utf8' }),
      crlfDelay: Infinity,
    });

    for await (const rawLine of rl) {
      const line = rawLine.trim();
      if (!line) continue;
      try {
        const entry = JSON.parse(line) as LedgerEntry;
        if (filter.agentId && entry.agentId !== filter.agentId) continue;
        if (filter.decisionType && entry.decisionType !== filter.decisionType) continue;
        if (filter.since && entry.recordedAtMs < filter.since) continue;
        if (filter.until && entry.recordedAtMs > filter.until) continue;
        results.push(entry);
        if (filter.limit && results.length >= filter.limit) break;
      } catch {
        // Skip malformed lines
      }
    }

    return results;
  },

  /**
   * Detect entries where the model hash differs from a reference.
   * Useful for alerting when an LLM provider silently updates a model.
   */
  detectModelDrift(referenceModelHash: string, agentId?: string): LedgerEntry[] {
    return this.query({ agentId }).filter(
      (e) => e.context.modelHash !== referenceModelHash
    );
  },

  /**
   * Detect entries where the prompt template hash differs from a reference.
   * Catches unauthorized prompt changes.
   */
  detectPromptDrift(referenceTemplateHash: string, agentId?: string): LedgerEntry[] {
    return this.query({ agentId }).filter(
      (e) => e.context.promptTemplateHash !== referenceTemplateHash
    );
  },

  /** Summary statistics for monitoring dashboards */
  stats(): {
    totalInMemory: number;
    uniqueModels: number;
    uniquePromptTemplates: number;
    uniqueAgents: number;
    decisionTypes: Record<string, number>;
    avgDurationMs: number | null;
  } {
    const entries = Array.from(ledgerIndex.values());
    const typeCounts: Record<string, number> = {};
    for (const e of entries) {
      typeCounts[e.decisionType] = (typeCounts[e.decisionType] ?? 0) + 1;
    }
    const durations = entries.filter((e) => e.durationMs !== undefined).map((e) => e.durationMs!);

    return {
      totalInMemory: entries.length,
      uniqueModels: new Set(entries.map((e) => e.context.modelHash)).size,
      uniquePromptTemplates: new Set(entries.map((e) => e.context.promptTemplateHash)).size,
      uniqueAgents: new Set(entries.map((e) => e.agentId)).size,
      decisionTypes: typeCounts,
      avgDurationMs: durations.length > 0
        ? durations.reduce((a, b) => a + b, 0) / durations.length
        : null,
    };
  },

  initialize(): void {
    if (ledgerStream && !ledgerStream.destroyed) {
      ledgerStream.end();
      ledgerStream = null;
    }
    if (!existsSync(LEDGER_FILE_PATH)) {
      writeFileSync(LEDGER_FILE_PATH, '', { encoding: 'utf8' });
      lastEntryHash = 'GENESIS';
      return;
    }
    // Bootstrap the chain head from the last entry on disk so appends keep
    // chaining across restarts (STRIDE T-4).
    const lines = readFileSync(LEDGER_FILE_PATH, 'utf8')
      .split('\n')
      .filter((l) => l.trim().length > 0);
    lastEntryHash = 'GENESIS';
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const last = JSON.parse(lines[i]) as LedgerEntry;
        if (typeof last.entryHash === 'string' && last.entryHash) {
          lastEntryHash = last.entryHash;
          break;
        }
      } catch {
        // Skip trailing malformed lines; keep scanning backward.
      }
    }
  },
};

// Auto-initialize on import
DecisionLedger.initialize();

// Re-export hashContent so callers don't need a separate import to hash prompts
export { hashContent };
