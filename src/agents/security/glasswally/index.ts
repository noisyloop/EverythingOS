// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Glasswally Bridge
//
// Tails Glasswally's enforcement_actions.jsonl output, validates and sanitizes
// every record through the EverythingOS security pipeline, HMAC-verifies IOC
// bundles before trusting them, and routes everything into the SOC agent stack.
//
// Glasswally: https://github.com/noisyloop/glasswally
// Requires Glasswally running with: glasswally --output <outputDir>
// ═══════════════════════════════════════════════════════════════════════════════

import { openSync, readSync, closeSync, statSync, readdirSync, existsSync, lstatSync } from 'fs';
import { resolve, join, isAbsolute } from 'path';
import { createHmac, timingSafeEqual } from 'crypto';
import { z } from 'zod';
import { Agent, AgentConfig } from '../../../runtime/Agent';
import { AgentRiskTier } from '../../../types/agent-risk';
import { AgentManifest, validateManifest } from '../../../types/agent-manifest';
import { sanitizeInput } from '../../../security/sanitize';
import { AuditLogger } from '../../../security/audit-log';
import { getSecret } from '../../../security/secrets-provider';

export const MANIFEST: AgentManifest = validateManifest({
  id: 'glasswally',
  name: 'Glasswally Bridge',
  version: '1.0.0',
  category: 'security',
  description: 'Tails Glasswally enforcement decisions, verifies IOC bundle signatures, and routes distillation-attack alerts into the EverythingOS SOC pipeline.',
  capabilities: [
    'eventbus:publish',
    'filesystem:read',
    'ledger:write',
  ],
  trustLevel: AgentRiskTier.HIGH,
  tags: ['security', 'glasswally', 'distillation', 'ebpf', 'threat-intel', 'kernel'],
  author: 'EverythingOS',
  homepage: 'https://github.com/noisyloop/glasswally',
});

// ─────────────────────────────────────────────────────────────────────────────
// Glasswally wire-format schemas (Zod)
// Unknown fields are stripped by default — we never forward unvalidated data.
// ─────────────────────────────────────────────────────────────────────────────

const ActionTypeSchema = z.enum([
  'SuspendAccount',
  'ClusterTakedown',
  'RateLimit',
  'FlagForReview',
  'InjectCanary',
]);

type ActionType = z.infer<typeof ActionTypeSchema>;

/**
 * Maps Glasswally action types to EverythingOS alert severity.
 * Glasswally score tiers: Critical ≥0.85, High ≥0.72, Medium ≥0.52, Low ≥0.35
 */
const ACTION_SEVERITY: Record<ActionType, 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'> = {
  SuspendAccount:  'CRITICAL',
  ClusterTakedown: 'CRITICAL',
  InjectCanary:    'HIGH',
  RateLimit:       'MEDIUM',
  FlagForReview:   'LOW',
};

// Glasswally composite_score thresholds → human-readable tier label
const SCORE_TIER = [
  { min: 0.85, label: 'critical' },
  { min: 0.72, label: 'high' },
  { min: 0.52, label: 'medium' },
  { min: 0.35, label: 'low' },
  { min: 0,    label: 'info' },
] as const;

const EnforcementActionSchema = z.object({
  action_type:       ActionTypeSchema,
  account_id:        z.string().min(1).max(256),
  cluster_id:        z.string().max(256).optional(),
  affected_accounts: z.array(z.string().max(256)).max(10_000).default([]),
  reason:            z.string().max(2048),
  evidence:          z.array(z.string().max(512)).max(100).default([]),
  composite_score:   z.number().min(0).max(1),
  canary_token:      z.string().max(512).optional(),
  timestamp:         z.string().max(64),
});

const IocBundleSchema = z.object({
  cluster_id:        z.string().max(256),
  ips:               z.array(z.string().max(45)).max(100_000).default([]),
  subnets:           z.array(z.string().max(50)).max(10_000).default([]),
  tls_fingerprints:  z.array(z.string().max(128)).max(100_000).default([]),
  account_ids:       z.array(z.string().max(256)).max(1_000_000).default([]),
  confidence:        z.number().min(0).max(1),
  timestamp:         z.string().max(64),
  // HMAC-SHA256 over the bundle data (excluding this field) — 64 hex chars
  hmac:              z.string().regex(/^[a-f0-9]{64}$/),
});

type IocBundle = z.infer<typeof IocBundleSchema>;

// IOC bundle filenames must match this pattern — prevents directory traversal
// Glasswally generates: ioc_bundle_<cluster_id>.json
const IOC_BUNDLE_PATTERN = /^ioc_bundle_[a-zA-Z0-9_-]{1,100}\.json$/;

// Per-tick read cap — prevents memory exhaustion if Glasswally backfills a large file
const MAX_BYTES_PER_TICK = 1024 * 1024; // 1 MB

// Maximum JSONL line size accepted — well below Glasswally's 4 MB internal limit
const MAX_LINE_BYTES = 65_536; // 64 KB

// Maximum bytes the partial-line buffer may hold between ticks. A single
// physical line larger than this can never be a valid record (records are
// capped at MAX_LINE_BYTES), so it is treated as unrecoverable. Without this
// cap a Glasswally write that never emits a newline — a truncated mid-entry
// write, or a compromised Glasswally — grows lineBuffer by up to
// MAX_BYTES_PER_TICK every tick, unbounded, exhausting memory. (STRIDE D-6)
const MAX_LINE_BUFFER = 1024 * 1024; // 1 MB

// Maximum IOC bundle file size
const MAX_BUNDLE_BYTES = 50 * 1024 * 1024; // 50 MB

export interface GlasswallyAgentOptions {
  /**
   * Absolute path to Glasswally's --output directory.
   * GlasswallyAgent tails enforcement_actions.jsonl in this directory
   * and scans for ioc_bundle_*.json files.
   */
  outputDir: string;

  /**
   * HMAC-SHA256 secret for IOC bundle verification.
   * Must match the secret configured in Glasswally.
   * Falls back to GLASSWALLY_IOC_SECRET env var.
   * If not set, IOC bundles are logged but NOT forwarded to ThreatIntelAgent.
   */
  iocSecret?: string;

  /**
   * Maximum enforcement actions ingested per minute.
   * Protects against a malformed or compromised Glasswally output flooding the bus.
   * Default: 60
   */
  maxAlertsPerMinute?: number;

  /**
   * Tail enforcement_actions.jsonl from the beginning rather than the current end.
   * Useful for replay mode testing. Default: false
   */
  fromStart?: boolean;
}

export default class GlasswallyAgent extends Agent {
  private readonly outputDir: string;
  private readonly iocSecret: Buffer | null;
  private readonly maxAlertsPerMinute: number;
  private readonly fromStart: boolean;

  // File tailing state
  private enforcementOffset = 0;
  private lineBuffer = ''; // accumulates partial lines between reads
  // When an oversized physical line is discarded, bytes are dropped until the
  // next newline so parsing resumes cleanly at the following record.
  private skipOversizedLine = false;

  // Per-minute rate limiting for alert ingestion
  private alertCount = 0;
  private alertWindowStart = Date.now();

  // IOC bundle deduplication — track processed filenames so we never ingest twice
  private readonly processedBundles = new Set<string>();

  // Counters for glasswally:stats emissions
  private stats = {
    alerts_ingested: 0,
    alerts_dropped_schema: 0,
    alerts_dropped_rate: 0,
    ioc_bundles_verified: 0,
    ioc_bundles_rejected: 0,
  };

  constructor(options: GlasswallyAgentOptions, config?: Partial<AgentConfig>) {
    super({
      id: MANIFEST.id,
      name: MANIFEST.name,
      type: 'perception',
      description: MANIFEST.description,
      tickRate: 5_000, // tail every 5 seconds for near-real-time detection
      riskConfig: {
        tier: AgentRiskTier.HIGH,
        riskJustification: 'Ingests kernel-level enforcement decisions from Glasswally; HIGH for full audit trail on every alert forwarded into the SOC pipeline',
        requiresApproval: false,
        genAIRisks: {
          // reason/evidence fields can contain adversarial model output — sanitized before forwarding
          promptInjectionRisk: true,
          // account_ids and IPs are sensitive identifiers
          piiRisk: true,
          dataPrivacyRisk: true,
          informationIntegrityRisk: true,
          hallucinationRisk: false,
          harmfulContentRisk: false,
          physicalSafetyRisk: false,
        },
        allowedPublishChannels: [
          'alert:raw',           // → AlertTriageAgent
          'intel:ioc:bundle',    // → ThreatIntelAgent (verified IOC bundles only)
          'glasswally:enforcement', // → DecisionLedger record
          'glasswally:stats',
        ],
        allowedSubscribeChannels: [], // pulls from files, no EventBus subscriptions
        auditInputs: true,
        auditOutputs: true,
      },
      ...config,
    });

    this.outputDir = this.validateOutputDir(options.outputDir);
    this.maxAlertsPerMinute = options.maxAlertsPerMinute ?? 60;
    this.fromStart = options.fromStart ?? false;

    const secretStr = options.iocSecret ?? getSecret('GLASSWALLY_IOC_SECRET');
    this.iocSecret = secretStr ? Buffer.from(secretStr, 'utf-8') : null;

    if (!this.iocSecret) {
      console.warn(
        '[GlasswallyAgent] GLASSWALLY_IOC_SECRET is not set. ' +
        'IOC bundles will be logged but NOT forwarded to ThreatIntelAgent. ' +
        'Set this env var to the same HMAC secret configured in Glasswally.',
      );
    }
  }

  protected async onStart(): Promise<void> {
    const enforcementPath = join(this.outputDir, 'enforcement_actions.jsonl');

    if (!existsSync(enforcementPath)) {
      this.log('warn', 'enforcement_actions.jsonl not found — will begin tailing when Glasswally creates it');
      this.enforcementOffset = 0;
    } else if (this.fromStart) {
      this.enforcementOffset = 0;
    } else {
      // Seek to the current end — only process events that arrive after startup
      this.enforcementOffset = statSync(enforcementPath).size;
    }

    this.alertWindowStart = Date.now();
    this.log('info', `Glasswally bridge started — output dir: ${this.outputDir}`);
  }

  protected async onStop(): Promise<void> {
    this.log('info', 'Glasswally bridge stopped', {
      ...this.stats,
      bundles_seen: this.processedBundles.size,
    });
  }

  protected async onTick(): Promise<void> {
    this.tailEnforcementActions();
    this.scanForIocBundles();
    this.emit('glasswally:stats', {
      ...this.stats,
      timestamp: new Date().toISOString(),
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Enforcement action tailing
  // ─────────────────────────────────────────────────────────────────────────

  private tailEnforcementActions(): void {
    const filePath = join(this.outputDir, 'enforcement_actions.jsonl');
    if (!existsSync(filePath)) return;

    const { lines, newOffset } = this.readNewLines(filePath, this.enforcementOffset);
    this.enforcementOffset = newOffset;

    for (const line of lines) {
      this.processEnforcementLine(line);
    }
  }

  private processEnforcementLine(line: string): void {
    // Hard cap on line size — Glasswally allows 4MB but we reject anything over 64KB
    // to prevent memory exhaustion from pathological inputs
    if (line.length > MAX_LINE_BYTES) {
      this.stats.alerts_dropped_schema++;
      this.log('warn', 'Enforcement line exceeds 64KB — dropped', { size: line.length });
      return;
    }

    let raw: unknown;
    try {
      raw = JSON.parse(line);
    } catch {
      this.stats.alerts_dropped_schema++;
      this.log('debug', 'Non-JSON line in enforcement_actions.jsonl — skipped');
      return;
    }

    const result = EnforcementActionSchema.safeParse(raw);
    if (!result.success) {
      this.stats.alerts_dropped_schema++;
      this.log('warn', 'Enforcement record failed schema validation — dropped', {
        issues: result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`),
      });
      return;
    }

    if (!this.checkRateLimit()) {
      this.stats.alerts_dropped_rate++;
      this.log('warn', 'Glasswally rate limit exceeded — enforcement action dropped');
      AuditLogger.log({
        agentId: this.id,
        event: 'security.glasswally_rate_limited',
        metadata: { account_id: result.data.account_id, action_type: result.data.action_type },
      });
      return;
    }

    this.dispatchEnforcementAction(result.data);
  }

  private dispatchEnforcementAction(action: z.infer<typeof EnforcementActionSchema>): void {
    this.stats.alerts_ingested++;

    // Sanitize free-text fields — reason and evidence may contain adversarial content
    // from model output that Glasswally captured during the attack
    const { sanitized: cleanReason, injectionDetected: reasonInjection } =
      sanitizeInput(action.reason, `glasswally:reason:${action.account_id}`);

    const cleanEvidence = action.evidence.map((e) => {
      const { sanitized } = sanitizeInput(e, `glasswally:evidence:${action.account_id}`);
      return sanitized;
    });

    if (reasonInjection) {
      AuditLogger.log({
        agentId: this.id,
        event: 'security.injection_detected',
        metadata: { source: 'glasswally:reason', account_id: action.account_id },
      });
    }

    const severity = ACTION_SEVERITY[action.action_type];
    const scoreTier = SCORE_TIER.find((t) => action.composite_score >= t.min)?.label ?? 'info';

    // Route to AlertTriageAgent via alert:raw
    // Pre-populated severity field is respected by classifySeverity() — no re-classification needed
    this.emit('alert:raw', {
      source: 'glasswally',
      title: `[Glasswally] ${action.action_type}: ${action.account_id}`,
      description: cleanReason,
      severity,
      tags: [
        'glasswally',
        'distillation-attack',
        action.action_type.toLowerCase(),
        `score:${scoreTier}`,
        ...(action.cluster_id ? [`cluster:${action.cluster_id}`] : []),
      ],
      metadata: {
        action_type: action.action_type,
        account_id: action.account_id,
        cluster_id: action.cluster_id,
        affected_count: action.affected_accounts.length,
        composite_score: action.composite_score,
        evidence: cleanEvidence,
        glasswally_timestamp: action.timestamp,
      },
    });

    // Record enforcement decision to DecisionLedger — full provenance trail
    this.act(
      'glasswally:enforcement',
      {
        action_type: action.action_type,
        account_id: action.account_id,
        composite_score: action.composite_score,
        severity,
        cluster_id: action.cluster_id,
        timestamp: action.timestamp,
      },
      { reason: `Glasswally ${action.action_type} on ${action.account_id} (score: ${action.composite_score.toFixed(3)})` },
    );

    this.log(
      severity === 'CRITICAL' || severity === 'HIGH' ? 'warn' : 'info',
      `[${severity}] ${action.action_type} — ${action.account_id}`,
      { score: action.composite_score, tier: scoreTier, cluster: action.cluster_id },
    );
  }

  // ─────────────────────────────────────────────────────────────────────────
  // IOC bundle ingestion
  // ─────────────────────────────────────────────────────────────────────────

  private scanForIocBundles(): void {
    let entries: string[];
    try {
      entries = readdirSync(this.outputDir);
    } catch {
      return; // directory may not exist yet
    }

    for (const filename of entries) {
      // Strict pattern check prevents directory traversal via crafted filenames
      if (!IOC_BUNDLE_PATTERN.test(filename)) continue;
      if (this.processedBundles.has(filename)) continue;

      // Mark as processed before reading — prevents double-processing on error
      this.processedBundles.add(filename);

      const filePath = join(this.outputDir, filename);
      this.processIocBundle(filePath, filename);
    }
  }

  private processIocBundle(filePath: string, filename: string): void {
    // Must be a regular file — reject symlinks, devices, FIFOs
    let stat;
    try {
      stat = lstatSync(filePath);
    } catch {
      return;
    }
    if (!stat.isFile()) {
      this.log('warn', `IOC bundle is not a regular file — rejected: ${filename}`);
      return;
    }
    if (stat.size > MAX_BUNDLE_BYTES) {
      this.log('warn', `IOC bundle exceeds 50 MB size limit — rejected: ${filename}`);
      return;
    }

    const content = this.readFileContent(filePath, MAX_BUNDLE_BYTES);
    if (content === null) {
      this.log('warn', `Failed to read IOC bundle: ${filename}`);
      return;
    }

    let raw: unknown;
    try {
      raw = JSON.parse(content);
    } catch {
      this.log('warn', `IOC bundle is not valid JSON: ${filename}`);
      return;
    }

    const result = IocBundleSchema.safeParse(raw);
    if (!result.success) {
      this.log('warn', `IOC bundle schema validation failed: ${filename}`, {
        issues: result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`),
      });
      return;
    }

    const bundle = result.data;

    // Without the IOC secret we cannot verify the HMAC — refuse to trust the bundle
    if (!this.iocSecret) {
      this.log('warn', `IOC bundle received but GLASSWALLY_IOC_SECRET not set — not forwarding: ${bundle.cluster_id}`);
      return;
    }

    // HMAC-SHA256 signature verification — a tampered bundle is a security incident
    if (!this.verifyBundleHmac(bundle)) {
      this.stats.ioc_bundles_rejected++;
      this.log('warn', `IOC bundle HMAC verification FAILED — bundle discarded: ${bundle.cluster_id}`);
      AuditLogger.log({
        agentId: this.id,
        event: 'security.ioc_bundle_tampered',
        metadata: {
          cluster_id: bundle.cluster_id,
          filename,
          // Do not log the hmac value — that would aid an attacker trying to forge valid signatures
        },
      });
      return;
    }

    this.stats.ioc_bundles_verified++;

    // Emit the entire verified bundle as a single event to ThreatIntelAgent
    // (avoids per-IOC EventBus rate limiting on large bundles)
    this.emit('intel:ioc:bundle', {
      cluster_id: bundle.cluster_id,
      ips: bundle.ips,
      subnets: bundle.subnets,
      tls_fingerprints: bundle.tls_fingerprints,
      confidence: bundle.confidence,
      source: `glasswally:${bundle.cluster_id}`,
      timestamp: bundle.timestamp,
    });

    this.log('info', `IOC bundle verified and forwarded: ${bundle.cluster_id}`, {
      ips: bundle.ips.length,
      subnets: bundle.subnets.length,
      tls_fingerprints: bundle.tls_fingerprints.length,
      confidence: bundle.confidence,
    });
  }

  // HMAC verification — uses timingSafeEqual to prevent timing attacks.
  // Glasswally signs the bundle data (without the hmac field) with HMAC-SHA256.
  private verifyBundleHmac(bundle: IocBundle): boolean {
    if (!this.iocSecret) return false;
    const { hmac: _, ...data } = bundle;
    const payload = JSON.stringify(data);
    const expected = createHmac('sha256', this.iocSecret).update(payload).digest('hex');
    try {
      return timingSafeEqual(
        Buffer.from(bundle.hmac, 'hex'),
        Buffer.from(expected, 'hex'),
      );
    } catch {
      // Buffer.from will throw if the hex string has odd length
      return false;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // File reading
  // ─────────────────────────────────────────────────────────────────────────

  // Reads new bytes from a JSONL file starting at `offset`.
  // Handles file rotation (Glasswally may roll enforcement_actions.jsonl daily).
  // Caps reads at MAX_BYTES_PER_TICK to prevent memory exhaustion.
  private readNewLines(
    filePath: string,
    offset: number,
  ): { lines: string[]; newOffset: number } {
    let currentSize: number;
    try {
      currentSize = statSync(filePath).size;
    } catch {
      return { lines: [], newOffset: offset };
    }

    // File was truncated or rotated — reset to the beginning
    if (currentSize < offset) {
      this.log('info', `File rotation detected, resetting offset: ${filePath}`);
      this.lineBuffer = '';
      this.skipOversizedLine = false;
      offset = 0;
    }

    if (currentSize === offset) return { lines: [], newOffset: offset };

    const bytesToRead = Math.min(currentSize - offset, MAX_BYTES_PER_TICK);
    const buf = Buffer.allocUnsafe(bytesToRead);
    let bytesRead = 0;

    const fd = openSync(filePath, 'r');
    try {
      bytesRead = readSync(fd, buf, 0, bytesToRead, offset);
    } finally {
      closeSync(fd);
    }

    if (bytesRead === 0) return { lines: [], newOffset: offset };

    const chunk = buf.subarray(0, bytesRead).toString('utf-8');

    let text: string;
    if (this.skipOversizedLine) {
      // Discarding the tail of an oversized physical line. Drop everything up
      // to and including the next newline, then resume parsing after it.
      const nl = chunk.indexOf('\n');
      if (nl === -1) {
        // Still inside the oversized line — discard this entire chunk.
        return { lines: [], newOffset: offset + bytesRead };
      }
      this.skipOversizedLine = false;
      text = chunk.slice(nl + 1);
    } else {
      // Prepend any partial line held from the previous tick
      text = this.lineBuffer + chunk;
    }

    const parts = text.split('\n');

    // The last segment may be an incomplete line — hold it for the next tick
    this.lineBuffer = parts.pop() ?? '';

    // Cap the partial-line buffer. A line larger than MAX_LINE_BUFFER can
    // never be a valid record (records are capped at MAX_LINE_BYTES), so the
    // remainder of this physical line is unrecoverable: discard the buffer and
    // skip bytes until the next newline. Complete lines parsed above are
    // unaffected — only the oversized trailing fragment is dropped. (STRIDE D-6)
    if (this.lineBuffer.length > MAX_LINE_BUFFER) {
      this.log('warn', 'Glasswally partial-line buffer exceeded cap — line discarded as unrecoverable', {
        size: this.lineBuffer.length,
        cap: MAX_LINE_BUFFER,
      });
      AuditLogger.log({
        agentId: this.id,
        event: 'security.glasswally_line_buffer_overflow',
        metadata: { size: this.lineBuffer.length, cap: MAX_LINE_BUFFER },
      });
      this.lineBuffer = '';
      this.skipOversizedLine = true;
    }

    const lines = parts.filter((l) => l.trim().length > 0);
    return { lines, newOffset: offset + bytesRead };
  }

  // Reads an entire file as a string. Returns null on error or if file exceeds maxBytes.
  private readFileContent(filePath: string, maxBytes: number): string | null {
    let size: number;
    try {
      size = statSync(filePath).size;
    } catch {
      return null;
    }
    if (size > maxBytes) return null;

    const buf = Buffer.allocUnsafe(size);
    const fd = openSync(filePath, 'r');
    try {
      const bytesRead = readSync(fd, buf, 0, size, 0);
      return buf.subarray(0, bytesRead).toString('utf-8');
    } catch {
      return null;
    } finally {
      closeSync(fd);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Rate limiting
  // ─────────────────────────────────────────────────────────────────────────

  private checkRateLimit(): boolean {
    const now = Date.now();
    if (now - this.alertWindowStart > 60_000) {
      this.alertCount = 0;
      this.alertWindowStart = now;
    }
    if (this.alertCount >= this.maxAlertsPerMinute) return false;
    this.alertCount++;
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Path validation
  // ─────────────────────────────────────────────────────────────────────────

  private validateOutputDir(dir: string): string {
    if (!isAbsolute(dir)) {
      throw new Error(
        `[GlasswallyAgent] outputDir must be an absolute path, got: "${dir}". ` +
        `Use path.resolve() when constructing the path.`,
      );
    }

    const resolved = resolve(dir);

    let stat;
    try {
      stat = lstatSync(resolved);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        // Directory doesn't exist yet — Glasswally may not have started.
        // We'll check on each tick. This is a valid startup state.
        console.warn(
          `[GlasswallyAgent] outputDir does not exist yet — will begin tailing when Glasswally creates it: ${resolved}`,
        );
        return resolved;
      }
      throw err;
    }

    // Never follow a symlink — an attacker could point it at /etc or /proc
    if (stat.isSymbolicLink()) {
      throw new Error(
        `[GlasswallyAgent] outputDir must not be a symlink: "${resolved}". ` +
        `Use the real directory path.`,
      );
    }

    if (!stat.isDirectory()) {
      throw new Error(`[GlasswallyAgent] outputDir is not a directory: "${resolved}"`);
    }

    return resolved;
  }
}
