// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Alert Triage
// Classifies incoming security alerts by severity, deduplicates within a
// rolling window, and routes to the appropriate channel for response.
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent, AgentConfig } from '../../../runtime/Agent';
import { AgentRiskTier } from '../../../types/agent-risk';
import { AgentManifest, validateManifest } from '../../../types/agent-manifest';

export const MANIFEST: AgentManifest = validateManifest({
  id: 'alert-triage',
  name: 'Alert Triage',
  version: '1.0.0',
  category: 'soc',
  description: 'Classifies incoming security alerts by severity, deduplicates within a rolling window, and routes to the appropriate SOC response channel.',
  capabilities: [
    'eventbus:subscribe', 'eventbus:publish',
    'memory:read', 'memory:write',
    'ledger:write',
  ],
  trustLevel: AgentRiskTier.HIGH,
  tags: ['soc', 'triage', 'alerts', 'security', 'classification'],
  author: 'EverythingOS',
});

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface RawAlert {
  source: string;
  title: string;
  description: string;
  severity?: AlertSeverity;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface TriagedAlert extends RawAlert {
  id: string;
  severity: AlertSeverity;
  triageScore: number;
  channel: string;
  timestamp: number;
}

const SEVERITY_SCORES: Record<AlertSeverity, number> = {
  CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25, INFO: 5,
};

const SEVERITY_PATTERNS: Array<{ pattern: RegExp; severity: AlertSeverity }> = [
  { pattern: /inject|exploit|rce|command.execut|privilege.escal|code.execut/i, severity: 'CRITICAL' },
  { pattern: /auth.fail|unauthorized|forbidden|breach|compromise|revok/i, severity: 'HIGH' },
  { pattern: /rate.limit|anomal|unusual|suspicious|malform|fingerprint.tamper/i, severity: 'MEDIUM' },
  { pattern: /warn|degrad|slow|timeout|retry/i, severity: 'LOW' },
];

function classifySeverity(alert: RawAlert): AlertSeverity {
  if (alert.severity) return alert.severity;
  const text = `${alert.title} ${alert.description}`;
  for (const { pattern, severity } of SEVERITY_PATTERNS) {
    if (pattern.test(text)) return severity;
  }
  return 'INFO';
}

function alertKey(alert: RawAlert): string {
  return `${alert.source}:${alert.title}`.toLowerCase().replace(/\s+/g, '-').slice(0, 128);
}

export default class AlertTriageAgent extends Agent {
  private recentKeys = new Map<string, number>(); // key -> last-seen timestamp
  private readonly dedupWindowMs: number;
  private alertCounter = 0;
  private stats = { total: 0, deduplicated: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  constructor(dedupWindowMs = 5 * 60 * 1000, config?: Partial<AgentConfig>) {
    super({
      id: MANIFEST.id,
      name: MANIFEST.name,
      type: 'analysis',
      description: MANIFEST.description,
      tickRate: 60_000, // purge stale dedup keys + emit stats every minute
      riskConfig: {
        tier: AgentRiskTier.HIGH,
        riskJustification: 'Routes security alerts — incorrect routing could suppress CRITICAL alerts; HIGH tier enforces full audit trail',
        requiresApproval: false, // routing is automated; HIGH is for audit depth, not approval gate
        genAIRisks: {
          informationIntegrityRisk: true,
          promptInjectionRisk: false,
          piiRisk: false,
          hallucinationRisk: false,
          harmfulContentRisk: false,
          physicalSafetyRisk: false,
          dataPrivacyRisk: false,
        },
        allowedPublishChannels: ['alert:critical', 'alert:high', 'alert:medium', 'alert:low', 'alert:info', 'alert:stats'],
        allowedSubscribeChannels: ['alert:raw'],
        auditInputs: true,
        auditOutputs: true,
      },
      ...config,
    });
    this.dedupWindowMs = dedupWindowMs;
  }

  protected async onStart(): Promise<void> {
    this.subscribe<RawAlert>('alert:raw', (event) => {
      this.triage(event.payload);
    });
    this.log('info', 'Alert triage agent started');
  }

  protected async onStop(): Promise<void> {
    this.recentKeys.clear();
    this.log('info', 'Alert triage agent stopped');
  }

  protected async onTick(): Promise<void> {
    const now = Date.now();
    for (const [key, ts] of this.recentKeys) {
      if (now - ts > this.dedupWindowMs) this.recentKeys.delete(key);
    }
    this.emit('alert:stats', { ...this.stats, dedupWindowMs: this.dedupWindowMs });
  }

  private triage(raw: RawAlert): void {
    this.stats.total++;

    const key = alertKey(raw);
    const lastSeen = this.recentKeys.get(key);
    if (lastSeen && Date.now() - lastSeen < this.dedupWindowMs) {
      this.stats.deduplicated++;
      return;
    }

    this.recentKeys.set(key, Date.now());

    const severity = classifySeverity(raw);
    const id = `alert_${++this.alertCounter}_${Date.now()}`;
    const channel = `alert:${severity.toLowerCase()}` as TriagedAlert['channel'];

    const triaged: TriagedAlert = {
      ...raw,
      id,
      severity,
      triageScore: SEVERITY_SCORES[severity],
      channel,
      timestamp: Date.now(),
    };

    const key2 = severity.toLowerCase() as keyof typeof this.stats;
    if (key2 in this.stats) (this.stats[key2] as number)++;

    this.act(channel, triaged, { reason: `${severity} alert from ${raw.source}: ${raw.title}` });

    this.log(
      severity === 'CRITICAL' || severity === 'HIGH' ? 'warn' : 'info',
      `[${severity}] ${raw.title}`,
      { id, source: raw.source },
    );
  }
}
