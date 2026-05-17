// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Anomaly Watch
// Monitors the event bus for statistical anomalies using a sliding bucket window.
// Fires when a channel's event rate deviates beyond 3σ from its rolling baseline.
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent, AgentConfig } from '../../../runtime/Agent';
import { AgentRiskTier } from '../../../types/agent-risk';
import { AgentManifest, validateManifest } from '../../../types/agent-manifest';

export const MANIFEST: AgentManifest = validateManifest({
  id: 'anomaly-watch',
  name: 'Anomaly Watch',
  version: '1.0.0',
  category: 'soc',
  description: 'Monitors the event bus for statistical anomalies — sudden spikes, unusual silence, or timing irregularities — and alerts the SOC.',
  capabilities: ['eventbus:subscribe', 'eventbus:publish', 'memory:read', 'memory:write', 'ledger:write'],
  trustLevel: AgentRiskTier.MEDIUM,
  tags: ['soc', 'anomaly', 'detection', 'statistics', 'monitoring'],
  author: 'EverythingOS',
});

interface ChannelStats {
  channel: string;
  totalCount: number;
  buckets: number[];     // event counts per time bucket (newest last)
  mean: number;
  stddev: number;
  lastUpdated: number;
}

const BUCKET_MS = 10_000;             // each bucket spans 10 seconds
const BUCKET_COUNT = 30;              // keep 5 minutes of history
const ZSCORE_THRESHOLD = 3.0;         // 3σ rule — ~0.3% false positive rate
const MIN_BUCKETS_FOR_BASELINE = 10;  // require 100s of data before alarming

function recomputeStats(stats: ChannelStats): void {
  const n = stats.buckets.length;
  if (n === 0) return;
  const sum = stats.buckets.reduce((a, b) => a + b, 0);
  stats.mean = sum / n;
  const variance = stats.buckets.reduce((acc, v) => acc + (v - stats.mean) ** 2, 0) / n;
  stats.stddev = Math.sqrt(variance);
}

export default class AnomalyWatchAgent extends Agent {
  private channels: Map<string, ChannelStats> = new Map();
  private anomalyCount = 0;

  // Channels observed by default — add more via 'anomaly:watch' events
  private static readonly DEFAULT_CHANNELS = [
    'agent.registered', 'agent.started', 'agent.stopped', 'agent.error',
    'security.injection_detected', 'security.pii_scrubbed',
    'llm.call', 'llm.rate_limited',
    'alert:critical', 'alert:high',
    'eventbus.publish_blocked',
  ];

  constructor(config?: Partial<AgentConfig>) {
    super({
      id: MANIFEST.id,
      name: MANIFEST.name,
      type: 'analysis',
      description: MANIFEST.description,
      tickRate: BUCKET_MS,
      riskConfig: {
        tier: AgentRiskTier.MEDIUM,
        riskJustification: 'Statistical monitoring only — emits anomaly alerts but takes no automated action',
        allowedPublishChannels: ['anomaly:detected', 'anomaly:stats'],
        allowedSubscribeChannels: [
          'anomaly:watch',
          'agent.registered', 'agent.started', 'agent.stopped', 'agent.error',
          'security.injection_detected', 'security.pii_scrubbed',
          'llm.call', 'llm.rate_limited',
          'alert:critical', 'alert:high',
          'eventbus.publish_blocked',
        ],
      },
      ...config,
    });
  }

  protected async onStart(): Promise<void> {
    // Subscribe to default channels
    for (const ch of AnomalyWatchAgent.DEFAULT_CHANNELS) {
      this.watchChannel(ch);
    }

    // Allow dynamic channel registration
    this.subscribe<{ channel: string }>('anomaly:watch', (event) => {
      this.watchChannel(event.payload.channel);
    });

    this.log('info', `Anomaly watch started — monitoring ${AnomalyWatchAgent.DEFAULT_CHANNELS.length} channels`);
  }

  protected async onStop(): Promise<void> {
    this.log('info', `Anomaly watch stopped — ${this.anomalyCount} anomalies detected`);
  }

  protected async onTick(): Promise<void> {
    this.advanceBuckets();
    this.emit('anomaly:stats', {
      channels: this.channels.size,
      anomalies: this.anomalyCount,
      totalEvents: Array.from(this.channels.values()).reduce((a, s) => a + s.totalCount, 0),
    });
  }

  private watchChannel(channel: string): void {
    if (this.channels.has(channel)) return;
    this.channels.set(channel, {
      channel,
      totalCount: 0,
      buckets: [0],
      mean: 0,
      stddev: 0,
      lastUpdated: Date.now(),
    });
    // Subscribe using the agent's secured subscribe path
    try {
      this.subscribe(channel, () => this.recordEvent(channel));
    } catch {
      // Channel may not be in allowedSubscribeChannels — log but don't crash
      this.log('debug', `Cannot watch channel (not in ACL): ${channel}`);
      this.channels.delete(channel);
    }
  }

  private recordEvent(channel: string): void {
    const stats = this.channels.get(channel);
    if (!stats) return;
    stats.totalCount++;
    if (stats.buckets.length === 0) stats.buckets.push(0);
    stats.buckets[stats.buckets.length - 1]++;
    stats.lastUpdated = Date.now();
  }

  private advanceBuckets(): void {
    for (const stats of this.channels.values()) {
      const currentCount = stats.buckets[stats.buckets.length - 1] ?? 0;

      // Trim window
      if (stats.buckets.length >= BUCKET_COUNT) stats.buckets.shift();

      // Check for anomaly using the COMPLETED bucket
      if (stats.buckets.length >= MIN_BUCKETS_FOR_BASELINE) {
        recomputeStats(stats);
        if (stats.stddev > 0) {
          const z = (currentCount - stats.mean) / stats.stddev;
          if (Math.abs(z) >= ZSCORE_THRESHOLD) {
            this.anomalyCount++;
            this.act('anomaly:detected', {
              channel: stats.channel,
              zScore: Math.round(z * 100) / 100,
              observed: currentCount,
              mean: Math.round(stats.mean * 100) / 100,
              stddev: Math.round(stats.stddev * 100) / 100,
              anomalyType: z > 0 ? 'spike' : 'silence',
              timestamp: new Date().toISOString(),
            }, { reason: `Anomaly on ${stats.channel}: z=${z.toFixed(2)}` });

            this.log('warn', `Anomaly: ${z > 0 ? 'spike' : 'silence'} on ${stats.channel}`, {
              z: z.toFixed(2), observed: currentCount, mean: stats.mean,
            });
          }
        }
      }

      stats.buckets.push(0); // open new bucket
    }
  }
}
