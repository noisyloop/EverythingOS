// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Signal-Noise Filter
// Scores incoming event payloads for information density and suppresses
// low-value noise before it reaches downstream agents.
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent, AgentConfig } from '../../../runtime/Agent';
import { AgentRiskTier } from '../../../types/agent-risk';
import { AgentManifest, validateManifest } from '../../../types/agent-manifest';

export const MANIFEST: AgentManifest = validateManifest({
  id: 'signal-noise',
  name: 'Signal-Noise Filter',
  version: '1.0.0',
  category: 'creative',
  description: 'Scores incoming event payloads for signal quality and suppresses low-value noise before it reaches downstream agents.',
  capabilities: ['eventbus:subscribe', 'eventbus:publish'],
  trustLevel: AgentRiskTier.LOW,
  tags: ['creative', 'filter', 'signal-processing', 'noise'],
  author: 'EverythingOS',
});

export interface SignalRule {
  channel: string;
  minLength?: number;
  requiredFields?: string[];
  scoreThreshold?: number; // 0–1, default 0.4
}

function scorePayload(payload: unknown, rule: SignalRule): number {
  if (payload === null || payload === undefined) return 0;

  let score = 0.5;

  const str = JSON.stringify(payload);
  if (rule.minLength && str.length < rule.minLength) score -= 0.3;

  if (rule.requiredFields && typeof payload === 'object' && payload !== null) {
    const obj = payload as Record<string, unknown>;
    const present = rule.requiredFields.filter((f) => obj[f] !== undefined);
    score += (present.length / rule.requiredFields.length) * 0.5;
  }

  if (typeof payload === 'object' && payload !== null) {
    const keys = Object.keys(payload as object).length;
    score += Math.min(keys / 10, 0.2);
  }

  return Math.max(0, Math.min(1, score));
}

export default class SignalNoiseAgent extends Agent {
  private rules: SignalRule[] = [];
  private passCount = 0;
  private dropCount = 0;

  constructor(rules?: SignalRule[], config?: Partial<AgentConfig>) {
    super({
      id: MANIFEST.id,
      name: MANIFEST.name,
      type: 'perception',
      description: MANIFEST.description,
      riskConfig: {
        tier: AgentRiskTier.LOW,
        riskJustification: 'Event stream filter — no external calls, only re-emits scored events',
        allowedPublishChannels: ['signal:pass', 'signal:stats'],
        allowedSubscribeChannels: ['signal:raw', 'signal:configure'],
      },
      ...config,
    });
    this.rules = rules ?? [];
  }

  protected async onStart(): Promise<void> {
    this.subscribe<{ channel: string; payload: unknown }>('signal:raw', (event) => {
      this.filter(event.payload.channel, event.payload.payload);
    });

    this.subscribe<SignalRule>('signal:configure', (event) => {
      const rule = event.payload;
      const idx = this.rules.findIndex((r) => r.channel === rule.channel);
      if (idx >= 0) {
        this.rules[idx] = rule;
      } else {
        this.rules.push(rule);
      }
      this.log('info', `Rule updated for channel: ${rule.channel}`);
    });

    this.log('info', `Signal-noise filter started with ${this.rules.length} rules`);
  }

  protected async onStop(): Promise<void> {
    this.log('info', `Signal-noise filter stopped — passed: ${this.passCount}, dropped: ${this.dropCount}`);
  }

  private filter(channel: string, payload: unknown): void {
    const rule = this.rules.find((r) => r.channel === channel) ?? { channel, scoreThreshold: 0.4 };
    const threshold = rule.scoreThreshold ?? 0.4;
    const score = scorePayload(payload, rule);

    if (score >= threshold) {
      this.passCount++;
      this.emit('signal:pass', { channel, payload, score });
    } else {
      this.dropCount++;
      this.log('debug', 'Signal dropped', { channel, score, threshold });
    }
  }

  getStats(): { passCount: number; dropCount: number; noiseRatio: number } {
    const total = this.passCount + this.dropCount;
    return {
      passCount: this.passCount,
      dropCount: this.dropCount,
      noiseRatio: total > 0 ? this.dropCount / total : 0,
    };
  }
}
