// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Echo Chamber Detector
// Detects self-reinforcing loops in agent output streams by tracking
// word-overlap similarity across a sliding window of recent LLM responses.
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent, AgentConfig } from '../../../runtime/Agent';
import { AgentRiskTier } from '../../../types/agent-risk';
import { AgentManifest, validateManifest } from '../../../types/agent-manifest';

export const MANIFEST: AgentManifest = validateManifest({
  id: 'echo-chamber',
  name: 'Echo Chamber Detector',
  version: '1.0.0',
  category: 'creative',
  description: 'Detects self-reinforcing loops in agent output streams by tracking similarity across recent LLM responses.',
  capabilities: ['eventbus:subscribe', 'eventbus:publish'],
  trustLevel: AgentRiskTier.LOW,
  tags: ['creative', 'safety', 'loop-detection', 'analysis'],
  author: 'EverythingOS',
});

const WINDOW_SIZE = 20;
const ECHO_THRESHOLD = 0.75;   // word-overlap ratio that flags similarity
const ECHO_RATIO_ALARM = 0.5;  // fraction of window that must be similar to fire

function wordOverlap(a: string, b: string): number {
  const setA = new Set(a.split(/\s+/).filter(Boolean));
  const setB = new Set(b.split(/\s+/).filter(Boolean));
  if (setA.size === 0 || setB.size === 0) return 0;
  let overlap = 0;
  for (const word of setA) { if (setB.has(word)) overlap++; }
  return overlap / Math.min(setA.size, setB.size);
}

export default class EchoChamberAgent extends Agent {
  private recentOutputs: string[] = [];
  private detectedCount = 0;

  constructor(config?: Partial<AgentConfig>) {
    super({
      id: MANIFEST.id,
      name: MANIFEST.name,
      type: 'analysis',
      description: MANIFEST.description,
      riskConfig: {
        tier: AgentRiskTier.LOW,
        riskJustification: 'Read-only analysis of event stream — no external calls or side effects',
        allowedPublishChannels: ['echo:detected', 'echo:stats'],
        allowedSubscribeChannels: ['llm:response', 'agent:output'],
      },
      ...config,
    });
  }

  protected async onStart(): Promise<void> {
    this.subscribe<{ content: string; agentId?: string }>('llm:response', (event) => {
      this.observe(event.payload.content, event.payload.agentId ?? 'unknown');
    });
    this.subscribe<{ content: string; agentId?: string }>('agent:output', (event) => {
      this.observe(event.payload.content, event.payload.agentId ?? 'unknown');
    });
    this.log('info', 'Echo chamber detector started');
  }

  protected async onStop(): Promise<void> {
    this.recentOutputs = [];
    this.log('info', 'Echo chamber detector stopped');
  }

  private observe(content: string, agentId: string): void {
    const normalized = content.toLowerCase().trim();

    if (this.recentOutputs.length >= WINDOW_SIZE) {
      this.recentOutputs.shift();
    }

    if (this.recentOutputs.length > 0) {
      const similarities = this.recentOutputs.map((prev) => wordOverlap(normalized, prev));
      const highCount = similarities.filter((s) => s >= ECHO_THRESHOLD).length;
      const echoRatio = highCount / this.recentOutputs.length;

      if (echoRatio >= ECHO_RATIO_ALARM) {
        this.detectedCount++;
        this.emit('echo:detected', {
          agentId,
          echoRatio,
          windowSize: this.recentOutputs.length,
          detectedCount: this.detectedCount,
          snippet: content.slice(0, 120),
        });
        this.log('warn', 'Echo chamber pattern detected', { agentId, echoRatio });
      }
    }

    this.recentOutputs.push(normalized);
  }

  getStats(): { windowSize: number; detectedCount: number } {
    return { windowSize: this.recentOutputs.length, detectedCount: this.detectedCount };
  }
}
