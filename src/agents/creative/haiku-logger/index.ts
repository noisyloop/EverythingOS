// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Haiku Logger
// Converts DecisionLedger entries and agent lifecycle events into haiku poems,
// producing a human-readable audit trail with 5-7-5 syllable structure.
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent, AgentConfig } from '../../../runtime/Agent';
import { AgentRiskTier } from '../../../types/agent-risk';
import { AgentManifest, validateManifest } from '../../../types/agent-manifest';

export const MANIFEST: AgentManifest = validateManifest({
  id: 'haiku-logger',
  name: 'Haiku Logger',
  version: '1.0.0',
  category: 'creative',
  description: 'Transforms DecisionLedger entries and audit events into haiku poems for a poetic, human-readable audit trail.',
  capabilities: ['model:call', 'eventbus:subscribe', 'eventbus:publish', 'ledger:read'],
  trustLevel: AgentRiskTier.MEDIUM,
  tags: ['creative', 'logging', 'haiku', 'audit', 'llm'],
  author: 'EverythingOS',
});

interface HaikuEntry {
  timestamp: string;
  eventSummary: string;
  haiku: string;
}

export default class HaikuLoggerAgent extends Agent {
  private haikuLog: HaikuEntry[] = [];
  private pendingEvents: string[] = [];

  constructor(config?: Partial<AgentConfig>) {
    super({
      id: MANIFEST.id,
      name: MANIFEST.name,
      type: 'perception',
      description: MANIFEST.description,
      tickRate: 30_000, // batch-compose every 30 seconds
      riskConfig: {
        tier: AgentRiskTier.MEDIUM,
        riskJustification: 'Calls LLM to compose haiku from audit events — no external side effects beyond LLM API call',
        genAIRisks: {
          promptInjectionRisk: false,
          piiRisk: false,
          hallucinationRisk: false,
          harmfulContentRisk: false,
          informationIntegrityRisk: false,
          physicalSafetyRisk: false,
          dataPrivacyRisk: false,
        },
        allowedPublishChannels: ['haiku:composed', 'haiku:log'],
        allowedSubscribeChannels: ['agent:registered', 'agent:stopped', 'decision:recorded', 'security:injection_detected'],
      },
      llm: {
        provider: 'claude',
        model: 'claude-haiku-4-5-20251001',
        temperature: 1.0,
        maxTokens: 60,
      },
      ...config,
    });
  }

  protected async onStart(): Promise<void> {
    this.subscribe<{ agentId: string }>('agent:registered', (event) => {
      this.pendingEvents.push(`Agent joined the system: ${event.payload.agentId}`);
    });

    this.subscribe<{ agentId: string }>('agent:stopped', (event) => {
      this.pendingEvents.push(`Agent left the system: ${event.payload.agentId}`);
    });

    this.subscribe<{ agentId: string; decisionType: string }>('decision:recorded', (event) => {
      this.pendingEvents.push(`${event.payload.agentId} decided: ${event.payload.decisionType}`);
    });

    this.subscribe<{ agentId: string; patterns?: string[] }>('security:injection_detected', (event) => {
      this.pendingEvents.push(`Injection attempt blocked for ${event.payload.agentId}`);
    });

    this.log('info', 'Haiku logger started — composing silence into verse');
  }

  protected async onStop(): Promise<void> {
    this.pendingEvents = [];
    this.log('info', `Haiku logger stopped — ${this.haikuLog.length} haiku composed`);
  }

  protected async onTick(): Promise<void> {
    if (this.pendingEvents.length === 0 || !this.config.llm) return;

    const batch = this.pendingEvents.splice(0, 5);
    const summary = batch.join('; ');

    try {
      const haiku = await this.think(
        `Write a single haiku (5-7-5 syllable structure) capturing the essence of these system events:\n${summary}\n\nRespond with ONLY the haiku — three lines, no title, no explanation.`,
        { systemPrompt: 'You are a Zen poet who captures machine events in haiku. Be concise, evocative, and precise about syllable counts.' },
      );

      const entry: HaikuEntry = {
        timestamp: new Date().toISOString(),
        eventSummary: summary.slice(0, 100),
        haiku: haiku.trim(),
      };

      this.haikuLog.push(entry);
      this.emit('haiku:composed', entry);
      this.log('info', 'Haiku composed', { haiku: haiku.trim() });
    } catch (err) {
      this.log('warn', 'Haiku composition failed', { error: String(err) });
    }
  }

  getLog(): HaikuEntry[] { return [...this.haikuLog]; }
}
