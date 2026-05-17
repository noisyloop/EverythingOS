// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Compliance Mapper
// Maps observed agent events to NIST AI RMF 1.0 and NIST AI 600-1 controls,
// accumulating evidence and generating structured compliance reports.
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent, AgentConfig } from '../../../runtime/Agent';
import { AgentRiskTier } from '../../../types/agent-risk';
import { AgentManifest, validateManifest } from '../../../types/agent-manifest';

export const MANIFEST: AgentManifest = validateManifest({
  id: 'compliance-mapper',
  name: 'Compliance Mapper',
  version: '1.0.0',
  category: 'soc',
  description: 'Maps observed agent events to NIST AI RMF 1.0 and NIST AI 600-1 controls, generating compliance evidence automatically.',
  capabilities: ['eventbus:subscribe', 'eventbus:publish', 'ledger:read', 'memory:write'],
  trustLevel: AgentRiskTier.LOW,
  tags: ['soc', 'compliance', 'nist', 'audit', 'governance'],
  author: 'EverythingOS',
});

export interface ControlMapping {
  control: string;
  function: 'GOVERN' | 'MAP' | 'MEASURE' | 'MANAGE';
  description: string;
  evidenceCount: number;
  lastObserved?: string;
}

export interface ComplianceReport {
  generatedAt: string;
  controlsCovered: number;
  totalEvidence: number;
  mappings: ControlMapping[];
}

// Maps EverythingOS event types to the NIST controls they satisfy
const EVENT_TO_CONTROLS: Record<string, Array<{ control: string; function: ControlMapping['function']; description: string }>> = {
  'agent.registered': [
    { control: 'NIST AI RMF GOVERN GV-1.2', function: 'GOVERN', description: 'AI risk governance — agent registration with declared risk tier' },
    { control: 'NIST AI RMF MAP MP-2',       function: 'MAP',    description: 'AI risk categorization — tier declared at registration' },
  ],
  'agent.started': [
    { control: 'NIST AI RMF MANAGE MG-2.2', function: 'MANAGE', description: 'AI system deployment controls' },
  ],
  'agent.stopped': [
    { control: 'NIST AI RMF MANAGE MG-2.2', function: 'MANAGE', description: 'AI system lifecycle management' },
  ],
  'agent.error': [
    { control: 'NIST AI RMF MANAGE MG-4.1', function: 'MANAGE', description: 'AI incident response — error captured and logged' },
  ],
  'security.injection_detected': [
    { control: 'NIST AI 600-1 Prompt Injection', function: 'MANAGE', description: 'Prompt injection detection and mitigation' },
    { control: 'NIST AI RMF MANAGE MG-3.1',     function: 'MANAGE', description: 'AI input validation and sanitization' },
  ],
  'security.pii_scrubbed': [
    { control: 'NIST AI 600-1 Data Privacy',  function: 'MANAGE', description: 'PII scrubbing before LLM call' },
    { control: 'NIST AI RMF GOVERN GV-6.2',   function: 'GOVERN', description: 'Data governance — privacy protection' },
  ],
  'llm.call': [
    { control: 'NIST AI RMF MEASURE MS-2.5',              function: 'MEASURE', description: 'AI system monitoring — LLM call logged' },
    { control: 'NIST AI 600-1 Information Integrity',     function: 'MEASURE', description: 'LLM call traced and hash-recorded' },
  ],
  'llm.rate_limited': [
    { control: 'NIST AI RMF MANAGE MG-2.4', function: 'MANAGE', description: 'AI usage controls — rate limiting enforced' },
  ],
  'eventbus.publish_blocked': [
    { control: 'NIST AI RMF MANAGE MG-3.1', function: 'MANAGE', description: 'Access control — unauthorized publish blocked' },
    { control: 'NIST AI RMF GOVERN GV-1.2', function: 'GOVERN', description: 'Channel ACL enforcement' },
  ],
  'decision.recorded': [
    { control: 'NIST AI RMF MEASURE MS-2.5', function: 'MEASURE', description: 'Decision provenance — content-addressed ledger entry' },
    { control: 'NIST AI RMF GOVERN GV-4.2',  function: 'GOVERN', description: 'AI accountability — decision recorded with context' },
  ],
  'agent.action': [
    { control: 'NIST AI RMF MANAGE MG-2.2', function: 'MANAGE', description: 'Consequential action gated through act() with ledger record' },
    { control: 'NIST AI RMF MEASURE MS-2.5', function: 'MEASURE', description: 'Action audited and hash-recorded' },
  ],
};

export default class ComplianceMapperAgent extends Agent {
  private mappings: Map<string, ControlMapping> = new Map();
  private evidenceLog: Array<{ event: string; controls: string[]; timestamp: string }> = [];
  private readonly maxEvidenceLog = 10_000;

  constructor(config?: Partial<AgentConfig>) {
    super({
      id: MANIFEST.id,
      name: MANIFEST.name,
      type: 'analysis',
      description: MANIFEST.description,
      tickRate: 3_600_000, // emit hourly compliance report
      riskConfig: {
        tier: AgentRiskTier.LOW,
        riskJustification: 'Read-only compliance mapping — observes events, no external calls or side effects',
        allowedPublishChannels: ['compliance:evidence', 'compliance:report'],
        allowedSubscribeChannels: [
          'agent.registered', 'agent.started', 'agent.stopped', 'agent.error',
          'security.injection_detected', 'security.pii_scrubbed',
          'llm.call', 'llm.rate_limited',
          'eventbus.publish_blocked',
          'decision.recorded', 'agent.action',
        ],
      },
      ...config,
    });
  }

  protected async onStart(): Promise<void> {
    for (const eventType of Object.keys(EVENT_TO_CONTROLS)) {
      this.subscribe(eventType, (event) => this.mapEvent(event.type));
    }
    this.log('info', `Compliance mapper started — tracking ${Object.keys(EVENT_TO_CONTROLS).length} event types`);
  }

  protected async onStop(): Promise<void> {
    this.log('info', `Compliance mapper stopped — ${this.evidenceLog.length} evidence entries`);
  }

  protected async onTick(): Promise<void> {
    this.emit('compliance:report', this.generateReport());
  }

  private mapEvent(eventType: string): void {
    const controlDefs = EVENT_TO_CONTROLS[eventType];
    if (!controlDefs || controlDefs.length === 0) return;

    const ts = new Date().toISOString();
    const controlIds: string[] = [];

    for (const def of controlDefs) {
      if (!this.mappings.has(def.control)) {
        this.mappings.set(def.control, {
          control: def.control,
          function: def.function,
          description: def.description,
          evidenceCount: 0,
        });
      }
      const mapping = this.mappings.get(def.control)!;
      mapping.evidenceCount++;
      mapping.lastObserved = ts;
      controlIds.push(def.control);
    }

    const entry = { event: eventType, controls: controlIds, timestamp: ts };
    if (this.evidenceLog.length >= this.maxEvidenceLog) this.evidenceLog.shift();
    this.evidenceLog.push(entry);

    this.emit('compliance:evidence', entry);
  }

  generateReport(): ComplianceReport {
    return {
      generatedAt: new Date().toISOString(),
      controlsCovered: this.mappings.size,
      totalEvidence: this.evidenceLog.length,
      mappings: Array.from(this.mappings.values())
        .sort((a, b) => b.evidenceCount - a.evidenceCount),
    };
  }
}
