// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Agent Scaffold
// Copy-paste contributor template.
// Usage: cp -r src/agents/_scaffold src/agents/my-agent
// Then: rename the class, fill in the manifest, implement onStart/onTick/onStop.
// This directory is skipped by auto-discovery (starts with '_').
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent, AgentConfig } from '../../runtime/Agent';
import { AgentRiskTier } from '../../types/agent-risk';
import { AgentManifest, validateManifest } from '../../types/agent-manifest';

// ─────────────────────────────────────────────────────────────────────────────
// STEP 1 — Fill in the manifest.
// Every field is Zod-validated at load time; typos fail loudly at startup.
// Claim only the capabilities you actually use — principle of least capability.
// ─────────────────────────────────────────────────────────────────────────────

export const MANIFEST: AgentManifest = validateManifest({
  id: 'scaffold',                        // unique slug: lowercase, hyphens only
  name: 'Scaffold Agent',                // human-readable display name
  version: '0.1.0',                      // semver — bump on breaking changes
  category: 'foundation',               // see AgentCategoryEnum for all options
  description: 'Copy-paste contributor template — replace this description with at least 10 chars.',
  capabilities: [
    'eventbus:publish',
    'eventbus:subscribe',
    // Add from: model:call, memory:read/write, network:http, filesystem:read/write,
    //           hardware:gpio/serial/mqtt/i2c, ledger:write/read, secrets:read,
    //           agents:spawn/query, model:embed
  ],
  trustLevel: AgentRiskTier.LOW,         // LOW | MEDIUM | HIGH
  tags: ['scaffold', 'template'],
  author: 'Your Name / Team',
  // homepage: 'https://github.com/your-org/your-agent',
});

// ─────────────────────────────────────────────────────────────────────────────
// STEP 2 — Implement the agent class.
// Rename ScaffoldAgent to match your agent. The constructor must call super()
// with config that includes every channel you'll publish or subscribe to.
// ─────────────────────────────────────────────────────────────────────────────

export default class ScaffoldAgent extends Agent {
  constructor(config?: Partial<AgentConfig>) {
    super({
      id: MANIFEST.id,
      name: MANIFEST.name,
      type: 'foundation',   // perception | analysis | decision | execution | learning | orchestration | foundation
      description: MANIFEST.description,
      tickRate: 0,          // >0 = periodic onTick() in ms; 0 = no ticking
      riskConfig: {
        tier: AgentRiskTier.LOW,
        riskJustification: 'Template agent — no external calls or side effects',
        // List every channel you will call emit() on:
        allowedPublishChannels: ['scaffold:heartbeat'],
        // List every channel you will call subscribe() on:
        allowedSubscribeChannels: ['scaffold:ping'],
      },
      ...config,
    });
  }

  // ─── LIFECYCLE ────────────────────────────────────────────────────────────

  // Called once when the agent starts.
  // Set up subscriptions, initialize state, connect to external services.
  protected async onStart(): Promise<void> {
    this.subscribe<{ from?: string }>('scaffold:ping', (event) => {
      this.log('info', 'Received ping', { from: event.payload.from });
      this.emit('scaffold:heartbeat', { pong: true, agentId: this.id });
    });

    this.log('info', 'Scaffold agent started — replace this with real logic');
  }

  // Called once when the agent stops.
  // Clean up timers, close connections, flush buffers.
  protected async onStop(): Promise<void> {
    this.log('info', 'Scaffold agent stopped');
  }

  // Called every tickRate ms if tickRate > 0.
  // Keep this fast — expensive async work belongs in separate methods.
  protected async onTick(): Promise<void> {
    // this.emit('scaffold:heartbeat', { tick: Date.now() });
  }

  // ─── STEP 3 — Add domain methods below ───────────────────────────────────
  //
  // Consequential action (HIGH/MEDIUM tier — logged to DecisionLedger):
  //   this.act('my-agent:action', payload, { reason: 'why this action' });
  //
  // LLM call (requires config.llm in constructor):
  //   const text = await this.think('Your prompt');
  //
  // User-supplied input (always sanitize!):
  //   const { response } = await this.thinkWithUserInput(
  //     'Answer: {userContent}', untrustedInput
  //   );
  //
  // Agent-local state (persisted to WorldState):
  //   this.setState('myKey', value);
  //   const val = this.getState<MyType>('myKey');
  //
  // Health override (return domain-specific signals):
  //   healthCheck(): HealthStatus {
  //     return { ...super.healthCheck(), details: { queueDepth: this.queue.length } };
  //   }
}
