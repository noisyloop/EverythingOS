# Contributing Agents to EverythingOS

> Every agent you write is automatically covered by the full security pipeline:
> HMAC per-call signing, input sanitization, content filtering, rate limiting,
> and an append-only audit trail. You get all of that for free.
> Your job is to write the domain logic.

---

## Quick Start

```bash
# Copy the scaffold into your own directory
cp -r src/agents/_scaffold src/agents/my-agent

# Fill in the manifest and implement onStart / onTick / onStop
# The directory name becomes your agent's module path in auto-discovery
```

The scaffold at `src/agents/_scaffold/index.ts` is annotated with every decision you need to make. Read it first.

---

## Directory Convention

Each agent lives in its own subdirectory under the appropriate category:

```
src/agents/
  creative/
    echo-chamber/
      index.ts      ← MANIFEST export + default class export
  soc/
    alert-triage/
      index.ts
  _scaffold/        ← starts with '_', skipped by auto-discovery
    index.ts
```

The registry's `loadFromDirectory()` scans subdirectories. It expects:
- A `MANIFEST` named export that passes `validateManifest()`
- A `default` export that is a class extending `Agent`

Directories starting with `_` or `.` are skipped.

---

## Agent Manifest

Every agent must export a validated manifest:

```typescript
import { AgentManifest, validateManifest } from '../../types/agent-manifest';
import { AgentRiskTier } from '../../types/agent-risk';

export const MANIFEST: AgentManifest = validateManifest({
  id: 'my-agent',        // unique, lowercase, hyphens only
  name: 'My Agent',
  version: '1.0.0',      // semver
  category: 'creative',  // see table below
  description: 'What it does and why — minimum 10 characters.',
  capabilities: ['eventbus:publish', 'eventbus:subscribe'],
  trustLevel: AgentRiskTier.LOW,
  tags: ['my-tag'],
  author: 'Your Name',
});
```

Manifest validation runs at load time. Bad manifests are skipped with a warning — they cannot crash other agents.

---

## Categories

| Category | Description | Example agents |
|---|---|---|
| `foundation` | System infrastructure | Clock, HealthMonitor, Shutdown |
| `security` | CVE monitoring, model guard | CveWatch |
| `creative` | Generative, aesthetic, experimental | EchoChamber, HaikuLogger, SwarmVote |
| `soc` | Security operations | AlertTriage, ThreatIntel, AnomalyWatch |
| `robotics` | Physical system planning | MissionPlanner, SafetySupervisor |
| `events` | Live event operations | StageManager, CrowdFlow |
| `research` | Scientific research support | LiteratureReview, HypothesisTracker |
| `finance` | Trading signals, financial analysis | SignalGenerator |
| `comms` | Messaging integrations | DiscordBot, SlackRelay |
| `data` | ETL, enrichment, transformation | DataNormalizer |

---

## Capabilities

Declare only what your agent actually uses. The registry and ModelGuard enforce this list at runtime.

| Capability | What it grants |
|---|---|
| `model:call` | Invoke an LLM via `this.think()` / `this.thinkWithUserInput()` |
| `model:embed` | Generate text embeddings via LLMRouter |
| `memory:read` | Read from any memory store |
| `memory:write` | Write to any memory store |
| `network:http` | Outbound HTTP via `createHttpClient()` (SSRF-protected) |
| `network:ws` | WebSocket connections via websocket-guard |
| `filesystem:read` | Read files from the local filesystem |
| `filesystem:write` | Write files to the local filesystem |
| `hardware:gpio` | Access GPIO hardware |
| `hardware:serial` | Communicate over serial ports |
| `hardware:mqtt` | MQTT publish/subscribe |
| `hardware:i2c` | I2C bus communication |
| `eventbus:publish` | Publish events to the EventBus |
| `eventbus:subscribe` | Subscribe to EventBus channels |
| `ledger:write` | Write to the DecisionLedger |
| `ledger:read` | Read from the DecisionLedger |
| `secrets:read` | Request credentials from CredentialVault |
| `agents:spawn` | Spawn sub-agents |
| `agents:query` | Query AgentRegistry for peer agents |

---

## Trust Tiers

| Tier | Approval | LLM rate limit | Audit | When to use |
|---|---|---|---|---|
| `LOW` | None | 0/min | Off | Read-only, no external calls, no side effects |
| `MEDIUM` | None | 60/min | On | External API calls, user interaction, LLM use |
| `HIGH` | Required¹ | 30/min | On | Consequential real-world actions — trades, deployments, hardware |

¹ HIGH-tier agents route through `ApprovalGateAgent` by default. Set `requiresApproval: false` only if you have a documented reason why the action is automated-safe.

**When in doubt, start at LOW.** Upgrade when you actually add an external call or side effect.

---

## Channels and ACLs

Every channel you call `this.emit()` on must appear in `allowedPublishChannels`.
Every channel you call `this.subscribe()` on must appear in `allowedSubscribeChannels`.

The EventBus enforces this at runtime. Violations are blocked and logged as security events.

Wildcards are supported in declarations: `'alert:*'` matches `alert:critical`, `alert:high`, etc.

**Naming convention:** `category:noun` or `category:noun:verb`. Examples:
- `alert:raw`, `alert:critical`, `alert:stats`
- `intel:ioc:match`, `intel:feed:updated`
- `echo:detected`, `echo:stats`

---

## Lifecycle Methods

```typescript
export default class MyAgent extends Agent {
  // Called once at start. Set up subscriptions and initialize state.
  protected async onStart(): Promise<void> { }

  // Called once at stop. Flush buffers, close connections.
  protected async onStop(): Promise<void> { }

  // Called every tickRate ms if tickRate > 0 in config.
  protected async onTick(): Promise<void> { }
}
```

---

## Patterns

### Subscribe and respond
```typescript
this.subscribe<{ query: string }>('my:request', (event) => {
  const result = this.compute(event.payload.query);
  this.emit('my:response', { result });
});
```

### LLM call (model:call required)
```typescript
const text = await this.think('Summarize this: ' + input, {
  systemPrompt: 'You are a concise summarizer.',
});
```

### User input — always sanitize (model:call + medium/high tier)
```typescript
const { response, sanitized } = await this.thinkWithUserInput(
  'Answer this question: {userContent}',
  userSuppliedText,
);
```

### Consequential action (use act() instead of emit())
```typescript
// act() = emit() + DecisionLedger.record() in one call.
// Use for any action with real-world consequences.
this.act('trade:execute', { symbol: 'BTC', side: 'buy', qty: 0.1 }, {
  reason: 'Signal score exceeded threshold: 0.92',
});
```

### Agent-local state (persisted to WorldState)
```typescript
this.setState('processedCount', count);
const prev = this.getState<number>('processedCount') ?? 0;
```

### Outbound HTTP (network:http required — SSRF protected)
```typescript
import { createHttpClient } from '../../security/http-guard';
private http = createHttpClient();

const resp = await this.http.get<MyResponse>('https://api.example.com/data');
```

---

## Health Check Override

The base `healthCheck()` returns `healthy | degraded | unhealthy | idle`. Override to add domain-specific signals:

```typescript
healthCheck(): HealthStatus {
  return {
    ...super.healthCheck(),
    details: {
      queueDepth: this.queue.length,
      lastProcessed: this.lastProcessed?.toISOString(),
      errorRate: this.errorCount / this.totalCount,
    },
  };
}
```

---

## Testing Requirements

Before opening a PR:

1. `npm test` — all tests pass
2. `npm run typecheck` — zero TypeScript errors
3. `npm run audit:check` — no new high/critical dependency vulnerabilities
4. Add a test that:
   - Starts your agent
   - Exercises the main behavior (subscribe → emit, or tick)
   - Verifies the output event payload
   - Stops the agent cleanly

The test for `EchoChamberAgent` in `tests/agents/creative/echo-chamber.test.ts` is a reference example.

---

## Open Ideas

These are unclaimed agent ideas the community could build. Open an issue to claim one.

**Creative**
- `ContextCompressionAgent` — summarizes long conversation histories before they hit the context window
- `StyleTransferAgent` — rewrites agent outputs in a target tone or style
- `NarrativeLoggerAgent` — converts system events into a running narrative story (longer-form than haiku)
- `DreamAgent` — runs during low-activity periods to synthesize patterns from recent memory into hypotheses

**SOC**
- `ForensicsAgent` — reconstructs event sequences from the audit log for incident investigation
- `RedTeamAgent` — periodically attempts prompt injection against other agents to test their defenses
- `SLAWatchAgent` — monitors agent response times against declared SLAs and alerts on violations

**Comms**
- `SlackBridgeAgent` — bidirectional relay between EventBus channels and a Slack workspace
- `DiscordBridgeAgent` — same for Discord
- `PagerDutyAgent` — escalates CRITICAL alerts to PagerDuty

**Data**
- `SchemaValidatorAgent` — validates incoming event payloads against declared JSON schemas
- `EnrichmentAgent` — augments events with metadata from external APIs (geo-IP, WHOIS, etc.)

**Research**
- `HypothesisTrackerAgent` — accepts a claim and asynchronously tests it against memory and web sources
- `CitationAgent` — finds references for claims made in LLM outputs

**Robotics** (Phase 5 — field time needed first)
- `MissionPlannerAgent`
- `WorldModelAgent`
- `SafetySupervisorAgent`

---

## Security Findings

If you discover a security issue while writing an agent, please report it per [`SECURITY.md`](SECURITY.md) rather than opening a public issue. Don't include exploit details in PR descriptions.
