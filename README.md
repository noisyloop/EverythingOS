# EverythingOS

**LLM-agnostic multi-agent framework with mandatory security enforcement and NIST AI RMF compliance.**

Most agent frameworks are capability-first and security-optional. EverythingOS inverts that. Every agent declares its risk tier before it runs. Every LLM call is logged with a tamper-evident hash chain. Every credential expires. Every misbehaving agent can be isolated surgically without shutting down the system.

Security is not a layer you add on top. It is the substrate everything else runs on.

---

## Why this exists

Frameworks like LangChain, AutoGen, and CrewAI make it easy to build agents that do things. None of them make it easy to prove what your agents did, why they did it, or that they stayed within their authorized boundaries while doing it.

EverythingOS was built for deployments where those questions matter — financial systems, robotics, infrastructure automation, any context where an agent acting outside its boundaries causes real harm.

If you need an agent framework you can audit, this is it.

---

## What's different

| Capability | Most frameworks | EverythingOS |
|------------|----------------|--------------|
| Risk tier enforcement | ❌ | ✅ Mandatory — TypeScript won't compile without it |
| Tamper-evident audit log | ❌ | ✅ Hash-chained — chain breaks if log is altered |
| LLM decision provenance | ❌ | ✅ Every LLM call recorded with model, prompt hash, output hash |
| Credential isolation | ❌ | ✅ Ephemeral scoped tokens — no agent holds raw keys |
| Surgical quarantine | ❌ | ✅ Isolate one agent without stopping others |
| Approved model allowlist | ❌ | ✅ Unapproved models throw before the request is made |
| Behavioral fingerprinting | ❌ | ✅ Detects silent model weight changes |
| NIST AI RMF compliance | ❌ | ✅ 26 mapped controls, all four functions |
| Continuous adversarial eval | ❌ | ✅ Signed reports accumulate as dated evidence |
| Human-in-the-loop gate | ❌ | ✅ HIGH risk agents require ApprovalGateAgent |

---

## Quick start

```bash
git clone https://github.com/m0rs3c0d3/EverythingOS.git
cd EverythingOS
nvm use        # pins to Node 22.22.0
npm install
cp .env.example .env
npm run dev
```

### Write your first agent

Every agent must declare a risk tier. TypeScript enforces this — missing `riskConfig` is a compile error.

```typescript
import { Agent } from './src/runtime/Agent';
import { AgentRiskTier } from './src/types/agent-risk';

class MyAgent extends Agent {
  constructor() {
    super({
      id: 'my-agent',
      name: 'MyAgent',
      type: 'execution',
      description: 'What this agent does',

      riskConfig: {
        tier: AgentRiskTier.MEDIUM,

        // Declare exactly what this agent can touch — nothing else is accessible
        allowedPublishChannels: ['my-service:response'],
        allowedSubscribeChannels: ['my-service:request'],

        // Required for any agent that calls an LLM
        genAIRisks: {
          promptInjectionRisk: true,
          piiRisk: false,
          hallucinationRisk: true,
          harmfulContentRisk: false,
          dataPrivacyRisk: false,
          informationIntegrityRisk: false,
          physicalSafetyRisk: false,
        },

        riskJustification: 'Processes requests and calls Anthropic API',
        llmRateLimit: 60,
        auditInputs: true,
        auditOutputs: true,
        dataClassification: 'internal',
      },

      llm: {
        provider: 'anthropic',
        model: 'claude-sonnet-4-20250514',
        temperature: 0.7,
      },
    });
  }

  protected async onStart(): Promise<void> {
    this.subscribe<{ content: string }>('my-service:request', async (event) => {
      // thinkWithUserInput() runs the mandatory pipeline:
      //   sanitize injection patterns → scrub PII → call LLM →
      //   filter output → log input hash + output hash to audit trail
      // You cannot skip these steps. They are in the base class.
      const { response } = await this.thinkWithUserInput(
        'Process this request: {userContent}',
        event.payload.content,
      );

      this.emit('my-service:response', { content: response });
    });
  }

  protected async onStop(): Promise<void> {}
}
```

The framework blocks anything that violates the declared contract:

```
// Trying to emit to an undeclared channel at runtime:
// [Agent:my-agent] Publish to 'system:config' blocked — not in allowedPublishChannels
// → logged to audit trail as 'agent.permission_denied'
```

---

## Risk tiers

Three tiers, progressively tighter constraints:

**LOW** — Read-only agents, data aggregation, monitoring. No LLM calls. No network egress. Quarantine-capable.

**MEDIUM** — Network-enabled agents with LLM access. Rate limited. Allowlisted egress only. Requires `genAIRisks` declaration. All inputs and outputs hash-logged.

**HIGH** — Agents that take irreversible actions — financial trades, hardware commands, system changes. Requires `riskJustification`. Requires `ApprovalGateAgent` to be running. Stricter rate limits. Ephemeral scoped credentials with 1-hour TTL max.

AgentRegistry runs a compliance pre-flight check before any agent starts. A HIGH risk agent missing its `riskJustification` never starts — it throws with the exact reason.

---

## Security architecture

```
Request
  │
  ▼
sanitizeInput()          ← strips prompt injection patterns
  │
  ▼
scrubPII()               ← removes PII before LLM sees it
  │
  ▼
checkRateLimit()         ← per-agent, per-tier limit
  │
  ▼
ModelGuard.assertApproved()   ← allowlist check, throws if unapproved
  │
  ▼
DecisionLedger.buildContext() ← records model, prompt hash, parameters
  │
  ▼
LLM call
  │
  ▼
DecisionLedger.record()  ← records output hash, links to context
  │
  ▼
filterOutput()           ← blocks harmful content in response
  │
  ▼
AuditLogger.log()        ← hash-chained tamper-evident entry
  │
  ▼
Response
```

Every step is mandatory. The base class enforces the pipeline — subclasses call `think()` or `thinkWithUserInput()` and get all of it automatically.

### Audit log

The audit log is hash-chained. Each entry contains the SHA-256 hash of the previous entry. If any entry is tampered with, all subsequent hashes become invalid. `AuditLogger.verifyChain()` detects this.

```typescript
const result = AuditLogger.verifyChain();
// { valid: true, entries: 847 }
// or
// { valid: false, reason: 'Chain broken at entry 412', entries: 847 }
```

### Decision ledger

Every LLM call produces a ledger entry — not just that a call happened, but which model, which prompt template (by hash), which parameters, and a hash of the output. An investigator can reconstruct the exact context of any decision.

```typescript
const entry = DecisionLedger.getEntry(ledgerId);
// {
//   agentId: 'trading-executor',
//   modelId: 'claude-sonnet-4-20250514',
//   modelIdHash: 'a3f8...',
//   promptTemplateHash: 'd291...',
//   inputHash: 'b7c4...',
//   outputHash: '91ab...',
//   timestamp: '2026-02-21T18:30:00Z',
//   ...
// }
```

### Model guard

Every LLM call is checked against an approved model allowlist before the request is made. Unapproved models throw immediately.

```typescript
// This throws before touching the network:
await llmRouter.complete({
  provider: 'anthropic',
  model: 'some-unlisted-model',  // ← [ModelGuard] Model not in approved list
  messages: [...],
});
```

Behavioral fingerprinting runs on a weekly schedule and hashes the outputs of fixed deterministic probes at temperature 0. If the outputs change, the model changed — even if the version string didn't.

### Quarantine

Quarantine is surgical. One misbehaving agent can be isolated — event bus unsubscribed, credentials revoked, state snapshot captured — without touching other agents.

```typescript
await QuarantineManager.quarantine({
  agentId: 'compromised-agent',
  reason: 'Attempted unauthorized channel publish',
  triggeredBy: 'supervisor',
});
// Token revoked, event bus subscriptions removed, forensic snapshot saved
// Other agents continue running
```

### Credential vault

Agents never hold credentials directly. The vault issues ephemeral scoped tokens — each agent gets access to exactly what it needs, and only for as long as it needs it.

```typescript
const cred = await CredentialVault.issue({
  agentId: 'my-agent',
  scope: ['read:market-data'],
  ttlSeconds: 3600,  // max 1 hour for HIGH tier
});
// On expiry, credential is automatically revoked
// On quarantine, credential is immediately revoked
```

---

## Compliance

EverythingOS maps all 26 security controls to specific files with verification methods. See [`docs/CONTROLS.md`](docs/CONTROLS.md) for the full mapping.

NIST AI RMF 1.0 coverage:

- **GOVERN** — Risk policy, ethics policy, usage policy, incident response
- **MAP** — Risk tier system, genAI risk declarations, threat modeling
- **MEASURE** — Continuous adversarial eval, behavioral fingerprinting, audit chain verification
- **MANAGE** — Quarantine, credential vault, emergency stop, approval gate

NIST AI 600-1 (GenAI) risk categories covered: prompt injection, PII/privacy, harmful content, information integrity, data poisoning, model behavioral change.

The adversarial eval harness runs weekly in CI and produces signed, content-addressed JSON reports. Each report accumulates in `eval-reports/index.jsonl`. Twelve weeks of passing reports is a different kind of evidence than a one-time test.

See [`docs/containment-policy.md`](docs/containment-policy.md) for runtime containment boundaries per tier and [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md) for the incident response runbook.

---

## Robotics

EverythingOS operates above ROS2. ROS handles real-time control. EverythingOS handles decision authority — what the robot is allowed to do, who approved it, and what happened.

The safety architecture applies the same tier system to physical agents: LOW for sensors and telemetry, HIGH for motion commands. HIGH-tier physical agents require `ApprovalGateAgent` and a documented `riskJustification` that names the physical consequences of failure.

```typescript
riskConfig: {
  tier: AgentRiskTier.HIGH,
  riskJustification: 'Controls manipulator arm — commands are physically irreversible',
  genAIRisks: {
    physicalSafetyRisk: true,  // triggers additional review requirements
    ...
  },
  requiresApproval: true,
}
```

See [`BRIDGES.md`](BRIDGES.md) for the ROS2 bridge specification and the extension model.

---

## Project structure

```
src/
  runtime/
    Agent.ts              ← base class — mandatory security pipeline
    AgentRegistry.ts      ← compliance pre-flight, emergency stop
    LLMRouter.ts          ← provider-agnostic LLM interface
  security/
    audit-log.ts          ← hash-chained tamper-evident logger
    decision-ledger.ts    ← LLM provenance records
    model-guard.ts        ← approved model allowlist + fingerprinting
    agent-auth.ts         ← HMAC token auth
    sanitize.ts           ← input sanitization + PII scrubbing
    content-filter.ts     ← output filtering
    http-guard.ts         ← SSRF-resistant HTTP client
    websocket-guard.ts    ← secure WebSocket wrapper
    credential-vault.ts   ← ephemeral scoped credentials
    quarantine.ts         ← surgical agent isolation
  agents/
    decision/
      ApprovalGateAgent.ts  ← human-in-the-loop for HIGH risk
    foundation/
      CveWatchAgent.ts      ← automated CVE monitoring
  api/
    server.ts             ← REST API, compliance endpoints
    compliance.ts         ← NIST compliance status API
docs/
  CONTROLS.md             ← 26 controls mapped to files + NIST references
  containment-policy.md   ← runtime boundaries per tier
  AI_ETHICS.md
  AI_USAGE_POLICY.md
  INCIDENT_RESPONSE.md
tests/
  security/
    prompt-injection.test.ts
  eval/
    eval-harness.ts       ← continuous adversarial evaluation
```

---

## Philosophy

Autonomous systems should be built to protect people, not to make compliance someone else's problem.

Every design decision in EverythingOS comes back to three questions: Can you stop it? Can you prove what it did? Can you contain the damage if it goes wrong?

If the answer to any of those is no, the feature doesn't ship.

**Robots For Peace.**

---

## Contributing

See [`BRIDGES.md`](BRIDGES.md) for how to extend EverythingOS without modifying core behavior.

Security issues: see [`SECURITY.md`](SECURITY.md) for the disclosure process.

---

## License

MIT
