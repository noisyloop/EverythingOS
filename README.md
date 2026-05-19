# EverythingOS

> **A security-first multi-agent framework for building autonomous systems.**  
> NIST AI RMF aligned · Production-grade architecture · Community contributions welcome

This README is written for three different readers. Go to yours — the sections are deliberately separate and do not repeat each other:

- [**1 · Build a custom agent**](#1--build-a-custom-agent) — you want to ship an agent today.
- [**2 · Security evaluation**](#2--security-evaluation) — you're assessing this for a deployment.
- [**3 · The decision**](#3--the-decision) — you're deciding whether to adopt it.

---

# 1 · Build a custom agent

*For the developer who wants working code, not a security lecture.*

## What this actually does

You write small classes called **agents**. An agent reacts to events ("a message arrived", "a timer ticked"), does some work, and emits events of its own. EverythingOS is the layer underneath that handles the annoying-but-critical parts for you: authenticating every message an agent sends, cleaning untrusted input before it reaches a model, recording an audit trail, and rate-limiting runaway loops. You write the behavior; the framework keeps it accountable.

## Run it in ~15 minutes

```bash
git clone https://github.com/noisyloop/EverythingOS
cd EverythingOS
npm ci          # use ci, not install — lockfile is law

# Create .env with a signing secret (required in production):
echo "EOS_AGENT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")" > .env

npm test           # run the full test suite
npm run e2e:proof  # prove the whole stack works, end to end, with no mocks
```

`npm run e2e:proof` is the fastest way to see the system actually work: it registers a real agent, pushes untrusted input through the sanitization pipeline, writes a file, emits over the event bus, and verifies a tamper-evident ledger entry. If any layer is broken it names the layer and exits non-zero.

## Make your own agent

```bash
npx everythingos new my-agent     # alias: npx eos new my-agent
```

It asks two questions — a **risk tier** (LOW / MEDIUM / HIGH) and a **description** — then generates `src/agents/my-agent/index.ts` from the maintained template at `src/agents/_scaffold`. A generated agent looks like this (real, trimmed):

```ts
export const MANIFEST: AgentManifest = validateManifest({
  id: 'my-agent',
  name: 'My Agent',
  version: '0.1.0',
  category: 'foundation',
  description: 'What this agent does — at least 10 characters.',
  capabilities: ['eventbus:publish', 'eventbus:subscribe'],
  trustLevel: AgentRiskTier.LOW,
  tags: ['my-agent'],
  author: 'You',
});

export default class MyAgentAgent extends Agent {
  constructor(config?: Partial<AgentConfig>) {
    super({
      id: MANIFEST.id,
      name: MANIFEST.name,
      type: 'foundation',
      riskConfig: {
        tier: AgentRiskTier.LOW,
        riskJustification: 'Why this agent is safe at this tier',
        allowedPublishChannels: ['my-agent:heartbeat'],   // exactly what you emit
        allowedSubscribeChannels: ['my-agent:ping'],       // exactly what you hear
      },
      ...config,
    });
  }

  protected async onStart(): Promise<void> {
    this.subscribe<{ from?: string }>('my-agent:ping', (event) => {
      this.log('info', 'ping', { from: event.payload.from });
      this.emit('my-agent:heartbeat', { pong: true, agentId: this.id });
    });
  }

  protected async onStop(): Promise<void> {}
}
```

Register and run it (same pattern as [`examples/demo-simple.ts`](examples/demo-simple.ts)):

```ts
import MyAgentAgent from './src/agents/my-agent';
import { agentRegistry } from './src';

agentRegistry.register(new MyAgentAgent());
await agentRegistry.start('my-agent');
```

## The rules — and why they exist

These aren't bureaucracy. Each one stops a specific failure:

- **You must declare every channel you publish or subscribe to.** No wildcards. *Why:* a buggy or compromised agent physically cannot talk on channels it never declared — the blast radius is bounded by the manifest, not by hope.
- **Every agent declares a risk tier.** *Why:* the framework applies tier-appropriate controls automatically (LLM rate limits, input/output auditing). HIGH-tier agents will not start without a registered `ApprovalGateAgent`.
- **Untrusted input goes through `this.thinkWithUserInput()` (or `sanitizeInput()`), never raw into a prompt.** *Why:* a Unicode-aware injection/PII pipeline runs first, so a crafted message can't smuggle instructions into your model call.
- **Consequential actions use `this.act()`, not `this.emit()`.** *Why:* `act()` emits *and* writes a tamper-evident decision-ledger entry, so the action is provable after the fact.

The manifest is Zod-validated at load time — typos fail loudly at startup, not silently in production.

## What happens after your first agent runs

You now extend it: put real logic in `onStart`/`onTick`, add channels to the allowlists as you use them, call `this.think()` for LLM work (configure `llm` in the constructor), and `this.act()` for anything with real-world effect. The STEP 3 comment block in your generated file documents `setState/getState`, `healthCheck()` overrides, and the LLM helpers. When you're ready to trust the whole chain, read [`examples/e2e-proof.ts`](examples/e2e-proof.ts) — it's the worked example of an agent going through every layer for real. To extend EverythingOS to external systems or hardware without touching the core, build a **bridge** — see [`BRIDGES.md`](BRIDGES.md).

---

# 2 · Security evaluation

*For the security engineer deciding whether this is safe to deploy. Read [`docs/STRIDE.md`](docs/STRIDE.md) alongside this — it is the authoritative threat model and it self-audits.*

## What "security-first" means here — in code vs. as a slogan

**In the codebase, concretely:** per-call HMAC signing with nonce + replay window on every `emit()`/`subscribe()`; a channel ACL that is enforced, not advisory; a mandatory input-sanitization pipeline baked into the `Agent` base class (you cannot easily bypass it); a hash-chained, tamper-evident audit log and decision ledger; CI gates that fail the build on dependency CVEs, secrets, SSRF regressions, and STRIDE claim/evidence drift; and a threat model that downgraded its own previously-false "resolved" markers during a verification audit.

**As a slogan, honestly:** "production-grade architecture" describes the *design*. It is **not** a claim that isolation is finished. The largest open item — **STRIDE E-2 (CRITICAL, ❌ not implemented)** — means all agents, every tier, share one Node.js process and one V8 heap. Risk tiers are an **enforced policy control, not a memory/process isolation boundary.** `IsolatedAgentRunner` exists in the tree but has zero callers; it is not wired into the agent lifecycle. Plan for this.

## Trust boundary model

```
┌────────────────────────────────────────────────────────────────────────┐
│  Single Node.js process — ONE V8 heap (NO per-agent isolation today)    │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Agent Orchestrator — AgentRegistry                              │  │
│  │  (lifecycle, risk-tier preflight, emergency stop)               │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│        │                │                 │                            │
│   ┌────▼────┐      ┌────▼────┐       ┌────▼────┐                        │
│   │  Agent  │      │  Agent  │       │  Agent  │   LOW · MEDIUM · HIGH  │
│   │  (LOW)  │      │  (MED)  │       │  (HIGH) │   all share this heap  │
│   └────┬────┘      └────┬────┘       └────┬────┘                        │
│        └────────────────┼─────────────────┘                            │
│                         ▼                                              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  EventBus  (per-call HMAC sig · nonce · ACL · rate-limited)      │  │
│  └─────────────────────────────┬────────────────────────────────────┘  │
│                                ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Security Pipeline                                              │  │
│  │  agent-auth · sanitize (NFKC + injection) · content-filter      │  │
│  └─────────────────────────────┬────────────────────────────────────┘  │
│                                ▼                                       │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────────┐    │
│  │ PolicyEng. │ │ ModelGuard │ │ Credential │ │ ApprovalGateAgent│    │
│  │ /Supervisor│ │ allowlist+ │ │ Vault      │ │ (HIGH-tier human │    │
│  │ (locked at │ │ fingerprint│ │ scoped TTL │ │  in-the-loop;    │    │
│  │  startup)  │ │            │ │            │ │  out-of-band)    │    │
│  └─────┬──────┘ └─────┬──────┘ └────────────┘ └──────────────────┘    │
│        └──────────────┼───────────────────────────────────────┐       │
│                       ▼                                        │       │
│  ┌──────────────────────────────────────────────────────────┐ │       │
│  │  Audit Trail + Decision Ledger                           │ │       │
│  │  (hash-chained · async · append-only JSONL)              │ │       │
│  └──────────────────────────────────────────────────────────┘ │       │
│                                                                │       │
│  ┌──────────────────────────────────────────────────────────┐ │       │
│  │  Plugin Sandbox — SEPARATE worker_thread heap            │◄┘       │
│  │  (the only real in-process isolation boundary today)     │         │
│  └──────────────────────────────────────────────────────────┘         │
└───────────────────────────────┬────────────────────────────────────────┘
                                │  outbound only via http-guard (SSRF/DNS)
                                ▼
     External APIs   ·   Glasswally output dir  ──►  GlasswallyAgent
                         (HMAC-signed IOC bundles → SOC alert events)
```

Trust boundaries **TB-1 … TB-9** (Agent↔EventBus, EventBus↔Pipeline, Agent↔LLM/ModelGuard, Agent↔CredentialVault, Main↔PluginWorker, EverythingOS↔HumanApprover, Process↔Filesystem, EverythingOS↔ExternalHTTP, EverythingOS↔Glasswally) are enumerated with per-finding analysis in [`docs/STRIDE.md`](docs/STRIDE.md). The **only** real in-process isolation boundary today is TB-5 (the plugin worker). Everything else inside the process is a control, not a wall.

## What the CI gates enforce

A PR cannot merge unless these pass (`.github/workflows/security.yml`): TypeScript type check; full security test suite; SSRF regression (http-guard enforcement); audit-chain integrity verification; the **STRIDE claim/evidence gate** (every ✅ in the threat model must be test-backed or audit-attested — the doc and code cannot silently diverge); `npm audit` at high/critical; Gitleaks secret scan; Node version gate; CodeQL/static analysis. SBOM generation runs on main. This is the mechanism that keeps "security-first" from rotting into a slogan.

## Implemented controls (where the code lives)

Each is a real, wired control. File paths are load-bearing.

- **Per-call HMAC authentication** — fresh nonce per `emit()`/`subscribe()`, signs `agentId:channel:nonce:timestamp` with a per-agent key; 60s clock-skew window; 5-min nonce replay rejection; revocations persist to disk and survive restart. `src/security/agent-auth.ts`, `src/runtime/Agent.ts`
- **Unicode-aware input sanitization** — NFKC normalization, zero-width stripping, whitespace collapse, then injection-pattern matching and PII scrubbing; only normalized text is forwarded, raw is hashed for audit. `src/security/sanitize.ts`
- **HTTP guard** — SSRF blocklist (RFC1918/link-local/loopback/cloud-metadata), async DNS-rebinding revalidation, `maxRedirects: 0`, scheme blocking (CVE-2025-58754), `allowAbsoluteUrls:false` (CVE-2025-27152). A CI step rejects raw `axios` imports elsewhere. `src/security/http-guard.ts`
- **Tamper-evident audit log** — append-only JSONL, each entry carries the prior entry's SHA-256; `verifyChain()` detects tampering in O(n); async `WriteStream`; raw content never logged. `src/security/audit-log.ts`
- **Model Guard** — provider:model allowlist (unapproved throws before any API call) plus deterministic behavioral fingerprinting against a baseline. **Caveat (STRIDE T-2, HIGH/partial):** the fingerprint baseline is HMAC-signed with `MODEL_GUARD_SIGN_KEY` if set, otherwise it falls back to `EOS_AGENT_SECRET` and then to a hardcoded dev key — so the baseline is only as strong as that key and is forgeable by anyone who can read it unless `MODEL_GUARD_SIGN_KEY` is explicitly configured. `src/security/model-guard.ts`
- **Credential vault** — agents get a scoped `credentialId` (provider+task, TTL ≤1h), never the raw key; every grant/expiry/revoke is logged. `src/security/credential-vault.ts`
- **Memory safety** — `recall()` results pass back through the injection pipeline and are wrapped in an explicit "treat as data, not instructions" trust label. `src/services/memory/MemoryService.ts`
- **EventBus rate limiting** — per-source 200 events/60s plus a global ceiling; stale counters purged on a timer. `src/core/event-bus/EventBus.ts`
- **Plugin sandbox** — untrusted plugins run in a `worker_threads` heap with a memory cap, per-call timeout, structured `postMessage` only, and sanitized config in / sanitized returns out. This is the one real isolation boundary. `src/security/plugin-sandbox.ts`
- **Glasswally integration** — tails Glasswally's eBPF enforcement output, sanitizes every free-text field through the injection pipeline, HMAC-verifies IOC bundles before forwarding (a bad signature is treated as an attack, not a data error), and maps actions to SOC severities. `src/agents/security/glasswally/index.ts`
- **Risk-tier preflight** — declared at registration; `AgentRegistry` runs a compliance preflight on the real start path. **Honest scope (Flag/STRIDE E-2):** HIGH-tier agents must clear an `ApprovalGateAgent` preflight and approvals arrive on an authenticated out-of-band channel (not the EventBus). But because there is no per-agent process isolation, this is an **enforced runtime policy, not a containment guarantee** — a compromised in-process agent of any tier shares the heap and is not walled off by the tier system. "No actuator without an approval gate" holds against *honest* agents and accidental misuse; it does **not** hold against a compromised in-process agent until E-2 is implemented. `src/types/agent-risk.ts`, `src/core/registry/AgentRegistry.ts`

## What is still open (do not deploy blind to these)

From the authoritative Finding Summary in [`docs/STRIDE.md`](docs/STRIDE.md):

- **E-2 — CRITICAL, ❌ NOT IMPLEMENTED.** No per-agent process isolation; risk tiers are not a security boundary. The single largest gap.
- **S-1 (HIGH, ⚠️)** in-process token-registry exposure; **S-3 (MED, ⚠️)** runtime model-approval has no caller auth; **T-2 (HIGH, ⚠️)** fingerprint key not cryptographically separate unless `MODEL_GUARD_SIGN_KEY` is set; **I-5 (LOW, ⚠️)** approved-model list leaks via `violations.jsonl`.
- **D-5, E-1 — research-grade (🔬):** formal proofs of the replay/approval protocols, not code tasks.

Additional honest limitations (mitigated, not eliminated): swarm mesh has no X.509 mTLS (HMAC `meshSecret` only); the credential vault seals secrets out of `process.env` only when prod-gated; built-in fingerprint probes are the default unless overridden; long-term memory uses trust-scored keyword search, not semantic provenance; Glasswally's eBPF mode requires a **separate privileged process** (`CAP_BPF`, Linux ≥5.8) — `tail` mode runs anywhere but loses kernel visibility.

## NIST mapping

Every control is mapped to NIST AI RMF 1.0 / AI 600-1 / CSF 2.0 function and practice ID, with verification evidence, in [`docs/CONTROLS.md`](docs/CONTROLS.md) (GOVERN/MAP/MEASURE/MANAGE, 26 controls). Treat it as the audit/procurement artifact; treat `docs/STRIDE.md` as the adversarial one.

---

# 3 · The decision

*Three paragraphs. No diagrams, no code.*

Autonomous agents increasingly take consequential actions — moving money, deploying code, driving hardware. The unsolved operational problem is not capability; it is accountability and blast radius: when a model hallucinates a tool call or an agent is compromised, most teams cannot answer *who approved this, what exactly ran, and what was the containment*. EverythingOS exists to make those questions answerable structurally rather than by post-hoc log spelunking.

Existing agent frameworks are orchestration libraries: they chain model calls and leave authentication, input sanitization, audit, and containment to whoever integrates them — which in practice means inconsistently or not at all. EverythingOS makes per-call authentication, a mandatory input-sanitization pipeline, a tamper-evident decision ledger, risk-tier preflight enforcement, and a *published, self-auditing* STRIDE threat model first-class and CI-enforced. The honest trade to weigh: today's containment is real at the plugin boundary (separate worker heap) and is *policy-enforced* at the agent boundary — full per-agent process isolation (STRIDE E-2) is on the roadmap, not shipped. If your threat model includes a compromised in-process agent, that gap is the deciding factor; if it centers on accountability, hallucinated actions, untrusted input, and supply-chain/CVE hygiene, the shipped controls are substantive and verifiable.

Deployment requirements are modest: a single Node.js process (Node ≥20.20, pinned to 22.22 via `.nvmrc`), `EOS_AGENT_SECRET` set in production, optional `MODEL_GUARD_SIGN_KEY` and prod-gated secret sealing, and no external database — the audit log and decision ledger are append-only JSONL on the local filesystem (size and rotation are your responsibility). Glasswally is optional and, for kernel-level detection, needs a separate privileged eBPF process. Licensed MIT. The fastest due-diligence step is `npm run e2e:proof` plus a read of `docs/STRIDE.md`: the first proves the pipeline runs end-to-end with no mocks; the second tells you, in the project's own words, exactly what is and isn't done.

---

## Contributing

EverythingOS is built on the premise that agentic security is a hard, unsolved problem. The open items above are not a bug list — they're research and engineering problems the community is better positioned to solve together.

- **Open a Discussion** if you've worked on agent security, formal verification, secrets management, or distributed systems.
- **Security findings:** follow [`SECURITY.md`](SECURITY.md). Don't open public issues for unpatched vulnerabilities.
- **New controls:** PRs welcome — include the threat being mitigated and a test demonstrating the attack path.
- **NIST/compliance:** if declared alignment and implementation diverge, open an issue.
- **Hardware/robotics safety:** the swarm and hardware layers have the weakest safety properties; functional-safety and ROS 2 security expertise is especially welcome.

Before opening a PR: `npm test`, `npm run typecheck`, `npm run audit:check`, and add a test for the security property you changed.

## License

MIT

---

*EverythingOS is part of the [noisyloop](https://github.com/noisyloop) security tooling portfolio. Built under the Robots For Peace framework — autonomous systems should be auditable, constrained, and accountable.*
