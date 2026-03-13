# EverythingOS

> **A security-first multi-agent framework for building autonomous systems.**  
> NIST AI RMF compliant. Production hardened. 81/81 tests green.

---

## The Problem With AI Agents in Production

Every AI agent framework you've seen was built for demos. They chain LLM calls together, call it an "agent," and ship it. Nobody asks what happens when a model hallucinates a tool call. Nobody asks who's auditing the decisions. Nobody asks what the blast radius is when an autonomous action goes wrong.

EverythingOS was built to ask those questions first.

---

## What It Is

EverythingOS is a TypeScript multi-agent framework designed for autonomous systems that operate in environments where **security, auditability, and containment** are non-negotiable. It's not a toy. It's the infrastructure layer for agents that make real decisions.

- **ModelGuard** — input/output validation layer that sits between every agent and every model call
- **DecisionLedger** — immutable audit log of every agent decision, action, and outcome
- **NIST AI RMF compliance** — risk management framework alignment built into the architecture, not bolted on
- **Full security audit integration** — threat surface analysis baked into the agent lifecycle
- **81/81 passing tests, zero TypeScript errors** — because autonomous systems need verified behavior

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Agent Orchestrator                 │
│          (task routing, agent lifecycle)            │
└──────────────┬──────────────────────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
┌───▼────────┐    ┌───────▼───────┐
│  Agent A   │    │    Agent B    │   ... N agents
└───┬────────┘    └───────┬───────┘
    │                     │
    └──────────┬──────────┘
               │
┌──────────────▼──────────────────────────────────────┐
│                    ModelGuard                       │
│   ┌─────────────────┐   ┌──────────────────────┐   │
│   │  Input Validator│   │  Output Sanitizer    │   │
│   │  (prompt safety)│   │  (action constraint) │   │
│   └─────────────────┘   └──────────────────────┘   │
└──────────────┬──────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────┐
│               LLM / Tool Execution Layer            │
└──────────────┬──────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────┐
│                  DecisionLedger                     │
│        (immutable audit trail, tamper-evident)      │
└─────────────────────────────────────────────────────┘
```

---

## Security Properties

| Property | Implementation |
|----------|---------------|
| Input validation | ModelGuard pre-execution hook on every agent |
| Output containment | Action whitelisting per agent role |
| Decision auditability | DecisionLedger — append-only, cryptographically ordered |
| Model trust boundaries | Per-agent trust level configuration |
| Failure containment | Isolated agent execution contexts |
| AI risk governance | NIST AI RMF Govern / Map / Measure / Manage alignment |

---

## Quick Start

```bash
git clone https://github.com/m0rs3c0d3/everythingos
cd everythingos
npm install

# Run the test suite
npm test
# 81/81 passing, 0 TypeScript errors

# Spin up a basic agent
npx ts-node examples/basic-agent.ts
```

---

## Philosophy: Robots For Peace

EverythingOS exists under a governing principle: **autonomous systems should be auditable, constrained, and accountable.** Not because regulation requires it. Because anything else is reckless.

Every architectural decision in this framework traces back to that principle. ModelGuard exists because unconstrained model output is a security surface. DecisionLedger exists because autonomous actions without audit trails are unacceptable in any serious deployment. NIST AI RMF alignment exists because risk management isn't optional when systems act on their own.

---

## Use Cases

- **AI-assisted security operations** — autonomous triage, alert correlation, response recommendation
- **Robotics control planes** — decision frameworks for physical autonomous systems  
- **Regulated AI deployments** — any environment where AI governance is mandated
- **Red team automation** — safe, audited, contained autonomous offensive tooling

---

## Test Coverage

```bash
npm test

# Test Suites: 81 passed, 81 total
# Tests: 81 passed, 81 total
# TypeScript errors: 0
# Security audit findings: 0 critical, 0 high
```

---

## License

MIT

---

*Part of the [m0rs3c0d3](https://github.com/m0rs3c0d3) security tooling portfolio. Built under the Robots For Peace framework.*
