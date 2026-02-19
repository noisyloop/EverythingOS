# Security Controls Mapping

**Framework:** NIST AI RMF 1.0 | NIST AI 600-1 | NIST CSF 2.0  
**Last Updated:** February 2026  
**Policy Version:** 1.0.0

This document maps every security control in EverythingOS to its specific NIST function, category, and practice ID. It exists to convert "aligned with NIST" into "demonstrably operating under NIST logic" — the distinction that matters in audits, procurement reviews, and enterprise security assessments.

---

## How to Read This Document

Each row is a control. Columns are:

| Column | Meaning |
|--------|---------|
| **File** | The file implementing the control |
| **Control** | What the control does in one line |
| **NIST AI RMF** | Function + Practice ID from NIST AI RMF 1.0 |
| **NIST AI 600-1** | GenAI risk category addressed (where applicable) |
| **NIST CSF 2.0** | CSF 2.0 function + category (where applicable) |
| **Evidence** | How to verify this control is operating |

---

## GOVERN — Policies, Roles, and Accountability

Controls that establish who is responsible for what and under what rules the system operates.

| File | Control | NIST AI RMF | NIST AI 600-1 | NIST CSF 2.0 | Evidence |
|------|---------|-------------|---------------|--------------|---------|
| `SECURITY.md` | Vulnerability disclosure policy, known risk areas, responsible use obligations | GV-1.1, GV-1.2 | — | GV.OC-01 | File exists in repo root; GitHub Security Advisory configured |
| `AI_USAGE_POLICY.md` | Permitted uses by risk tier, LLM provider obligations, prohibited uses | GV-1.1, GV-1.2, GV-4 | — | GV.PO-01 | File exists in repo root |
| `AI_ETHICS.md` | Ethical principles governing agent behavior and deployment | GV-1.1, GV-6 | — | GV.OC-02 | File exists in repo root |
| `src/types/agent-risk.ts` | Agent risk tier taxonomy (LOW/MEDIUM/HIGH) with mandatory declaration at registration | GV-2, MP-2 | — | GV.RR-01 | Every agent instantiation requires `riskConfig`; TypeScript enforces at compile time |
| `src/core/AgentRegistry.ts` | Compliance preflight checks block non-compliant agents from starting | GV-2, GV-4 | — | GV.RR-02 | `preflightCheck()` throws on HIGH tier without ApprovalGate; verified in CI |
| `INCIDENT_RESPONSE.md` | Roles, severity levels, and escalation paths for incidents | GV-4, MG-4 | — | GV.RR-03 | File exists in repo root; runbooks per severity level documented |

---

## MAP — Risk Identification and Classification

Controls that identify, classify, and document risks before agents are deployed.

| File | Control | NIST AI RMF | NIST AI 600-1 | NIST CSF 2.0 | Evidence |
|------|---------|-------------|---------------|--------------|---------|
| `src/types/agent-risk.ts` | `AgentRiskConfig` interface enforces structured risk declaration including GenAI risk flags | MP-2, MP-4 | All 12 GenAI risk categories | ID.RA-01 | Type check at compile time; registry rejects agents missing `genAIRisks` when LLM is configured |
| `src/types/agent-risk.ts` | `GenAIRiskFlags` maps NIST AI 600-1 risk categories to boolean flags per agent | MP-4, MP-5 | CBRN, CSAM, hallucination, PII, prompt injection, harmful content | ID.RA-03 | Flags are required for MEDIUM+ LLM agents; checked in `AgentRegistry.preflightCheck()` |
| `src/examples/compliant-agents.ts` | Reference agent implementations demonstrating compliant risk declarations | MP-2 | — | ID.RA-06 | Runnable examples with correct and incorrect configurations annotated |
| `CONTROLS.md` *(this file)* | Explicit mapping of every control to NIST function and practice ID | MP-1, MP-6 | — | ID.RA-01 | This document; versioned in git alongside code |

---

## MEASURE — Testing, Monitoring, and Evidence

Controls that produce measurable, verifiable evidence that the system is operating as intended.

| File | Control | NIST AI RMF | NIST AI 600-1 | NIST CSF 2.0 | Evidence |
|------|---------|-------------|---------------|--------------|---------|
| `src/security/audit-log.ts` | Append-only, hash-chained audit log. Every security event produces a tamper-detectable entry | MS-2.6, MG-2.2 | Accountability | PR.DS-10, DE.AE-03 | `verifyChain()` output; log file at `AUDIT_LOG_PATH`; CI job `audit-chain` runs verification |
| `src/security/decision-ledger.ts` | Content-addressed provenance record for every LLM decision: model hash, prompt template hash, retrieval corpus fingerprint, parameters | MS-2.5, MS-2.6 | Information Integrity, Traceability | DE.AE-03, ID.RA-04 | Ledger file at `DECISION_LEDGER_PATH`; `verify()` on any `ledgerId`; drift detection via `detectModelDrift()` |
| `tests/security/prompt-injection.test.ts` | Point-in-time test suite: injection detection, PII scrubbing, output filtering, rate limiting | MS-2.2, MS-2.5 | Prompt Injection | DE.AE-04 | Jest output; CI job `security-tests` runs on every push |
| `tests/eval/eval-harness.ts` | Repeatable adversarial evaluation pipeline with signed, content-addressed reports persisted to disk | MS-2.2, MS-2.5, MS-2.7 | Prompt Injection, Harmful Content, Data Privacy | DE.AE-04, ID.RA-05 | Reports in `./eval-reports/`; `index.jsonl` accumulates across runs; exits `1` on FAIL for CI integration |
| `.github/workflows/security.yml` | CI pipeline: Node version check, `npm audit`, secret scan, SSRF regression, SBOM generation, audit chain verification | MS-2.3, MS-2.7 | — | DE.AE-04, PR.PS-01 | GitHub Actions run history; artifacts retained 90 days (audit) / 365 days (SBOM) |
| `src/agents/CveWatchAgent.ts` | Autonomous CVE monitoring agent: daily `npm audit`, GitHub Advisory Database queries, emits `security:cve_detected` | MS-2.3 | Cybersecurity Attacks | DE.AE-02 | Agent logs; `security:cve_detected` events in audit trail |

---

## MANAGE — Response, Containment, and Recovery

Controls that limit damage when things go wrong and enable recovery.

| File | Control | NIST AI RMF | NIST AI 600-1 | NIST CSF 2.0 | Evidence |
|------|---------|-------------|---------------|--------------|---------|
| `src/security/agent-auth.ts` | HMAC token issuance, validation, and revocation. EventBus ACL enforcement at publish and subscribe | MG-2.2, GV-2 | Cybersecurity Attacks | PR.AA-01, PR.AA-05 | Token registry; `auth.token_issued` / `auth.token_revoked` events in audit log |
| `src/security/sanitize.ts` | Input sanitization: injection pattern detection, PII scrubbing, length enforcement | MG-2.2, MS-2.2 | Prompt Injection, Data Privacy | PR.DS-01 | `sanitizeInput()` and `scrubPII()` return structured results with detection metadata |
| `src/security/content-filter.ts` | LLM output filtering: dangerous content blocking, jailbreak detection, length enforcement | MG-2.2, MS-2.2 | Harmful Content, Information Integrity | PR.DS-01 | `filterOutput()` returns block/flag/pass with reason; blocked events in audit log |
| `src/security/http-guard.ts` | SSRF protection: URL allowlist enforcement, internal IP blocking, response size limits (CVE-2025-27152, CVE-2025-58754) | MG-2.4 | Cybersecurity Attacks | PR.PS-06 | ESLint rule blocks direct `axios` imports; CI SSRF regression job; `http-guard` wraps all outbound HTTP |
| `src/security/websocket-guard.ts` | WebSocket hardening: header count limits, payload caps, idle timeouts (CVE-2024-37890) | MG-2.4 | Cybersecurity Attacks | PR.PS-06 | All ws servers/clients created via `createWsServer()` / `createWsClient()`; limits in constants |
| `src/security/credential-vault.ts` | Ephemeral scoped credentials per task, provenance logging, rotation records. No raw keys accessible to agents | MG-2.2, GV-2 | Cybersecurity Attacks, Data Privacy | PR.AA-02, PR.AA-05 | Use log via `getUseLog()`; rotation log via `getRotationLog()`; audit events on every grant/revoke |
| `src/security/quarantine.ts` | Per-agent isolation: token revocation, credential revocation, forensic snapshot, graceful stop. Surgical — does not halt the full system | MG-2.4, MG-4.2 | — | RS.MI-01, RS.MI-02 | Quarantine records via `QuarantineManager.list()`; `safety.violation` events in audit log; snapshot stored on record |
| `src/core/AgentRegistry.ts` | `emergencyStop()`: halts all agents and revokes all tokens system-wide | MG-4.1 | — | RS.MI-01 | `safety.emergency_stop` event in audit log; API endpoint `POST /api/compliance/emergency-stop` |
| `src/api/compliance.ts` | REST endpoints: compliance status, emergency stop, audit export, chain verification | MG-2.2, MG-4 | — | RS.CO-02 | `GET /api/compliance/status` returns 200 (compliant) or 409 (attention required) |
| `INCIDENT_RESPONSE.md` | Step-by-step runbooks for SEV-1 through SEV-4. Includes kill commands, isolation steps, forensic collection, post-mortem template | MG-4.1, MG-4.2 | — | RS.AN-03, RC.RP-01 | Document reviewed quarterly; runbooks tested against quarantine and emergency stop APIs |

---

## Cross-Cutting: Supply Chain and Dependency Security

| File | Control | NIST AI RMF | NIST CSF 2.0 | Evidence |
|------|---------|-------------|--------------|---------|
| `package.json` | Pinned dependency versions (axios ≥1.11.0, express ≥4.20.0, ws ≥8.17.1); `engines` field requires Node ≥20.20.0 | MS-2.3 | PR.PS-01 | `npm audit` in CI; `engines` enforced by npm on install |
| `.nvmrc` | Node.js version pinned to 22.22.0 — mitigates CVE-2025-55131 (buffer race condition) | MS-2.3 | PR.PS-01 | `.nvmrc` read by CI `node-version-check` job; verified against CVE floor |
| `.github/workflows/security.yml` | SBOM generated on every main branch push via `cyclonedx-npm`; retained 365 days | MS-2.3, ID.AM-2 | ID.AM-01 | SBOM artifact in GitHub Actions; committed to repo on release |

---

## Control Coverage Summary

| NIST AI RMF Function | Controls Implemented |
|----------------------|---------------------|
| GOVERN | 6 |
| MAP | 4 |
| MEASURE | 6 |
| MANAGE | 10 |
| **Total** | **26** |

| NIST AI 600-1 Risk Category | Mitigated By |
|-----------------------------|-------------|
| Prompt Injection | `sanitize.ts`, `eval-harness.ts`, `prompt-injection.test.ts` |
| Harmful Content | `content-filter.ts`, `eval-harness.ts` |
| Data Privacy / PII | `sanitize.ts`, `credential-vault.ts` |
| Information Integrity | `decision-ledger.ts`, `content-filter.ts` |
| Cybersecurity Attacks | `agent-auth.ts`, `http-guard.ts`, `websocket-guard.ts`, `credential-vault.ts`, `CveWatchAgent.ts` |
| Hallucination | `content-filter.ts`, ApprovalGateAgent (existing) |
| Accountability | `audit-log.ts`, `decision-ledger.ts` |
| Traceability | `decision-ledger.ts` |

---

*This document is version-controlled alongside the codebase. Any new security control added to the framework must have a corresponding row added here before the PR is merged.*  
*Review cadence: quarterly, or on any change to `src/security/`.*
