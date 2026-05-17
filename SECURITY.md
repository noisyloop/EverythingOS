# Security Policy

## NIST AI RMF Alignment

EverythingOS is designed in alignment with NIST AI RMF 1.0 (GOVERN, MAP, MEASURE, MANAGE)
and NIST AI 600-1 (Generative AI Profile). This document covers vulnerability disclosure,
known risks, responsible use, and the security controls built into the framework.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x (current) | ✅ Active security support |
| < 1.0 | ❌ No longer supported |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via GitHub's Security Advisory system:
1. Go to https://github.com/noisyloop/EverythingOS/security/advisories
2. Click "New draft security advisory"
3. Provide a detailed description, reproduction steps, and impact assessment

**Response SLA:**
- Acknowledgement within 48 hours
- Initial assessment within 5 business days
- Patch timeline communicated within 10 business days

---

## Known Risk Areas

The following areas carry inherent risk in any multi-agent AI framework.
Each is mitigated by controls documented in `src/security/`.

### 1. Prompt Injection (HIGH)
Agents that accept user-supplied text (Discord, Slack, API inputs) and pass it
to LLMs are susceptible to prompt injection. **Mitigation:** All user input passes
through `src/security/sanitize.ts` before reaching any LLM call.

### 2. Agent Privilege Escalation (HIGH)
Agents that gain unintended access to event channels outside their declared scope.
**Mitigation:** EventBus enforces per-agent ACLs declared at registration time.
See `src/security/agent-auth.ts`.

### 3. LLM Hallucination in Decision Paths (HIGH)
Agents using LLM output to make consequential decisions (trading signals, deployment
approvals, robotics commands) may act on fabricated information.
**Mitigation:** High-risk agent tiers require human-in-the-loop approval via
`ApprovalGateAgent`. Output validation is enforced via `src/security/content-filter.ts`.

### 4. Third-Party LLM Data Exposure (MEDIUM)
User content and agent context sent to external LLM APIs (Anthropic, OpenAI) may
contain PII. **Mitigation:** `src/security/sanitize.ts` scrubs PII before all
outbound LLM calls.

### 5. Supply Chain / Dependency Risk (MEDIUM)
npm dependencies introduce third-party code. **Mitigation:** Dependencies are pinned
in `package.json`, `npm audit` runs in CI, and an SBOM is generated on each release.

### 6. Insecure Event Bus (MEDIUM)
Unauthenticated agents could inject malicious events.
**Mitigation:** All EventBus publish calls require a valid HMAC agent token issued
by the AgentRegistry at registration.

### 7. ROS2 / Robotics Command Injection (CRITICAL when applicable)
Agents bridging to physical hardware via ROS2 must never accept unvalidated input
as motion or actuation commands. **Mitigation:** All robotics-bound events require
HIGH risk tier approval and pass through SafetyMonitor before execution.

---

## Security Controls Summary

| Control | Location | Status |
|---------|----------|--------|
| Input sanitization & prompt injection defense | `src/security/sanitize.ts` | ✅ |
| PII scrubbing | `src/security/sanitize.ts` | ✅ |
| Agent HMAC token auth | `src/security/agent-auth.ts` | ✅ |
| EventBus ACL enforcement | `src/security/agent-auth.ts` | ✅ |
| Append-only audit log | `src/security/audit-log.ts` | ✅ |
| LLM output content filter | `src/security/content-filter.ts` | ✅ |
| Agent risk tier typing | `src/types/agent-risk.ts` | ✅ |
| Prompt injection test suite | `tests/security/prompt-injection.test.ts` | ✅ |
| Human-in-the-loop approval | `ApprovalGateAgent` (existing) | ✅ |
| Dependency audit in CI | `.github/workflows/security.yml` | ✅ |
| Software Bill of Materials | `sbom.json` (generated on release) | ✅ |

---

## Responsible Use

EverythingOS is a general-purpose agent framework. Operators are responsible for:

- Complying with the Terms of Service of any LLM provider used (Anthropic, OpenAI, etc.)
- Complying with platform Terms of Service for any integration (Discord, Slack, etc.)
- Ensuring appropriate data privacy controls for the jurisdiction of deployment
- Never deploying HIGH risk tier agents (financial, robotics, system config) without
  human oversight and tested fallback procedures
- Disclosing bot/agent identity to users in any consumer-facing deployment

---

## NIST AI 600-1 GenAI Risk Register

| GenAI Risk | Mitigation Implemented |
|---|---|
| Hallucination | Content filter + approval gates for HIGH tier |
| Prompt Injection | Input sanitization layer on all user-facing agents |
| Data Privacy / PII | PII scrubber before all LLM API calls |
| Harmful Content | Output content policy filter |
| Cybersecurity Attacks | Agent auth tokens + EventBus ACLs |
| Impersonation | Bot disclosure requirement in responsible use |
| Information Integrity | Confidence scoring in decision agents |

---

*This policy is reviewed quarterly. Last updated: February 2026.*
*Framework: NIST AI RMF 1.0, NIST AI 600-1, NIST CSF 2.0*
