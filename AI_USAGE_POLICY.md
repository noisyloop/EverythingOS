# AI Usage Policy

**Framework:** NIST AI RMF 1.0 — GOVERN Function (GV-1.1, GV-1.2, GV-4)
**Last Updated:** February 2026

---

## Purpose

This policy defines acceptable use of EverythingOS across deployment contexts,
establishes risk tolerances per agent tier, and documents operator obligations
when deploying the framework with live LLM integrations.

---

## Deployment Contexts & Risk Tolerance

EverythingOS supports multiple deployment contexts. The acceptable behaviors and
required controls differ by context. Operators must select the appropriate tier
for each agent at registration time via the `riskTier` field in `AgentConfig`.

### LOW Risk (Tier 1–2) — Autonomous Operation Permitted

**Examples:** Clock agents, metrics collectors, read-only data monitors, simulations

**Permitted:**
- Fully autonomous operation without human review
- Access to `LOW` and `MEDIUM` event channels only
- Internal state reads

**Not Permitted:**
- External API calls
- Writing to shared state that affects other agents
- LLM integration without output filtering

---

### MEDIUM Risk (Tier 3–4) — Supervised Autonomous Operation

**Examples:** Discord bots, Slack integrations, trading signal generators, sentiment analysis

**Permitted:**
- Autonomous operation with output filtering active
- External API calls (LLM providers, platform APIs)
- Publishing to platform channels (Discord, Slack)
- Reading user-supplied content (with sanitization required)

**Not Permitted:**
- Financial transactions without human approval
- Access to system configuration events
- Storage of PII beyond the current session
- Disabling or bypassing input sanitization

**Required Controls:**
- Input sanitization via `sanitizeInput()` before all LLM calls
- PII scrubbing via `scrubPII()` before all outbound LLM calls
- Output content filtering via `filterOutput()` on all LLM responses
- Rate limiting: max 60 LLM calls per agent per minute
- Bot identity disclosure in any consumer-facing channel

---

### HIGH Risk (Tier 5–6) — Human-in-the-Loop Required

**Examples:** Trading execution agents, deployment agents, robotics/ROS2 agents,
system configuration agents, healthcare data agents

**Permitted:**
- Consequential actions AFTER explicit human approval via `ApprovalGateAgent`
- Emergency stop execution without approval (safety override)
- Access to all event channels declared at registration

**Not Permitted:**
- Autonomous execution of irreversible actions
- Physical actuation without SafetyMonitor active
- Unilateral financial transactions above defined thresholds
- Modifying agent trust levels or permissions

**Required Controls:**
- All consequential actions routed through `ApprovalGateAgent`
- Full audit trail via `AuditLogger` (append-only, hash-chained)
- Human approval timeout: default 5 minutes, configurable
- Emergency stop path that bypasses all agents must remain functional
- Incident response runbook must be documented before deployment
- For robotics: `SafetyMonitor` must be active and zones configured

---

## LLM Provider Obligations

When using any external LLM provider, operators must:

1. Comply with that provider's usage policies:
   - Anthropic: https://www.anthropic.com/legal/usage-policy
   - OpenAI: https://openai.com/policies/usage-policies
   - Google: https://ai.google.dev/gemini-api/terms

2. Not use EverythingOS to:
   - Generate CSAM or content sexualizing minors
   - Produce CBRN (chemical, biological, radiological, nuclear) weapon designs
   - Create malware, exploits, or tools for unauthorized system access
   - Automate targeted harassment or influence operations
   - Circumvent other AI systems' safety mechanisms

3. Ensure API keys are stored in environment variables only, never committed to source control.

---

## Platform Integration Obligations

### Discord
- Bot must be identified as a bot in its profile
- Must not impersonate human users
- Must comply with Discord's Developer Policy and Terms of Service
- Rate limiting must be respected; the built-in rate limiter must not be disabled

### Slack
- Must use the Slack App framework, not user tokens
- Workspace admins must consent before deployment
- Message content sent to LLMs must be disclosed in the app's privacy policy

### Financial / Trading Agents
- Must not execute real financial transactions without explicit human approval
- Signal generation must include confidence scores and uncertainty indicators
- Logs of all signals generated must be retained for minimum 7 years if used in regulated contexts

---

## Prohibited Uses

The following are prohibited regardless of deployment context:

- Generating or distributing disinformation or synthetic media intended to deceive
- Automating coordinated inauthentic behavior on any platform
- Processing health data without HIPAA-compliant infrastructure and explicit consent
- Deploying without notifying end users that they are interacting with an AI system
- Using the framework to train competing AI models without written permission
- Disabling security controls defined in `src/security/` without equivalent replacement

---

## Incident Reporting

If you discover EverythingOS is being used in violation of this policy,
report it via the GitHub Security Advisory system documented in `SECURITY.md`.

---

*Operators are responsible for compliance with all applicable laws and regulations
in their jurisdiction, including but not limited to GDPR, CCPA, HIPAA, and
applicable financial services regulations.*
