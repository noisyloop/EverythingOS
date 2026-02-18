# Incident Response Runbook

**Framework:** NIST AI RMF 1.0 — MANAGE Function (MG-2, MG-4)
**NIST AI 600-1:** Incident response for GenAI systems
**Last Updated:** February 2026

---

## Severity Levels

| Level | Description | Response Time | Example |
|-------|-------------|---------------|---------|
| SEV-1 | Active harm or data breach | Immediate (< 5 min) | Agent executing unauthorized actions, PII exposed |
| SEV-2 | System compromise or safety violation | < 30 min | Prompt injection succeeded, agent auth bypass |
| SEV-3 | Degraded operation or policy violation | < 4 hours | Agent producing policy-violating content, audit log gap |
| SEV-4 | Anomaly requiring investigation | < 24 hours | Unusual LLM output patterns, rate limit breach |

---

## Step 1 — Immediate Containment (All Severities)

### Kill All Agents (Full Stop)
```bash
# Graceful shutdown — agents complete current tick then stop
npm run stop

# If graceful fails, force kill
pkill -f "node.*everythingos"

# Via API
curl -X POST http://localhost:3000/api/agents/stop-all
```

### Kill a Specific Agent
```bash
# Via API
curl -X POST http://localhost:3000/api/agents/{agentId}/stop

# Revoke agent token to prevent restart with old credentials
curl -X DELETE http://localhost:3000/api/auth/tokens/{agentId}
```

### Isolate a Compromised Agent
If an agent is suspected of being compromised but you need other agents running:
```bash
# Block agent from EventBus without stopping the system
curl -X PUT http://localhost:3000/api/auth/tokens/{agentId}/revoke

# Remove agent's channel permissions
curl -X DELETE http://localhost:3000/api/agents/{agentId}/permissions
```

### For Robotics Deployments — Physical E-Stop
```bash
# Software emergency stop (all motion)
curl -X POST http://localhost:3000/api/safety/emergency-stop

# If software fails: use physical emergency stop button
# DO NOT attempt to reconnect until root cause is identified
```

---

## Step 2 — Preserve Evidence

**Never modify or delete audit logs during an incident.**

### Export Audit Log for Time Window
```bash
# Export last 24 hours
curl "http://localhost:3000/api/audit?since=$(date -d '24 hours ago' -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o incident-audit-$(date +%Y%m%d-%H%M%S).json

# Export specific agent's log
curl "http://localhost:3000/api/audit?agentId={agentId}&limit=1000" \
  -o agent-audit-{agentId}-$(date +%Y%m%d-%H%M%S).json
```

### Verify Audit Log Integrity
```bash
# The audit log is hash-chained. Verify chain integrity:
npx ts-node -e "
  import { AuditLogger } from './src/security/audit-log';
  AuditLogger.verifyChain().then(result => {
    console.log('Chain valid:', result.valid);
    if (!result.valid) console.log('First broken link at entry:', result.brokenAt);
  });
"
```

### Snapshot Current World State
```bash
curl -X POST http://localhost:3000/api/state/snapshot \
  -H "Content-Type: application/json" \
  -d '{"label": "incident-snapshot-'$(date +%Y%m%d-%H%M%S)'"}'
```

---

## Step 3 — Identify & Assess

### Determine What Happened

Review the audit log for the incident window looking for:
- `auth.token_rejected` — attempted unauthorized EventBus access
- `security.injection_detected` — prompt injection attempt flagged
- `security.pii_scrubbed` — PII was present in user input
- `agent.permission_denied` — agent attempted out-of-scope channel access
- `content_filter.blocked` — LLM output was filtered
- `approval.denied` / `approval.timeout` — high-risk actions blocked or timed out

### Key Questions to Answer
1. Which agent was involved?
2. What event or input triggered the incident?
3. Was any action executed before containment?
4. Was any user data exposed to external systems?
5. Was any external system modified (platform message sent, trade executed, robot moved)?
6. Is this a novel attack or a known pattern?

---

## Step 4 — Notification

### Internal Notification (All SEV-1 and SEV-2)

Notify within 1 hour of confirmation:
- System owner / operator
- Anyone whose data may have been involved
- If robotics: physical safety responsible party

### External Notification Requirements

| Scenario | Required Notification | Timeline |
|---|---|---|
| PII exposed to unauthorized party | Affected users | Per GDPR: 72 hours to regulator; CCPA: 45 days to users |
| Discord/Slack platform breach | Platform security team | As soon as possible |
| Financial data exposed | Financial institution + regulators if applicable | Per applicable regulations |
| Physical harm (robotics) | Emergency services if needed; report to platform | Immediate |

### GitHub Security Advisory
For vulnerabilities in the EverythingOS framework itself (not operator-specific incidents):
https://github.com/m0rs3c0d3/EverythingOS/security/advisories/new

---

## Step 5 — Remediation

### Rotate Compromised Credentials
```bash
# Rotate LLM API keys (do in provider dashboards, then update .env)
# Anthropic: https://console.anthropic.com/settings/keys
# OpenAI: https://platform.openai.com/api-keys

# Re-issue all agent tokens after key rotation
curl -X POST http://localhost:3000/api/auth/rotate-all
```

### Patch and Redeploy
```bash
# Run dependency audit before redeployment
npm audit
npm audit fix

# Verify no new critical CVEs
npm audit --audit-level=high
```

### Test Before Restart
```bash
# Run security test suite
npm run test:security

# Run prompt injection tests specifically
npx jest tests/security/prompt-injection.test.ts --verbose
```

---

## Step 6 — Post-Incident Documentation

Within 5 business days of resolution, document:

1. **Timeline** — When did it start? When was it detected? When was it contained?
2. **Root Cause** — What was the actual failure? Technical and process root causes.
3. **Impact** — What was affected? Users, data, systems, physical?
4. **Detection** — How was it found? Was the audit log useful?
5. **Response** — What worked? What was slow or unclear?
6. **Corrective Actions** — What changes to code, config, or process prevent recurrence?
7. **Verification** — How will you confirm the fix works?

Store post-incident reports in a private, access-controlled location.
Do not commit them to the public repository.

---

## Quick Reference Card

```
SOMETHING IS WRONG — START HERE:

1. Stop agents:     npm run stop
                    OR: curl -X POST localhost:3000/api/agents/stop-all

2. Save audit log:  curl "localhost:3000/api/audit?since=<timestamp>" -o incident.json

3. Snapshot state:  curl -X POST localhost:3000/api/state/snapshot

4. Verify log:      npx ts-node -e "import {AuditLogger} from './src/security/audit-log'; AuditLogger.verifyChain().then(console.log)"

5. Investigate:     Look for auth.token_rejected, security.injection_detected,
                    content_filter.blocked in the audit log

6. Rotate keys:     Update .env, then: curl -X POST localhost:3000/api/auth/rotate-all

7. Test & restart:  npm run test:security && npm start
```

---

*This runbook must be reviewed and updated after every SEV-1 or SEV-2 incident,
and at minimum quarterly as part of the NIST AI RMF MANAGE cycle.*
