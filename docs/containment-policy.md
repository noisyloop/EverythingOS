# Runtime Containment Policy

**Framework:** NIST AI RMF 1.0 — MANAGE (MG-2.4), GOVERN (GV-2)  
**Last Updated:** February 2026  
**Policy Version:** 1.0.0

This document defines the runtime containment boundaries for EverythingOS agents by risk tier. It distinguishes between what the framework enforces in code and what the operator must enforce at the infrastructure level. Both layers are required — the framework cannot enforce process isolation or network egress without the infrastructure boundaries described here.

---

## Why Containment Matters

ACLs and tokens prevent misuse by design. Containment limits damage when design fails.

The security controls in `src/security/` operate on the assumption that agents are honest principals making authorized requests. Containment operates on the opposite assumption: that any agent may be compromised at any time, and the goal is to limit what a compromised agent can reach.

NIST AI RMF is increasingly explicit about "assume compromise" thinking. This document is the operational expression of that principle for EverythingOS deployments.

---

## Tier Definitions

| Tier | Examples | Autonomy Level |
|------|----------|---------------|
| **LOW** | Clock, metrics collector, world state reader | Fully autonomous — read-only |
| **MEDIUM** | Discord bot, Slack integration, trading signal generator | Supervised — external calls allowed |
| **HIGH** | Trade executor, deployment agent, ROS2/robotics, system config | Human-in-the-loop required |

---

## Network Egress Controls

### LOW Tier

**Framework enforcement:** `http-guard.ts` blocks all outbound HTTP calls from agents that use the guarded axios client. LOW tier agents should not instantiate HTTP clients at all.

**Infrastructure enforcement (operator responsibility):**

```
# iptables — block all egress from LOW tier agent process group
iptables -A OUTPUT -m owner --gid-owner eos-low -j DROP

# Docker — no network access
docker run --network none eos-low-agent

# Kubernetes — deny all egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: eos-low-tier-egress
spec:
  podSelector:
    matchLabels:
      eos-tier: low
  policyTypes:
    - Egress
  egress: []  # Empty = deny all
```

**Allowed destinations:** None.  
**Blocked destinations:** All.

---

### MEDIUM Tier

**Framework enforcement:** `http-guard.ts` enforces a per-integration host allowlist. Calls to unlisted hosts throw before the request is made. `credential-vault.ts` scopes API keys to specific tasks with TTLs.

**Infrastructure enforcement (operator responsibility):**

```
# Docker — restrict to declared external hosts only
docker run --network eos-medium-net eos-medium-agent

# Create the network with restricted egress
docker network create \
  --driver bridge \
  --opt com.docker.network.bridge.enable_ip_masquerade=true \
  eos-medium-net

# iptables — allow only declared provider IPs, block everything else
iptables -A OUTPUT -m owner --gid-owner eos-medium -d api.anthropic.com -j ACCEPT
iptables -A OUTPUT -m owner --gid-owner eos-medium -d api.openai.com -j ACCEPT
iptables -A OUTPUT -m owner --gid-owner eos-medium -d discord.com -j ACCEPT
iptables -A OUTPUT -m owner --gid-owner eos-medium -d slack.com -j ACCEPT
iptables -A OUTPUT -m owner --gid-owner eos-medium -j DROP
```

**Allowed destinations:**
- `api.anthropic.com` (LLM)
- `api.openai.com` (LLM)
- `generativelanguage.googleapis.com` (LLM)
- `discord.com` / `gateway.discord.gg` (Discord plugin)
- `slack.com` / `wss://wss-*.slack.com` (Slack plugin)
- `api.github.com` (GitHub plugin)
- Internal EverythingOS API (`localhost:3000`)

**Blocked destinations:** All other hosts, including all RFC 1918 private ranges and cloud metadata endpoints.

**Rate ceilings (framework-enforced via `riskConfig.llmRateLimit`):**
- LLM API calls: max 60 per agent per minute
- EventBus publish: unlimited within declared channel ACLs

---

### HIGH Tier

**Framework enforcement:** All MEDIUM controls apply. Additionally: every consequential action requires ApprovalGateAgent sign-off before execution. `audit-log.ts` logs all actions with full metadata. `credential-vault.ts` issues ephemeral credentials per task with a maximum 1-hour TTL.

**Infrastructure enforcement (operator responsibility):**

```
# Run HIGH tier agents in isolated containers with explicit egress
docker run \
  --network eos-high-net \
  --memory 512m \
  --cpus 1.0 \
  --read-only \
  --tmpfs /tmp:size=64m \
  eos-high-agent

# HIGH tier gets the same external host allowlist as MEDIUM,
# plus any execution-specific endpoints (exchange APIs, deployment targets)
iptables -A OUTPUT -m owner --gid-owner eos-high -d api.anthropic.com -j ACCEPT
iptables -A OUTPUT -m owner --gid-owner eos-high -d api.coinbase.com -j ACCEPT
# ... declare all permitted targets explicitly
iptables -A OUTPUT -m owner --gid-owner eos-high -j DROP
```

**Allowed destinations:** Same as MEDIUM, plus execution-specific endpoints declared in the agent's deployment manifest. Every permitted destination must be documented in the agent's `riskJustification`.

**Rate ceilings:**
- LLM API calls: max 30 per agent per minute (tighter than MEDIUM — HIGH agents should be deliberate, not chatty)
- Consequential actions: gated by ApprovalGateAgent, no rate ceiling — throughput is human-limited

**Additional HIGH tier requirements:**
- ApprovalGateAgent must be running before any HIGH tier agent starts (enforced by `AgentRegistry.preflightCheck()`)
- Physical emergency stop path must be tested before deployment (for robotics deployments)
- Rollback procedure must be documented in `riskJustification` before deployment

---

## Filesystem Access

### LOW Tier

**Allowed:** Read-only access to the EverythingOS world state database.  
**Blocked:** All writes. No access to `src/security/`, agent config files, or credential stores.

```
# Docker read-only root with no writable mounts
docker run --read-only --tmpfs /tmp:size=16m eos-low-agent
```

---

### MEDIUM Tier

**Allowed:**
- Read/write to agent-scoped state directory: `/var/eos/agents/{agentId}/state/`
- Read-only access to plugin config files
- Append-only access to audit log: `/var/eos/logs/audit.jsonl`

**Blocked:** Access to other agents' state directories. No access to credential store. No access to `src/security/`.

```
# Kubernetes volume mounts — scope to agent ID
volumeMounts:
  - name: agent-state
    mountPath: /var/eos/agents/my-agent/state
  - name: audit-log
    mountPath: /var/eos/logs/audit.jsonl
    readOnly: false  # append-only enforced by AuditLogger
```

---

### HIGH Tier

**Allowed:** Same as MEDIUM, plus read access to deployment manifests and execution configs specific to the agent's declared function.  
**Blocked:** Same as MEDIUM. HIGH tier agents are not granted broader filesystem access than MEDIUM — their elevated trust is expressed through ApprovalGate, not filesystem permissions.

---

## Process Isolation

Node.js is single-process by design. True process isolation between agents requires infrastructure boundaries, not application-level controls. The framework enforces logical isolation via EventBus ACLs and token revocation. Physical isolation is an operator responsibility.

### Recommended Approach: One Container Per High-Risk Agent

```
# Each HIGH tier agent runs in its own container
docker-compose.yml:

services:
  trading-agent:
    image: eos-agent:latest
    environment:
      - AGENT_ID=trading-agent
      - AGENT_MODULE=src/agents/trading/TradingExecutorAgent
    networks:
      - eos-high-net
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'

  approval-gate:
    image: eos-agent:latest
    environment:
      - AGENT_ID=approval-gate
      - AGENT_MODULE=src/agents/decision/ApprovalGateAgent
    networks:
      - eos-high-net
```

### Minimum Viable Isolation for Development

If running all agents in a single process (development only), the framework still enforces:
- EventBus ACLs via `agent-auth.ts` — agents cannot publish or subscribe outside declared channels
- Token revocation via `quarantine.ts` — a quarantined agent is immediately cut off from the event bus
- Credential scoping via `credential-vault.ts` — each agent only gets credentials for its own tasks

This is logical isolation, not physical isolation. It is sufficient for development and low-stakes deployments. It is not sufficient for HIGH tier agents in production.

---

## API Rate Ceilings

These are enforced by the framework via `riskConfig.llmRateLimit` in `agent-auth.ts`. Operators may set lower limits; they may not set higher limits without updating the policy and documenting the justification.

| Tier | LLM Calls/Min | EventBus Publishes | External API Calls |
|------|--------------|-------------------|-------------------|
| LOW | 0 (no LLM) | Unlimited (ACL-scoped) | None permitted |
| MEDIUM | 60 | Unlimited (ACL-scoped) | Unlimited (host-allowlisted) |
| HIGH | 30 | Unlimited (ACL-scoped) | Approval-gated for consequential actions |

---

## Cloud Metadata Endpoint Blocking

All tiers. No exceptions.

The following endpoints must be blocked at the network level for any cloud deployment. `http-guard.ts` blocks them in application code — the network-level block is a defense-in-depth measure.

| Endpoint | Cloud |
|----------|-------|
| `169.254.169.254` | AWS, GCP, Azure (IMDSv1) |
| `fd00:ec2::254` | AWS (IMDSv2 IPv6) |
| `metadata.google.internal` | GCP |
| `100.100.100.200` | Alibaba Cloud |
| `168.63.129.16` | Azure |

```
# Block all metadata endpoints at iptables level
iptables -A OUTPUT -d 169.254.169.254 -j DROP
iptables -A OUTPUT -d 100.100.100.200 -j DROP
ip6tables -A OUTPUT -d fd00:ec2::254 -j DROP
```

---

## Quarantine Containment Guarantees

When `QuarantineManager.quarantine()` is called, the following is guaranteed by the framework:

1. **EventBus token revoked** — agent cannot publish or subscribe to any channel
2. **All credential vault grants revoked** — agent cannot make any external API call
3. **Agent stop attempted** — graceful stop with 5-second timeout
4. **Forensic snapshot captured** — state, subscriptions, recent audit events preserved
5. **Audit trail entry written** — `safety.violation` event with full metadata

The following is **not** guaranteed by the framework and requires infrastructure enforcement:

- Network-level egress cutoff (requires iptables/network policy update)
- Filesystem access revocation (requires unmounting agent-scoped volumes)
- Process termination if graceful stop fails (requires container restart policy or SIGKILL)

For critical-severity quarantines, operators should follow the quarantine with a container stop:

```bash
# After QuarantineManager.quarantine() returns
docker stop eos-agent-{agentId} --time 5
# or
kubectl delete pod eos-agent-{agentId} --grace-period=5
```

---

## Policy Review Cadence

| Trigger | Action |
|---------|--------|
| New agent tier introduced | Update network egress rules and this document |
| New external provider added | Add to MEDIUM/HIGH allowlist; update iptables rules |
| Security incident | Review containment boundaries that were crossed; update policy |
| Quarterly | Review all tier assignments; verify infrastructure boundaries match policy |
| NIST guidance update | Re-evaluate alignment; update NIST references |

---

*Operators are responsible for implementing the infrastructure-level controls described in this document. The EverythingOS framework enforces application-level controls only. Neither layer alone is sufficient for production HIGH tier deployments.*
