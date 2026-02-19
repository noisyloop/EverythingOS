```
███████╗██╗   ██╗███████╗██████╗ ██╗   ██╗████████╗██╗  ██╗██╗███╗   ██╗ ██████╗
██╔════╝██║   ██║██╔════╝██╔══██╗╚██╗ ██╔╝╚══██╔══╝██║  ██║██║████╗  ██║██╔════╝
█████╗  ██║   ██║█████╗  ██████╔╝ ╚████╔╝    ██║   ███████║██║██╔██╗ ██║██║  ███╗
██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗  ╚██╔╝     ██║   ██╔══██║██║██║╚██╗██║██║   ██║
███████╗ ╚████╔╝ ███████╗██║  ██║   ██║      ██║   ██║  ██║██║██║ ╚████║╚██████╔╝
╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝
                         ██████╗ ███████╗
                        ██╔═══██╗██╔════╝
                        ██║   ██║███████╗
                        ██║   ██║╚════██║
                        ╚██████╔╝███████║
                         ╚═════╝ ╚══════╝
```

# EverythingOS

**LLM-Agnostic Multi-Agent Operating System**

From chatbots to robot swarms — build autonomous agent systems that work with any LLM provider.

Built on TypeScript with a security-first design aligned to **NIST AI RMF 1.0** and **NIST AI 600-1**.

## Requirements

- Node.js >= 20.20.0
- npm >= 10.0.0

## Quick Start

```bash
git clone https://github.com/m0rs3c0d3/EverythingOS.git
cd EverythingOS
npm install
cp .env.example .env   # add your API keys
npm run build
npm start
```

## Key Features

### LLM-Agnostic Runtime

Plug in any provider without changing agent code:

| Provider | Status |
|----------|--------|
| Anthropic (Claude) | Supported |
| OpenAI (GPT) | Supported |
| Google (Gemini) | Supported |
| Local / Self-hosted | Supported |

### EventBus-Driven Architecture

Agents communicate through a typed, ACL-enforced event bus. Every message carries an `agentId` and timestamp. Priority queuing and dead-letter handling are built in.

### Agent Risk Tiers

Agents declare a risk tier at registration. Controls are automatically enforced:

- **LOW** — Fully autonomous (clock agents, monitors, simulations)
- **MEDIUM** — Supervised autonomous with input/output filtering (Discord bots, API integrations)
- **HIGH** — Human-in-the-loop required via `ApprovalGateAgent` (trading, robotics, deployments)

### Security Layer

- Prompt injection detection and input sanitization
- PII scrubbing before all outbound LLM calls
- Agent HMAC token authentication
- EventBus ACL enforcement (agents cannot publish outside declared channels)
- Append-only, hash-chained audit log
- LLM output content filtering
- Rate limiting

### REST API

```bash
npm run api   # starts Express server on :3000
```

Key endpoints:
- `GET /api/agents` — list registered agents
- `POST /api/agents/:id/stop` — stop an agent
- `POST /api/agents/stop-all` — emergency stop all agents
- `GET /api/decisions/:id/explain` — human-readable decision explanation
- `GET /api/compliance/status` — compliance status report

### Simulations

Test without hardware:

```bash
# Run examples directly with tsx
npx tsx examples/demo-simple.ts     # Simple agent demo
npx tsx examples/demo-robot.ts      # Robot in 2D world
npx tsx examples/demo-swarm.ts      # UAP swarm with formations
npx tsx examples/demo-cli.ts        # Interactive agent demo
npx tsx examples/discord-bot.ts     # Discord bot (requires token)
npx tsx examples/compliant-agents.ts  # NIST-compliant agent setup
```

## Available Scripts

```bash
npm run build          # Compile TypeScript
npm start              # Run compiled output
npm run api            # Start REST API server
npm run dev            # Watch mode (tsx)
npm test               # Run test suite
npm run test:security  # Run security-specific tests
npm run lint           # ESLint
npm run typecheck      # Type check without emit
npm run audit:check    # npm audit (high severity)
npm run sbom           # Generate Software Bill of Materials
npm run compliance     # Query compliance status (API must be running)
```

## Environment Variables

Copy `.env.example` to `.env`:

```bash
# LLM Providers (add one or more)
ANTHROPIC_API_KEY=your_key
OPENAI_API_KEY=your_key
GEMINI_API_KEY=your_key

# Integrations
DISCORD_BOT_TOKEN=your_token
```

## Project Structure

```
src/
├── core/           # EventBus, WorldState, AgentRegistry, Supervisor, Workflows
├── runtime/        # Agent base class, LLMRouter, ActionTypes, IntentContract
├── agents/         # Built-in agents (Clock, HealthMonitor, Shutdown, ApprovalGate, CVEWatch)
├── api/            # Express REST API server and compliance endpoints
├── config/         # System configuration
├── integrations/   # Discord (secure), Telegram (in progress)
├── observability/  # MetricsCollector
├── security/       # Sanitize, AgentAuth, AuditLog, ContentFilter, HTTP/WS guards
├── services/       # Memory, Trust, Tools, Explainability, Capabilities
├── simulation/     # Robot, UAP, Swarm simulation
├── plugins/        # Hardware abstraction layer
├── types/          # Shared TypeScript types
└── workflows/      # Workflow definitions (SocialReply, etc.)

cli/                # CLI entry point
examples/           # Runnable demo scripts
```

## Status

| Component | Status |
|-----------|--------|
| Core (EventBus, State, Registry, Supervisor) | Working |
| REST API Server | Working |
| LLM Router (Claude, OpenAI, Gemini, Local) | Working |
| Security Layer | Working |
| Audit Logging (append-only, hash-chained) | Working |
| Decision Explainability | Working |
| Memory System | Working |
| Observability / Metrics | Working |
| Discord Bot (Secure) | Working |
| Robot Simulation | Working |
| UAP Swarm Simulation | Working |
| Hardware Abstraction | Ready (needs hardware) |
| Telegram Integration | In Progress |
| ROS2 Bridge | Planned (Phase 5) |
| Swarm Coordination (distributed) | Planned (Phase 6) |
| Web Dashboard | Planned |

## Documentation

- [Security Policy](SECURITY.md)
- [Bridge Architecture](BRIDGES.md)
- [AI Ethics & Trustworthiness](AI_ETHICS.md)
- [AI Usage Policy](AI_USAGE_POLICY.md)
- [Incident Response Runbook](INCIDENT_RESPONSE.md)

## NIST AI RMF Alignment

EverythingOS is designed in alignment with **NIST AI RMF 1.0** (GOVERN, MAP, MEASURE, MANAGE) and **NIST AI 600-1** (Generative AI Profile). See [AI_ETHICS.md](AI_ETHICS.md) for how each trustworthiness characteristic is operationalized, and [AI_USAGE_POLICY.md](AI_USAGE_POLICY.md) for deployment obligations by risk tier.

## License

MIT
