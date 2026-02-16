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

## Status

| Component | Status |
|-----------|--------|
| Core (EventBus, Agents, State) | ✅ Working |
| Foundation Agents (Clock, Health, Shutdown) | ✅ Working |
| Memory System | ✅ Working |
| Security (Auth, Rate Limiting, Audit) | ✅ Working |
| Observability (Metrics) | ✅ Working |
| CLI Wizard | ✅ Working |
| Robot Simulation | ✅ Working |
| UAP Swarm Simulation | ✅ Working |
| Discord Integration (Secure) | ✅ Working |
| Hardware Abstraction | ✅ Ready (needs hardware) |
| Raspberry Pi Platform | ✅ Ready (needs hardware) |
| Jetson Platform | ✅ Ready (needs hardware) |
| ROS2 Bridge | ✅ Ready (needs ROS2) |
| Swarm Coordination | ✅ Ready (needs multiple nodes) |
| REST API | 🔧 In Progress |
| Telegram Integration | 🔧 In Progress |
| Web Dashboard | 📋 Planned |

## Quick Start

**Requirements:** Node.js 20+ (recommend using [nvm](https://github.com/nvm-sh/nvm))

```bash
# Clone and install
git clone https://github.com/m0rs3c0d3/EverythingOS.git
cd EverythingOS
npm install

# Run the CLI wizard
npm run cli

# Or run demos directly
npm run demo
```

## CLI Wizard

The fastest way to get started:

```bash
npm run cli
```

```
  What would you like to do?

  1) 🚀 Quick Start — Deploy a Discord bot in 60 seconds
  2) 🤖 Create Agent — Scaffold a custom agent
  3) 🛸 Run Simulation — Launch UAP swarm demo
  4) ⚙️  Configure — Set up LLM providers & settings
  5) 📊 Dashboard — Open web dashboard
  6) 📖 Documentation — Open docs in browser
```

## Demos

### Simple Agent Demo

```bash
npm run demo
```

```
EverythingOS Demo Starting...
▶  STARTED clock
▶  STARTED health-monitor
⏱  TICK #1
💚 HEALTH: healthy
```

### Interactive CLI

```bash
npm run demo:cli
```

| Key | Action |
|-----|--------|
| `s` | Show status |
| `e` | Emit test event |
| `q` | Quit |

### Robot Simulation

Control a virtual robot in a 2D world:

```bash
npm run sim
```

| Key | Action |
|-----|--------|
| `w/a/s/d` | Move |
| `g` | Go to goal |
| `p` | Start patrol |
| `m` | Show map |
| `q` | Quit |

### UAP Swarm Simulation

Control a fleet of 5 autonomous UAPs:

```bash
npm run swarm
```

| Key | Action |
|-----|--------|
| `1-5` | Formations (line, V, diamond, circle, sphere) |
| `p` | Start patrol |
| `s` | Scatter |
| `c` | Converge |
| `i` | Intercept target |
| `q` | Quit |

## Discord Bot (Secure)

Deploy a secure Discord bot with defense-in-depth protection:

```bash
# Set your tokens
export DISCORD_BOT_TOKEN=your_token
export ANTHROPIC_API_KEY=your_key  # or OPENAI_API_KEY

# Start
npm run discord
```

### Security Features

| Protection | Description |
|------------|-------------|
| Prompt Injection Detection | 20+ patterns detected and blocked |
| Rate Limiting | 10/min per user, 30/min per channel |
| DMs Disabled | Primary abuse vector blocked by default |
| PII Detection | SSN, credit cards, emails flagged |
| Abuse Scoring | Auto-block repeat offenders |
| Output Sanitization | Strips leaked system prompts |
| Hardened System Prompt | Jailbreak-resistant instructions |
| Audit Logging | Hashed user IDs, no PII stored |

## What is EverythingOS?

EverythingOS is a TypeScript framework for building autonomous AI agents that work together. Think of it as an operating system where instead of running programs, you run intelligent agents.

**Core Features:**
- **Event-Driven Architecture** — Agents communicate through pub/sub with priority queuing
- **LLM Abstraction** — Switch between OpenAI, Claude, Gemini, or local models
- **Agent Lifecycle** — Built-in supervision, health monitoring, automatic recovery
- **Three-Layer Memory** — Working, episodic, and long-term memory for learning
- **Hardware Ready** — Direct integration with Raspberry Pi, Jetson, ROS2
- **Secure by Default** — Rate limiting, injection detection, audit logging

**Design Philosophy:**
> Most agent frameworks assume the world is safe, fast, and reversible. EverythingOS assumes the opposite.

## Creating Agents

```typescript
import { Agent } from 'everythingos';

class MyAgent extends Agent {
  constructor() {
    super({
      id: 'my-agent',
      name: 'My Agent',
      type: 'perception',
      tickRate: 5000,  // Run onTick every 5 seconds
    });
  }

  protected async onStart(): Promise<void> {
    this.subscribe('some:event', (e) => this.handleEvent(e));
  }

  protected async onStop(): Promise<void> {
    // Cleanup
  }

  protected async onTick(): Promise<void> {
    // Periodic work
    this.emit('my:event', { data: 'hello' });
  }

  private async handleEvent(event: Event) {
    console.log('Received:', event.payload);
  }
}
```

### Agent Types

| Type | Purpose | Example |
|------|---------|---------|
| **Perception** | Observe environment | Monitor sensors, watch APIs |
| **Analysis** | Process data | Sentiment analysis, pattern detection |
| **Decision** | Determine actions | Route requests, approve operations |
| **Execution** | Perform actions | Send messages, control hardware |
| **Learning** | Improve over time | Track outcomes, adjust parameters |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          EVERYTHINGOS                                │
├─────────────────────────────────────────────────────────────────────┤
│  EVENT BUS │ WORKFLOWS │ SUPERVISOR │ STATE │ MEMORY │ SECURITY     │
├─────────────────────────────────────────────────────────────────────┤
│                           LLM ROUTER                                 │
│              OpenAI │ Claude │ Gemini │ Ollama                       │
├─────────────────────────────────────────────────────────────────────┤
│                             AGENTS                                   │
│     Perception │ Analysis │ Decision │ Execution │ Learning          │
├─────────────────────────────────────────────────────────────────────┤
│                         INTEGRATIONS                                 │
│                    Discord │ Telegram │ Slack                        │
├─────────────────────────────────────────────────────────────────────┤
│                          SIMULATION                                  │
│               Robot │ UAP Swarm │ Sensor Networks                    │
├─────────────────────────────────────────────────────────────────────┤
│                      ROBOTICS LAYER                                  │
│         ROS2 Bridge │ Motion Control │ Safety Monitor                │
├─────────────────────────────────────────────────────────────────────┤
│                       HARDWARE LAYER                                 │
│     Raspberry Pi │ Jetson │ Sensors │ Actuators │ Protocols          │
└─────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
src/
├── core/           # EventBus, State, Registry, Supervisor
├── runtime/        # Agent base class, LLM Router
├── services/       # Memory, Tools, Trust, Explainability
├── security/       # Auth, Rate Limiting, Audit
├── observability/  # Metrics
├── agents/         # Foundation + Decision agents
├── integrations/   # Discord, Telegram (secure)
├── simulation/     # Robot, UAP, Swarm simulations
├── plugins/
│   ├── hardware/   # Sensors, Actuators, Protocols
│   ├── platforms/  # Pi, Jetson, Deployment
│   ├── robotics/   # ROS2, Motion, Safety
│   └── swarm/      # Coordination, Mesh, Formation
└── api/            # REST server

cli/                # Interactive CLI wizard
examples/           # Demo scripts
```

## Scripts

```bash
npm run cli         # Interactive wizard
npm run demo        # Simple demo
npm run demo:cli    # Interactive agent demo
npm run sim         # Robot simulation
npm run swarm       # UAP swarm simulation
npm run discord     # Secure Discord bot
npm run build       # Compile TypeScript
npm run test        # Run tests
npm run api         # Start REST API server
```

## Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
# Discord Bot
DISCORD_BOT_TOKEN=your_token

# LLM Providers (set at least one)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GOOGLE_API_KEY=...

# Ollama (local, no key needed)
OLLAMA_BASE_URL=http://localhost:11434

# System
PORT=3000
LOG_LEVEL=info
```

## Roadmap

- [x] Core agent framework
- [x] Event bus with priority queuing
- [x] Three-layer memory system
- [x] Security (auth, rate limiting, audit)
- [x] Hardware abstraction layer
- [x] ROS2 bridge
- [x] Swarm coordination
- [x] CLI wizard
- [x] Robot simulation
- [x] UAP swarm simulation
- [x] Secure Discord integration
- [ ] Telegram integration
- [ ] WhatsApp integration
- [ ] Comprehensive test suite
- [ ] Web dashboard
- [ ] Docker deployment
- [ ] Example robots

## Documentation

- [Hardware Setup Guide](HARDWARE.md) — Raspberry Pi setup and parts list
- [Bridge Architecture](BRIDGES.md) — How EverythingOS connects to physical systems

## Contributing

Contributions welcome! Please open an issue or PR.

## License

MIT © m0rs3c0d3
