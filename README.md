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

## Quick Start

```bash
git clone https://github.com/m0rs3c0d3/EverythingOS.git
cd EverythingOS
npm install
npm run cli
```

## What's New

### 🚀 CLI Wizard
Interactive setup that actually works:
```bash
npm run cli
```
- Deploy a Discord bot in 60 seconds
- Create custom agents from templates
- Configure LLM providers
- Launch simulations

### Secure Discord Bot
Production-ready Discord integration with defense-in-depth security:
```bash
export DISCORD_BOT_TOKEN=your_token
export ANTHROPIC_API_KEY=your_key
npm run discord
```

**Security features:**
- Prompt injection detection (20+ patterns)
- Rate limiting (10/min per user)
- DMs disabled by default
- PII detection
- Abuse scoring with auto-block
- Hardened system prompts

### UFO Simulations
Test without hardware:

```bash
# Robot in 2D world
npm run sim

# UAP swarm with formations
npm run swarm
```

## Status

| Component | Status |
|-----------|--------|
| Core (EventBus, Agents, State) | ✅ Working |
| CLI Wizard | ✅ Working |
| Discord Bot (Secure) | ✅ Working |
| Robot Simulation | ✅ Working |
| UAP Swarm Simulation | ✅ Working |
| Memory System | ✅ Working |
| Security Layer | ✅ Working |
| Hardware Abstraction | ✅ Ready (needs hardware) |
| Telegram Integration | 🔧 In Progress |
| Web Dashboard | 📋 Planned |

## Commands

```bash
npm run cli         # Interactive wizard
npm run discord     # Discord bot
npm run sim         # Robot simulation
npm run swarm       # UAP swarm simulation
npm run demo        # Simple agent demo
npm run demo:cli    # Interactive agent demo
```

## Environment Variables

Copy `.env.example` to `.env`:

```bash
DISCORD_BOT_TOKEN=your_token
ANTHROPIC_API_KEY=your_key
# or
OPENAI_API_KEY=your_key
```

## Project Structure

```
src/
├── core/           # EventBus, State, Registry
├── runtime/        # Agent base class, LLM Router
├── agents/         # Built-in agents
├── integrations/   # Discord (secure), Telegram (soon)
├── simulation/     # Robot, UAP, Swarm
├── security/       # Auth, Rate Limiting
└── plugins/        # Hardware, Robotics

cli/                # Interactive wizard
examples/           # Demo scripts
```

## Documentation

- [Hardware Setup](HARDWARE.md)
- [Bridge Architecture](BRIDGES.md)

## License

MIT
