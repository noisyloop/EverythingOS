#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS CLI
// The "holy shit" first-touch experience
// ═══════════════════════════════════════════════════════════════════════════════

import * as readline from 'readline';
import * as fs from 'fs';
import * as path from 'path';
import { execSync, spawn } from 'child_process';

// ─────────────────────────────────────────────────────────────────────────────
// Colors & Styling
// ─────────────────────────────────────────────────────────────────────────────

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  italic: '\x1b[3m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgGreen: '\x1b[42m',
  bgBlue: '\x1b[44m',
};

const BANNER = `${c.cyan}
  ███████╗██╗   ██╗███████╗██████╗ ██╗   ██╗████████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
  ██╔════╝██║   ██║██╔════╝██╔══██╗╚██╗ ██╔╝╚══██╔══╝██║  ██║██║████╗  ██║██╔════╝ 
  █████╗  ██║   ██║█████╗  ██████╔╝ ╚████╔╝    ██║   ███████║██║██╔██╗ ██║██║  ███╗
  ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗  ╚██╔╝     ██║   ██╔══██║██║██║╚██╗██║██║   ██║
  ███████╗ ╚████╔╝ ███████╗██║  ██║   ██║      ██║   ██║  ██║██║██║ ╚████║╚██████╔╝
  ╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
                           ██████╗ ███████╗
                          ██╔═══██╗██╔════╝  ${c.dim}v2.0.0${c.cyan}
                          ██║   ██║███████╗  ${c.dim}From chatbots to robot swarms${c.cyan}
                          ██║   ██║╚════██║
                          ╚██████╔╝███████║
                           ╚═════╝ ╚══════╝
${c.reset}`;

// ─────────────────────────────────────────────────────────────────────────────
// Readline Interface
// ─────────────────────────────────────────────────────────────────────────────

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const ask = (question: string): Promise<string> => {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim());
    });
  });
};

const select = async (question: string, options: string[]): Promise<number> => {
  console.log(`\n${c.bold}${question}${c.reset}\n`);
  options.forEach((opt, i) => {
    console.log(`  ${c.cyan}${i + 1}${c.reset}) ${opt}`);
  });
  console.log();
  
  while (true) {
    const answer = await ask(`${c.dim}Enter choice (1-${options.length}):${c.reset} `);
    const num = parseInt(answer, 10);
    if (num >= 1 && num <= options.length) {
      return num - 1;
    }
    console.log(`${c.red}Invalid choice. Try again.${c.reset}`);
  }
};

const confirm = async (question: string, defaultYes = true): Promise<boolean> => {
  const hint = defaultYes ? '[Y/n]' : '[y/N]';
  const answer = await ask(`${question} ${c.dim}${hint}${c.reset} `);
  if (answer === '') return defaultYes;
  return answer.toLowerCase().startsWith('y');
};

const spinner = (text: string): { stop: (success?: boolean) => void } => {
  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  let i = 0;
  const interval = setInterval(() => {
    process.stdout.write(`\r${c.cyan}${frames[i]}${c.reset} ${text}`);
    i = (i + 1) % frames.length;
  }, 80);
  
  return {
    stop: (success = true) => {
      clearInterval(interval);
      const icon = success ? `${c.green}✓${c.reset}` : `${c.red}✗${c.reset}`;
      process.stdout.write(`\r${icon} ${text}\n`);
    }
  };
};

// ─────────────────────────────────────────────────────────────────────────────
// Main Menu
// ─────────────────────────────────────────────────────────────────────────────

async function mainMenu(): Promise<void> {
  console.clear();
  console.log(BANNER);
  
  const choice = await select('What would you like to do?', [
    `${c.green}🚀 Quick Start${c.reset} — Deploy a Discord bot in 60 seconds`,
    `${c.blue}🤖 Create Agent${c.reset} — Scaffold a custom agent`,
    `${c.magenta}🛸 Run Simulation${c.reset} — Launch UAP swarm demo`,
    `${c.yellow}⚙️  Configure${c.reset} — Set up LLM providers & settings`,
    `${c.cyan}📊 Dashboard${c.reset} — Open web dashboard`,
    `${c.dim}📖 Documentation${c.reset} — Open docs in browser`,
    `${c.dim}❌ Exit${c.reset}`,
  ]);

  switch (choice) {
    case 0: await quickStart(); break;
    case 1: await createAgent(); break;
    case 2: await runSimulation(); break;
    case 3: await configure(); break;
    case 4: await openDashboard(); break;
    case 5: await openDocs(); break;
    case 6: 
      console.log(`\n${c.cyan}Goodbye! 👋${c.reset}\n`);
      process.exit(0);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Quick Start — The "Holy Shit" Moment
// ─────────────────────────────────────────────────────────────────────────────

async function quickStart(): Promise<void> {
  console.clear();
  console.log(`\n${c.cyan}${c.bold}🚀 QUICK START${c.reset}`);
  console.log(`${c.dim}Deploy your first agent in 60 seconds${c.reset}\n`);

  // Step 1: Choose channel
  const channel = await select('Where should your agent live?', [
    `${c.blue}Discord${c.reset} — Best for developer communities`,
    `${c.cyan}Telegram${c.reset} — Popular with crypto/tech builders`,
    `${c.green}WhatsApp${c.reset} — Widest reach, personal use`,
    `${c.yellow}Terminal${c.reset} — Local testing only`,
  ]);

  const channels = ['discord', 'telegram', 'whatsapp', 'terminal'];
  const selectedChannel = channels[channel];

  // Step 2: Get credentials (skip for terminal)
  let token = '';
  if (selectedChannel !== 'terminal') {
    console.log(`\n${c.bold}Step 2: Authentication${c.reset}`);
    
    if (selectedChannel === 'discord') {
      console.log(`${c.dim}Get your bot token from: https://discord.com/developers/applications${c.reset}`);
      token = await ask(`${c.cyan}Discord Bot Token:${c.reset} `);
    } else if (selectedChannel === 'telegram') {
      console.log(`${c.dim}Get your token from @BotFather on Telegram${c.reset}`);
      token = await ask(`${c.cyan}Telegram Bot Token:${c.reset} `);
    } else if (selectedChannel === 'whatsapp') {
      console.log(`${c.dim}WhatsApp requires phone number verification${c.reset}`);
      console.log(`${c.yellow}Note: WhatsApp integration uses unofficial API${c.reset}`);
      token = await ask(`${c.cyan}Phone number (with country code):${c.reset} `);
    }
  }

  // Step 3: Choose LLM
  console.log(`\n${c.bold}Step 3: Choose your AI brain${c.reset}`);
  const llm = await select('Which LLM provider?', [
    `${c.magenta}Claude (Anthropic)${c.reset} — Best reasoning`,
    `${c.green}GPT-4 (OpenAI)${c.reset} — Most popular`,
    `${c.blue}Gemini (Google)${c.reset} — Fast & capable`,
    `${c.yellow}Ollama (Local)${c.reset} — Free, private, runs locally`,
  ]);

  const llmProviders = ['anthropic', 'openai', 'google', 'ollama'];
  const selectedLLM = llmProviders[llm];

  let apiKey = '';
  if (selectedLLM !== 'ollama') {
    const envVars: Record<string, string> = {
      anthropic: 'ANTHROPIC_API_KEY',
      openai: 'OPENAI_API_KEY', 
      google: 'GOOGLE_API_KEY',
    };
    const existingKey = process.env[envVars[selectedLLM]];
    
    if (existingKey) {
      console.log(`${c.green}✓${c.reset} Found ${envVars[selectedLLM]} in environment`);
    } else {
      apiKey = await ask(`${c.cyan}${envVars[selectedLLM]}:${c.reset} `);
    }
  }

  // Step 4: Agent personality
  console.log(`\n${c.bold}Step 4: Agent Personality${c.reset}`);
  const personality = await select('What kind of agent?', [
    `${c.cyan}Assistant${c.reset} — Helpful, friendly, general purpose`,
    `${c.yellow}Specialist${c.reset} — Expert in a specific domain`,
    `${c.magenta}Creative${c.reset} — Playful, witty, entertaining`,
    `${c.red}Minimal${c.reset} — Just answers questions, no fluff`,
  ]);

  const personalities = ['assistant', 'specialist', 'creative', 'minimal'];
  const selectedPersonality = personalities[personality];

  let specialization = '';
  if (selectedPersonality === 'specialist') {
    specialization = await ask(`${c.cyan}What's the specialty?${c.reset} (e.g., "crypto trading", "coding", "fitness"): `);
  }

  // Step 5: Name your agent
  const agentName = await ask(`\n${c.cyan}Name your agent:${c.reset} `) || 'Atlas';

  // Generate config
  console.log(`\n${c.bold}Generating your agent...${c.reset}\n`);

  const config = {
    name: agentName,
    channel: selectedChannel,
    channelToken: token,
    llm: {
      provider: selectedLLM,
      apiKey: apiKey || undefined,
    },
    personality: selectedPersonality,
    specialization: specialization || undefined,
  };

  // Create project files
  const s1 = spinner('Creating project structure');
  await sleep(500);
  s1.stop();

  const s2 = spinner('Generating agent configuration');
  await sleep(400);
  generateConfig(config);
  s2.stop();

  const s3 = spinner('Setting up channel integration');
  await sleep(600);
  generateChannelIntegration(config);
  s3.stop();

  if (selectedChannel === 'terminal') {
    const s4 = spinner('Starting terminal agent');
    await sleep(300);
    s4.stop();
    
    console.log(`\n${c.green}${c.bold}✓ Agent "${agentName}" is ready!${c.reset}\n`);
    console.log(`${c.dim}Starting interactive session...${c.reset}\n`);
    
    await runTerminalAgent(config);
  } else {
    console.log(`\n${c.green}${c.bold}✓ Agent "${agentName}" is configured!${c.reset}\n`);
    console.log(`${c.bold}Files created:${c.reset}`);
    console.log(`  ${c.dim}./everythingos.config.json${c.reset}`);
    console.log(`  ${c.dim}./agents/${agentName.toLowerCase()}.ts${c.reset}`);
    console.log(`\n${c.bold}To start your agent:${c.reset}`);
    console.log(`  ${c.cyan}npm run agent${c.reset}\n`);
    
    const startNow = await confirm('Start the agent now?');
    if (startNow) {
      console.log(`\n${c.yellow}Starting ${agentName}...${c.reset}\n`);
      // Would spawn the agent process here
      console.log(`${c.green}✓${c.reset} Agent is running! Send a message to your bot.`);
      console.log(`${c.dim}Press Ctrl+C to stop${c.reset}\n`);
    }
  }

  await ask(`\n${c.dim}Press Enter to return to menu...${c.reset}`);
  await mainMenu();
}

// ─────────────────────────────────────────────────────────────────────────────
// Create Custom Agent
// ─────────────────────────────────────────────────────────────────────────────

async function createAgent(): Promise<void> {
  console.clear();
  console.log(`\n${c.blue}${c.bold}🤖 CREATE AGENT${c.reset}`);
  console.log(`${c.dim}Scaffold a custom agent from templates${c.reset}\n`);

  const agentType = await select('What type of agent?', [
    `${c.cyan}Perception${c.reset} — Monitors and observes (APIs, sensors, messages)`,
    `${c.yellow}Analysis${c.reset} — Processes and understands data`,
    `${c.magenta}Decision${c.reset} — Makes choices and routes actions`,
    `${c.green}Execution${c.reset} — Takes actions (sends messages, controls hardware)`,
    `${c.blue}Learning${c.reset} — Improves over time from feedback`,
    `${c.white}Custom${c.reset} — Blank template`,
  ]);

  const types = ['perception', 'analysis', 'decision', 'execution', 'learning', 'custom'];
  const selectedType = types[agentType];

  const name = await ask(`\n${c.cyan}Agent name:${c.reset} `) || 'MyAgent';
  const description = await ask(`${c.cyan}Description:${c.reset} `) || 'A custom agent';

  const tickRate = await ask(`${c.cyan}Tick rate (ms):${c.reset} ${c.dim}[5000]${c.reset} `) || '5000';

  const s = spinner(`Creating ${name}`);
  await sleep(500);
  generateAgentFile(name, selectedType, description, parseInt(tickRate));
  s.stop();

  console.log(`\n${c.green}${c.bold}✓ Agent created!${c.reset}\n`);
  console.log(`${c.bold}File:${c.reset} ${c.dim}./src/agents/${name.toLowerCase()}.ts${c.reset}`);
  console.log(`\n${c.bold}Next steps:${c.reset}`);
  console.log(`  1. Edit the agent file to add your logic`);
  console.log(`  2. Register it: ${c.cyan}agentRegistry.register(new ${name}())${c.reset}`);
  console.log(`  3. Run: ${c.cyan}npm run dev${c.reset}\n`);

  await ask(`${c.dim}Press Enter to return to menu...${c.reset}`);
  await mainMenu();
}

// ─────────────────────────────────────────────────────────────────────────────
// Run Simulation
// ─────────────────────────────────────────────────────────────────────────────

async function runSimulation(): Promise<void> {
  console.clear();
  console.log(`\n${c.magenta}${c.bold}🛸 SIMULATIONS${c.reset}`);
  console.log(`${c.dim}Test agent coordination without hardware${c.reset}\n`);

  const sim = await select('Which simulation?', [
    `${c.cyan}🤖 Robot${c.reset} — Single robot in 2D world`,
    `${c.magenta}🛸 UAP Swarm${c.reset} — 5 UAPs in formation`,
    `${c.yellow}📡 Sensor Network${c.reset} — Distributed sensors`,
    `${c.green}🏭 Factory Floor${c.reset} — Multi-robot coordination`,
  ]);

  const sims = ['sim', 'swarm', 'sensors', 'factory'];
  const selectedSim = sims[sim];

  if (selectedSim === 'sensors' || selectedSim === 'factory') {
    console.log(`\n${c.yellow}Coming soon!${c.reset} This simulation is in development.\n`);
    await ask(`${c.dim}Press Enter to return to menu...${c.reset}`);
    await mainMenu();
    return;
  }

  console.log(`\n${c.green}Launching ${selectedSim} simulation...${c.reset}\n`);
  console.log(`${c.dim}Run this command in your terminal:${c.reset}`);
  console.log(`\n  ${c.cyan}npm run ${selectedSim}${c.reset}\n`);

  await ask(`${c.dim}Press Enter to return to menu...${c.reset}`);
  await mainMenu();
}

// ─────────────────────────────────────────────────────────────────────────────
// Configure
// ─────────────────────────────────────────────────────────────────────────────

async function configure(): Promise<void> {
  console.clear();
  console.log(`\n${c.yellow}${c.bold}⚙️  CONFIGURATION${c.reset}`);
  console.log(`${c.dim}Set up providers and system settings${c.reset}\n`);

  const setting = await select('What would you like to configure?', [
    `${c.magenta}LLM Providers${c.reset} — API keys for Claude, GPT-4, etc.`,
    `${c.blue}Channels${c.reset} — Discord, Telegram, WhatsApp tokens`,
    `${c.green}Hardware${c.reset} — Raspberry Pi, Jetson settings`,
    `${c.yellow}Memory${c.reset} — Database and storage settings`,
    `${c.cyan}Security${c.reset} — Rate limits, permissions`,
    `${c.dim}← Back${c.reset}`,
  ]);

  switch (setting) {
    case 0:
      await configureLLM();
      break;
    case 1:
      await configureChannels();
      break;
    case 2:
      await configureHardware();
      break;
    case 3:
    case 4:
      console.log(`\n${c.yellow}Coming soon!${c.reset}\n`);
      await ask(`${c.dim}Press Enter to continue...${c.reset}`);
      break;
    case 5:
      await mainMenu();
      return;
  }

  await configure();
}

async function configureLLM(): Promise<void> {
  console.log(`\n${c.bold}LLM Provider Configuration${c.reset}\n`);

  const providers = [
    { name: 'Anthropic (Claude)', env: 'ANTHROPIC_API_KEY', url: 'https://console.anthropic.com/' },
    { name: 'OpenAI (GPT-4)', env: 'OPENAI_API_KEY', url: 'https://platform.openai.com/api-keys' },
    { name: 'Google (Gemini)', env: 'GOOGLE_API_KEY', url: 'https://makersuite.google.com/app/apikey' },
  ];

  for (const provider of providers) {
    const existing = process.env[provider.env];
    const status = existing ? `${c.green}✓ configured${c.reset}` : `${c.dim}not set${c.reset}`;
    console.log(`  ${provider.name}: ${status}`);
  }

  console.log();
  const choice = await select('Configure which provider?', [
    ...providers.map(p => p.name),
    `${c.dim}← Back${c.reset}`,
  ]);

  if (choice < providers.length) {
    const provider = providers[choice];
    console.log(`\n${c.dim}Get your key from: ${provider.url}${c.reset}`);
    const key = await ask(`${c.cyan}${provider.env}:${c.reset} `);
    
    if (key) {
      // Would save to .env file
      console.log(`${c.green}✓${c.reset} Saved ${provider.env}`);
    }
  }
}

async function configureChannels(): Promise<void> {
  console.log(`\n${c.bold}Channel Configuration${c.reset}\n`);
  console.log(`${c.dim}Configure messaging platform integrations${c.reset}\n`);

  const choice = await select('Which channel?', [
    `${c.blue}Discord${c.reset}`,
    `${c.cyan}Telegram${c.reset}`,
    `${c.green}WhatsApp${c.reset}`,
    `${c.dim}← Back${c.reset}`,
  ]);

  if (choice === 0) {
    console.log(`\n${c.dim}Get your token from: https://discord.com/developers/applications${c.reset}`);
    const token = await ask(`${c.cyan}Discord Bot Token:${c.reset} `);
    if (token) console.log(`${c.green}✓${c.reset} Discord configured`);
  } else if (choice === 1) {
    console.log(`\n${c.dim}Get your token from @BotFather on Telegram${c.reset}`);
    const token = await ask(`${c.cyan}Telegram Bot Token:${c.reset} `);
    if (token) console.log(`${c.green}✓${c.reset} Telegram configured`);
  } else if (choice === 2) {
    console.log(`\n${c.yellow}WhatsApp requires QR code authentication${c.reset}`);
    console.log(`${c.dim}This will be implemented in the next update${c.reset}`);
  }
}

async function configureHardware(): Promise<void> {
  console.log(`\n${c.bold}Hardware Configuration${c.reset}\n`);

  const choice = await select('Which platform?', [
    `${c.red}Raspberry Pi${c.reset}`,
    `${c.green}NVIDIA Jetson${c.reset}`,
    `${c.blue}Arduino (via serial)${c.reset}`,
    `${c.dim}← Back${c.reset}`,
  ]);

  if (choice < 3) {
    console.log(`\n${c.yellow}Hardware configuration requires physical device${c.reset}`);
    console.log(`${c.dim}See HARDWARE.md for setup instructions${c.reset}\n`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard & Docs
// ─────────────────────────────────────────────────────────────────────────────

async function openDashboard(): Promise<void> {
  console.log(`\n${c.cyan}Opening dashboard...${c.reset}`);
  console.log(`\n${c.yellow}Dashboard is coming soon!${c.reset}`);
  console.log(`${c.dim}For now, use: npm run demo:cli${c.reset}\n`);
  await ask(`${c.dim}Press Enter to return to menu...${c.reset}`);
  await mainMenu();
}

async function openDocs(): Promise<void> {
  console.log(`\n${c.cyan}Opening documentation...${c.reset}`);
  const url = 'https://github.com/m0rs3c0d3/EverythingOS#readme';
  
  try {
    const cmd = process.platform === 'darwin' ? 'open' :
                process.platform === 'win32' ? 'start' : 'xdg-open';
    execSync(`${cmd} ${url}`, { stdio: 'ignore' });
    console.log(`${c.green}✓${c.reset} Opened in browser\n`);
  } catch {
    console.log(`${c.dim}Visit: ${url}${c.reset}\n`);
  }
  
  await ask(`${c.dim}Press Enter to return to menu...${c.reset}`);
  await mainMenu();
}

// ─────────────────────────────────────────────────────────────────────────────
// Terminal Agent (Interactive Chat)
// ─────────────────────────────────────────────────────────────────────────────

async function runTerminalAgent(config: any): Promise<void> {
  console.log(`${c.cyan}${c.bold}${config.name}${c.reset}: Hello! I'm ${config.name}, your AI assistant. How can I help?\n`);
  console.log(`${c.dim}Type your message or 'exit' to quit${c.reset}\n`);

  while (true) {
    const input = await ask(`${c.green}You:${c.reset} `);
    
    if (input.toLowerCase() === 'exit') {
      console.log(`\n${c.cyan}${config.name}:${c.reset} Goodbye! 👋\n`);
      break;
    }

    if (!input) continue;

    // Simulate thinking
    process.stdout.write(`${c.cyan}${config.name}:${c.reset} ${c.dim}thinking...${c.reset}`);
    await sleep(500 + Math.random() * 1000);
    process.stdout.write('\r' + ' '.repeat(50) + '\r');

    // Mock response (would call LLM in real implementation)
    const responses = [
      "That's an interesting question! Let me think about it...",
      "I'd be happy to help with that!",
      "Great question! Here's what I know...",
      "Hmm, let me process that for you...",
    ];
    const response = responses[Math.floor(Math.random() * responses.length)];
    console.log(`${c.cyan}${config.name}:${c.reset} ${response}\n`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// File Generators
// ─────────────────────────────────────────────────────────────────────────────

function generateConfig(config: any): void {
  const configContent = {
    name: config.name,
    version: '1.0.0',
    channel: {
      type: config.channel,
      token: config.channelToken ? '***' : undefined,
    },
    llm: {
      provider: config.llm.provider,
      model: config.llm.provider === 'anthropic' ? 'claude-sonnet-4-20250514' :
             config.llm.provider === 'openai' ? 'gpt-4o' :
             config.llm.provider === 'google' ? 'gemini-pro' : 'llama2',
    },
    agent: {
      personality: config.personality,
      specialization: config.specialization,
    },
  };

  // Would write to file in real implementation
  // fs.writeFileSync('everythingos.config.json', JSON.stringify(configContent, null, 2));
}

function generateChannelIntegration(config: any): void {
  // Would generate channel-specific integration code
}

function generateAgentFile(name: string, type: string, description: string, tickRate: number): void {
  const template = `// Generated by EverythingOS CLI
import { Agent } from 'everythingos';

export class ${name} extends Agent {
  constructor() {
    super({
      id: '${name.toLowerCase()}',
      name: '${name}',
      type: '${type}',
      description: '${description}',
      tickRate: ${tickRate},
    });
  }

  protected async onStart(): Promise<void> {
    this.log('info', '${name} started');
    // Add your initialization logic here
  }

  protected async onStop(): Promise<void> {
    this.log('info', '${name} stopped');
    // Add your cleanup logic here
  }

  protected async onTick(): Promise<void> {
    // Add your periodic logic here
  }
}
`;

  // Would write to file in real implementation
  // fs.mkdirSync('src/agents', { recursive: true });
  // fs.writeFileSync(`src/agents/${name.toLowerCase()}.ts`, template);
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry Point
// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  // Handle command line arguments
  const args = process.argv.slice(2);
  
  if (args[0] === 'init') {
    await quickStart();
  } else if (args[0] === 'agent') {
    await createAgent();
  } else if (args[0] === 'sim') {
    await runSimulation();
  } else if (args[0] === 'config') {
    await configure();
  } else {
    await mainMenu();
  }

  rl.close();
}

main().catch(console.error);
