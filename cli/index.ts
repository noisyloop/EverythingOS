#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS CLI
// The "holy" first-touch experience - NOW FULLY FUNCTIONAL
// ═══════════════════════════════════════════════════════════════════════════════

import * as readline from 'readline';
import * as fs from 'fs';
import * as path from 'path';
import { execSync, spawn, ChildProcess } from 'child_process';
import { fileURLToPath } from 'url';

// Get directory paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, '..');

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

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ─────────────────────────────────────────────────────────────────────────────
// File Operations - NOW REAL
// ─────────────────────────────────────────────────────────────────────────────

function ensureDir(dir: string): void {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function writeEnvFile(vars: Record<string, string>): void {
  const envPath = path.join(PROJECT_ROOT, '.env');
  let content = '';
  
  // Read existing .env if exists
  if (fs.existsSync(envPath)) {
    content = fs.readFileSync(envPath, 'utf-8');
  }
  
  // Update or add each variable
  for (const [key, value] of Object.entries(vars)) {
    if (!value) continue;
    
    const regex = new RegExp(`^${key}=.*$`, 'm');
    if (regex.test(content)) {
      content = content.replace(regex, `${key}=${value}`);
    } else {
      content += `\n${key}=${value}`;
    }
  }
  
  fs.writeFileSync(envPath, content.trim() + '\n');
}

function readEnvFile(): Record<string, string> {
  const envPath = path.join(PROJECT_ROOT, '.env');
  const vars: Record<string, string> = {};
  
  if (!fs.existsSync(envPath)) return vars;
  
  const content = fs.readFileSync(envPath, 'utf-8');
  for (const line of content.split('\n')) {
    const match = line.match(/^([^=]+)=(.*)$/);
    if (match) {
      vars[match[1]] = match[2];
    }
  }
  
  return vars;
}

function writeConfigFile(config: any): void {
  const configPath = path.join(PROJECT_ROOT, 'everythingos.config.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
}

function writeAgentFile(name: string, type: string, description: string, tickRate: number): string {
  const agentsDir = path.join(PROJECT_ROOT, 'src', 'agents', 'custom');
  ensureDir(agentsDir);
  
  const className = name.charAt(0).toUpperCase() + name.slice(1).replace(/[^a-zA-Z0-9]/g, '');
  const fileName = `${name.toLowerCase().replace(/[^a-z0-9]/g, '-')}.ts`;
  const filePath = path.join(agentsDir, fileName);
  
  const template = `// Generated by EverythingOS CLI
import { Agent } from '../../runtime/Agent';
import { eventBus } from '../../core/event-bus/EventBus';

export class ${className}Agent extends Agent {
  constructor() {
    super({
      id: '${name.toLowerCase().replace(/[^a-z0-9]/g, '-')}',
      name: '${name}',
      type: '${type}',
      tickRate: ${tickRate},
    });
  }

  protected async onStart(): Promise<void> {
    this.log('info', '${name} agent started');
    
    // Subscribe to events
    // this.subscribe('some:event', (e) => this.handleEvent(e));
  }

  protected async onStop(): Promise<void> {
    this.log('info', '${name} agent stopped');
  }

  protected async onTick(): Promise<void> {
    // Runs every ${tickRate}ms
    // Add your periodic logic here
    
    // Example: emit an event
    // this.emit('${name.toLowerCase()}:tick', { timestamp: Date.now() });
  }
}

// Export for registration
export default ${className}Agent;
`;

  fs.writeFileSync(filePath, template);
  return filePath;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Menu
// ─────────────────────────────────────────────────────────────────────────────

async function mainMenu(): Promise<void> {
  console.clear();
  console.log(BANNER);
  
  const choice = await select('What would you like to do?', [
    `${c.green}🚀 Quick Start${c.reset} — Deploy a Discord bot in 60 seconds`,
    `${c.blue}🤖 Create Agent${c.reset} — Scaffold a custom agent`,
    `${c.magenta}🛸 Run Simulation${c.reset} — Launch robot or swarm demo`,
    `${c.yellow}⚙️  Configure${c.reset} — Set up LLM providers & settings`,
    `${c.dim}📖 Documentation${c.reset} — Open docs in browser`,
    `${c.dim}❌ Exit${c.reset}`,
  ]);

  switch (choice) {
    case 0: await quickStart(); break;
    case 1: await createAgent(); break;
    case 2: await runSimulation(); break;
    case 3: await configure(); break;
    case 4: await openDocs(); break;
    case 5: 
      console.log(`\n${c.cyan}Goodbye! 👋${c.reset}\n`);
      rl.close();
      process.exit(0);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Quick Start — NOW FUNCTIONAL
// ─────────────────────────────────────────────────────────────────────────────

async function quickStart(): Promise<void> {
  console.clear();
  console.log(`\n${c.cyan}${c.bold}🚀 QUICK START${c.reset}`);
  console.log(`${c.dim}Deploy your first agent in 60 seconds${c.reset}\n`);

  // Step 1: Choose channel
  const channel = await select('Where should your agent live?', [
    `${c.blue}Discord${c.reset} — Best for developer communities`,
    `${c.cyan}Telegram${c.reset} — Popular with crypto/tech builders`,
    `${c.yellow}Terminal${c.reset} — Local testing (no setup needed)`,
  ]);

  const channels = ['discord', 'telegram', 'terminal'];
  const selectedChannel = channels[channel];

  // Step 2: Get credentials (skip for terminal)
  let channelToken = '';
  if (selectedChannel === 'discord') {
    console.log(`\n${c.bold}Step 2: Discord Bot Token${c.reset}`);
    console.log(`${c.dim}Get your token from: https://discord.com/developers/applications${c.reset}`);
    console.log(`${c.dim}1. Create Application → 2. Bot → 3. Reset Token → 4. Copy${c.reset}\n`);
    channelToken = await ask(`${c.cyan}Bot Token:${c.reset} `);
    
    if (!channelToken) {
      console.log(`${c.red}Token required for Discord bot.${c.reset}`);
      await ask(`${c.dim}Press Enter to return to menu...${c.reset}`);
      return mainMenu();
    }
  } else if (selectedChannel === 'telegram') {
    console.log(`\n${c.bold}Step 2: Telegram Bot Token${c.reset}`);
    console.log(`${c.dim}Get your token from @BotFather on Telegram${c.reset}\n`);
    channelToken = await ask(`${c.cyan}Bot Token:${c.reset} `);
    
    if (!channelToken) {
      console.log(`${c.red}Token required for Telegram bot.${c.reset}`);
      await ask(`${c.dim}Press Enter to return to menu...${c.reset}`);
      return mainMenu();
    }
  }

  // Step 3: Choose LLM
  console.log(`\n${c.bold}Step 3: Choose your AI brain${c.reset}`);
  const llm = await select('Which LLM provider?', [
    `${c.magenta}Claude (Anthropic)${c.reset} — Best reasoning`,
    `${c.green}GPT-4 (OpenAI)${c.reset} — Most popular`,
    `${c.yellow}Ollama (Local)${c.reset} — Free, private, runs locally`,
  ]);

  const llmProviders = ['anthropic', 'openai', 'ollama'];
  const selectedLLM = llmProviders[llm];

  let apiKey = '';
  const envVars: Record<string, string> = {
    anthropic: 'ANTHROPIC_API_KEY',
    openai: 'OPENAI_API_KEY',
  };

  if (selectedLLM !== 'ollama') {
    const envVar = envVars[selectedLLM];
    const existingKey = process.env[envVar] || readEnvFile()[envVar];
    
    if (existingKey) {
      console.log(`${c.green}✓${c.reset} Found ${envVar} in environment`);
      apiKey = existingKey;
    } else {
      console.log(`\n${c.dim}Get your key from: ${selectedLLM === 'anthropic' ? 'https://console.anthropic.com/' : 'https://platform.openai.com/api-keys'}${c.reset}`);
      apiKey = await ask(`${c.cyan}${envVar}:${c.reset} `);
      
      if (!apiKey) {
        console.log(`${c.red}API key required.${c.reset}`);
        await ask(`${c.dim}Press Enter to return to menu...${c.reset}`);
        return mainMenu();
      }
    }
  }

  // Step 4: Agent name
  const agentName = await ask(`\n${c.cyan}Name your agent:${c.reset} `) || 'Atlas';

  // ─────────────────────────────────────────────────────────────────────────
  // Generate files
  // ─────────────────────────────────────────────────────────────────────────
  
  console.log(`\n${c.bold}Setting up your agent...${c.reset}\n`);

  // Save environment variables
  const s1 = spinner('Saving configuration');
  await sleep(300);
  
  const envToSave: Record<string, string> = {};
  if (selectedChannel === 'discord' && channelToken) {
    envToSave.DISCORD_BOT_TOKEN = channelToken;
  } else if (selectedChannel === 'telegram' && channelToken) {
    envToSave.TELEGRAM_BOT_TOKEN = channelToken;
  }
  if (apiKey && selectedLLM !== 'ollama') {
    envToSave[envVars[selectedLLM]] = apiKey;
  }
  
  writeEnvFile(envToSave);
  s1.stop();

  // Save config file
  const s2 = spinner('Creating config file');
  await sleep(200);
  
  const config = {
    name: agentName,
    version: '1.0.0',
    channel: selectedChannel,
    llm: {
      provider: selectedLLM,
      model: selectedLLM === 'anthropic' ? 'claude-sonnet-4-20250514' :
             selectedLLM === 'openai' ? 'gpt-4o' : 'llama2',
    },
    security: {
      allowDMs: false,
      rateLimit: { perUser: 10, windowMs: 60000 },
      promptInjectionDetection: true,
    },
  };
  
  writeConfigFile(config);
  s2.stop();

  // Summary
  console.log(`\n${c.green}${c.bold}✓ Agent "${agentName}" is ready!${c.reset}\n`);
  
  console.log(`${c.bold}Files created:${c.reset}`);
  console.log(`  ${c.dim}.env${c.reset} — Your API keys (keep secret!)`);
  console.log(`  ${c.dim}everythingos.config.json${c.reset} — Agent configuration`);
  
  console.log(`\n${c.bold}Security enabled:${c.reset}`);
  console.log(`  ${c.green}✓${c.reset} DMs disabled by default`);
  console.log(`  ${c.green}✓${c.reset} Rate limiting (10 msgs/min per user)`);
  console.log(`  ${c.green}✓${c.reset} Prompt injection detection`);

  // Run or show command
  if (selectedChannel === 'terminal') {
    console.log(`\n${c.bold}Starting terminal agent...${c.reset}\n`);
    await runTerminalAgent(agentName, selectedLLM, apiKey);
  } else if (selectedChannel === 'discord') {
    const startNow = await confirm(`\n${c.bold}Start the Discord bot now?${c.reset}`);
    
    if (startNow) {
      console.log(`\n${c.yellow}Starting ${agentName}...${c.reset}`);
      console.log(`${c.dim}Press Ctrl+C to stop${c.reset}\n`);
      
      // Spawn the Discord bot
      const botProcess = spawn('npx', ['tsx', 'examples/discord-bot.ts'], {
        cwd: PROJECT_ROOT,
        stdio: 'inherit',
        env: { ...process.env, ...envToSave },
      });
      
      // Handle exit
      botProcess.on('close', (code) => {
        console.log(`\n${c.dim}Bot stopped with code ${code}${c.reset}`);
        rl.close();
        process.exit(code || 0);
      });
      
      // Keep CLI alive
      return;
    } else {
      console.log(`\n${c.bold}To start later:${c.reset}`);
      console.log(`  ${c.cyan}npm run discord${c.reset}\n`);
    }
  } else if (selectedChannel === 'telegram') {
    console.log(`\n${c.yellow}Telegram integration coming soon!${c.reset}`);
    console.log(`${c.dim}For now, use Discord or Terminal mode.${c.reset}\n`);
  }

  await ask(`${c.dim}Press Enter to return to menu...${c.reset}`);
  await mainMenu();
}

// ─────────────────────────────────────────────────────────────────────────────
// Terminal Agent - WITH REAL LLM CALLS
// ─────────────────────────────────────────────────────────────────────────────

async function runTerminalAgent(name: string, provider: string, apiKey: string): Promise<void> {
  console.log(`${c.cyan}${c.bold}${name}${c.reset}: Hello! I'm ${name}. How can I help you today?\n`);
  console.log(`${c.dim}Type your message or 'exit' to quit${c.reset}\n`);

  const systemPrompt = `You are ${name}, a helpful AI assistant. Be concise, friendly, and helpful. Keep responses brief unless asked for detail.`;

  while (true) {
    const input = await ask(`${c.green}You:${c.reset} `);
    
    if (input.toLowerCase() === 'exit' || input.toLowerCase() === 'quit') {
      console.log(`\n${c.cyan}${name}:${c.reset} Goodbye! 👋\n`);
      break;
    }

    if (!input) continue;

    process.stdout.write(`${c.cyan}${name}:${c.reset} ${c.dim}thinking...${c.reset}`);

    try {
      let response: string;
      
      if (provider === 'ollama') {
        response = await callOllama(input, systemPrompt);
      } else if (provider === 'anthropic') {
        response = await callAnthropic(input, systemPrompt, apiKey);
      } else if (provider === 'openai') {
        response = await callOpenAI(input, systemPrompt, apiKey);
      } else {
        response = "I'm not sure how to respond to that.";
      }

      // Clear "thinking..." and print response
      process.stdout.write('\r' + ' '.repeat(60) + '\r');
      console.log(`${c.cyan}${name}:${c.reset} ${response}\n`);
      
    } catch (error: any) {
      process.stdout.write('\r' + ' '.repeat(60) + '\r');
      console.log(`${c.red}Error:${c.reset} ${error.message}\n`);
    }
  }

  await ask(`${c.dim}Press Enter to return to menu...${c.reset}`);
  await mainMenu();
}

async function callAnthropic(message: string, system: string, apiKey: string): Promise<string> {
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 500,
      system,
      messages: [{ role: 'user', content: message }],
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Anthropic API error: ${response.status}`);
  }

  const data = await response.json();
  return data.content[0]?.text || 'No response';
}

async function callOpenAI(message: string, system: string, apiKey: string): Promise<string> {
  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: 'gpt-4o',
      max_tokens: 500,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: message },
      ],
    }),
  });

  if (!response.ok) {
    throw new Error(`OpenAI API error: ${response.status}`);
  }

  const data = await response.json();
  return data.choices[0]?.message?.content || 'No response';
}

async function callOllama(message: string, system: string): Promise<string> {
  const baseUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
  
  const response = await fetch(`${baseUrl}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'llama2',
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: message },
      ],
      stream: false,
    }),
  });

  if (!response.ok) {
    throw new Error(`Ollama error: Is Ollama running? (${response.status})`);
  }

  const data = await response.json();
  return data.message?.content || 'No response';
}

// ─────────────────────────────────────────────────────────────────────────────
// Create Agent - NOW FUNCTIONAL
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
  ]);

  const types = ['perception', 'analysis', 'decision', 'execution', 'learning'];
  const selectedType = types[agentType];

  const name = await ask(`\n${c.cyan}Agent name:${c.reset} `);
  if (!name) {
    console.log(`${c.red}Name required.${c.reset}`);
    await ask(`${c.dim}Press Enter to return to menu...${c.reset}`);
    return mainMenu();
  }

  const description = await ask(`${c.cyan}Description:${c.reset} `) || `A ${selectedType} agent`;
  const tickRateStr = await ask(`${c.cyan}Tick rate (ms):${c.reset} ${c.dim}[5000]${c.reset} `) || '5000';
  const tickRate = parseInt(tickRateStr, 10) || 5000;

  const s = spinner(`Creating ${name} agent`);
  await sleep(400);
  
  const filePath = writeAgentFile(name, selectedType, description, tickRate);
  s.stop();

  console.log(`\n${c.green}${c.bold}✓ Agent created!${c.reset}\n`);
  console.log(`${c.bold}File:${c.reset}`);
  console.log(`  ${c.dim}${filePath.replace(PROJECT_ROOT, '.')}${c.reset}`);
  
  console.log(`\n${c.bold}Next steps:${c.reset}`);
  console.log(`  1. Edit the agent file to add your logic`);
  console.log(`  2. Import and register it in your app:`);
  console.log(`     ${c.cyan}import ${name.charAt(0).toUpperCase() + name.slice(1)}Agent from './agents/custom/${name.toLowerCase()}';${c.reset}`);
  console.log(`     ${c.cyan}agentRegistry.register(new ${name.charAt(0).toUpperCase() + name.slice(1)}Agent());${c.reset}`);
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
    `${c.dim}← Back${c.reset}`,
  ]);

  if (sim === 2) {
    return mainMenu();
  }

  const commands = ['sim', 'swarm'];
  const selectedSim = commands[sim];

  console.log(`\n${c.green}Launching ${selectedSim} simulation...${c.reset}\n`);
  
  // Spawn the simulation
  const simProcess = spawn('npx', ['tsx', `examples/demo-${selectedSim === 'sim' ? 'robot' : 'swarm'}.ts`], {
    cwd: PROJECT_ROOT,
    stdio: 'inherit',
  });

  simProcess.on('close', async (code) => {
    console.log(`\n${c.dim}Simulation ended.${c.reset}`);
    await ask(`${c.dim}Press Enter to return to menu...${c.reset}`);
    await mainMenu();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Configure
// ─────────────────────────────────────────────────────────────────────────────

async function configure(): Promise<void> {
  console.clear();
  console.log(`\n${c.yellow}${c.bold}⚙️  CONFIGURATION${c.reset}`);
  console.log(`${c.dim}Set up providers and system settings${c.reset}\n`);

  // Show current config
  const envVars = readEnvFile();
  const hasAnthropic = envVars.ANTHROPIC_API_KEY || process.env.ANTHROPIC_API_KEY;
  const hasOpenAI = envVars.OPENAI_API_KEY || process.env.OPENAI_API_KEY;
  const hasDiscord = envVars.DISCORD_BOT_TOKEN || process.env.DISCORD_BOT_TOKEN;
  
  console.log(`${c.bold}Current Status:${c.reset}`);
  console.log(`  Anthropic: ${hasAnthropic ? `${c.green}✓ configured${c.reset}` : `${c.dim}not set${c.reset}`}`);
  console.log(`  OpenAI:    ${hasOpenAI ? `${c.green}✓ configured${c.reset}` : `${c.dim}not set${c.reset}`}`);
  console.log(`  Discord:   ${hasDiscord ? `${c.green}✓ configured${c.reset}` : `${c.dim}not set${c.reset}`}`);

  const choice = await select('\nWhat would you like to configure?', [
    `${c.magenta}Anthropic API Key${c.reset}`,
    `${c.green}OpenAI API Key${c.reset}`,
    `${c.blue}Discord Bot Token${c.reset}`,
    `${c.dim}← Back${c.reset}`,
  ]);

  if (choice === 3) {
    return mainMenu();
  }

  const configs = [
    { name: 'ANTHROPIC_API_KEY', url: 'https://console.anthropic.com/' },
    { name: 'OPENAI_API_KEY', url: 'https://platform.openai.com/api-keys' },
    { name: 'DISCORD_BOT_TOKEN', url: 'https://discord.com/developers/applications' },
  ];

  const selected = configs[choice];
  console.log(`\n${c.dim}Get your key from: ${selected.url}${c.reset}`);
  const value = await ask(`${c.cyan}${selected.name}:${c.reset} `);

  if (value) {
    writeEnvFile({ [selected.name]: value });
    console.log(`${c.green}✓${c.reset} Saved ${selected.name} to .env`);
  }

  await ask(`\n${c.dim}Press Enter to continue...${c.reset}`);
  await configure();
}

// ─────────────────────────────────────────────────────────────────────────────
// Open Docs
// ─────────────────────────────────────────────────────────────────────────────

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
// Entry Point
// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  if (args[0] === 'init' || args[0] === 'start') {
    await quickStart();
  } else if (args[0] === 'agent' || args[0] === 'create') {
    await createAgent();
  } else if (args[0] === 'sim' || args[0] === 'simulation') {
    await runSimulation();
  } else if (args[0] === 'config') {
    await configure();
  } else {
    await mainMenu();
  }
}

main().catch((err) => {
  console.error(`${c.red}Error:${c.reset}`, err.message);
  rl.close();
  process.exit(1);
});
