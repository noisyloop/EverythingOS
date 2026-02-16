#!/usr/bin/env npx tsx
// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Discord Bot Example
// Demonstrates the secure Discord integration
// ═══════════════════════════════════════════════════════════════════════════════

import { createDiscordBot, PRESET_PERSONALITIES } from '../src/integrations/discord';
import { eventBus } from '../src';

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

console.log(`${c.cyan}${c.bold}
╔═══════════════════════════════════════════════════════════╗
║           EVERYTHINGOS - Secure Discord Bot               ║
╚═══════════════════════════════════════════════════════════╝
${c.reset}`);

// Check for token
if (!process.env.DISCORD_BOT_TOKEN) {
  console.log(`${c.red}Error:${c.reset} DISCORD_BOT_TOKEN environment variable not set.`);
  console.log(`\n${c.dim}Get your token from: https://discord.com/developers/applications${c.reset}`);
  console.log(`\n${c.bold}To run:${c.reset}`);
  console.log(`  DISCORD_BOT_TOKEN=your_token npm run discord\n`);
  process.exit(1);
}

// Check for LLM API key
const hasLLMKey = process.env.ANTHROPIC_API_KEY || 
                  process.env.OPENAI_API_KEY || 
                  process.env.GOOGLE_API_KEY;

if (!hasLLMKey) {
  console.log(`${c.yellow}Warning:${c.reset} No LLM API key found.`);
  console.log(`${c.dim}Set one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY${c.reset}`);
  console.log(`${c.dim}Or use Ollama locally with OLLAMA_BASE_URL${c.reset}\n`);
}

// Determine LLM provider
const llmProvider = process.env.ANTHROPIC_API_KEY ? 'anthropic' :
                    process.env.OPENAI_API_KEY ? 'openai' :
                    process.env.GOOGLE_API_KEY ? 'google' : 'ollama';

console.log(`${c.green}✓${c.reset} LLM Provider: ${c.cyan}${llmProvider}${c.reset}`);

// Create bot
const bot = createDiscordBot({
  llm: { provider: llmProvider },
  personality: PRESET_PERSONALITIES.default,
  security: {
    allowDMs: false,  // Secure default
    enablePromptInjectionDetection: true,
    enablePIIDetection: true,
    enableAuditLog: true,
  },
  logLevel: 'info',
});

// Event listeners
eventBus.on('discord:ready', (e) => {
  const { username, personality } = e.payload as { username: string; personality: string };
  console.log(`\n${c.green}${c.bold}✓ Bot is online!${c.reset}`);
  console.log(`  Username:    ${c.cyan}${username}${c.reset}`);
  console.log(`  Personality: ${c.cyan}${personality}${c.reset}`);
  console.log(`  DMs:         ${c.yellow}disabled (secure default)${c.reset}`);
  console.log(`\n${c.dim}Mention the bot in a server to chat with it.${c.reset}`);
  console.log(`${c.dim}Press Ctrl+C to stop.${c.reset}\n`);
});

eventBus.on('discord:message:handled', (e) => {
  const { messageId, responseLength } = e.payload as { messageId: string; responseLength: number };
  console.log(`${c.green}✓${c.reset} Handled message ${c.dim}${messageId.slice(0, 8)}...${c.reset} (${responseLength} chars)`);
});

eventBus.on('discord:message:blocked', (e) => {
  const { reason, threatLevel } = e.payload as { reason: string; threatLevel: string };
  const color = threatLevel === 'high' ? c.red : threatLevel === 'medium' ? c.yellow : c.dim;
  console.log(`${color}✗ Blocked:${c.reset} ${reason} (threat: ${threatLevel})`);
});

eventBus.on('discord:security:injection', (e) => {
  const { patterns } = e.payload as { patterns: string[] };
  console.log(`${c.red}⚠ Injection attempt detected:${c.reset} ${patterns.join(', ')}`);
});

eventBus.on('discord:stopped', (e) => {
  const { uptime } = e.payload as { uptime: number };
  console.log(`\n${c.yellow}Bot stopped.${c.reset} Uptime: ${Math.floor(uptime / 1000)}s`);
});

// Start bot
console.log(`${c.dim}Connecting to Discord...${c.reset}`);
bot.start().catch((err) => {
  console.error(`${c.red}Failed to start:${c.reset}`, err.message);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log(`\n${c.yellow}Shutting down...${c.reset}`);
  await bot.stop();
  
  // Print stats
  const stats = bot.getStats();
  console.log(`\n${c.bold}Session Stats:${c.reset}`);
  console.log(`  Messages handled: ${stats.messageCount}`);
  console.log(`  Security blocks:  ${stats.securityStats.totalAuditEntries}`);
  console.log(`  Uptime:           ${Math.floor(stats.uptime / 1000)}s`);
  
  process.exit(0);
});

// Print security info
console.log(`\n${c.bold}Security Features:${c.reset}`);
console.log(`  ${c.green}✓${c.reset} Prompt injection detection`);
console.log(`  ${c.green}✓${c.reset} Rate limiting (10/min per user)`);
console.log(`  ${c.green}✓${c.reset} PII detection`);
console.log(`  ${c.green}✓${c.reset} Output sanitization`);
console.log(`  ${c.green}✓${c.reset} Audit logging`);
console.log(`  ${c.green}✓${c.reset} Hardened system prompt`);
