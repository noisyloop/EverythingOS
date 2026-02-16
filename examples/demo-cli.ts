#!/usr/bin/env npx tsx
// EVERYTHINGOS - Interactive CLI Demo

import { eventBus, agentRegistry, ClockAgent, HealthMonitorAgent } from '../src';

const c = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
};

console.log(`${c.cyan}
╔═══════════════════════════════════════════════════════════╗
║           EVERYTHINGOS - Interactive CLI                  ║
╚═══════════════════════════════════════════════════════════╝
${c.reset}`);

const clock = new ClockAgent({ tickRate: 2000 });
const health = new HealthMonitorAgent({ tickRate: 5000 });

agentRegistry.register(clock);
agentRegistry.register(health);

let eventCount = 0;

eventBus.on('*', (e) => {
  eventCount++;
  if (!e.type.includes(':tick')) {
    const time = new Date().toLocaleTimeString();
    console.log(`${c.dim}${time}${c.reset} ${c.cyan}${e.type}${c.reset}`);
  }
});

await clock.start();
await health.start();

console.log(`${c.green}System running!${c.reset} Commands: ${c.yellow}s${c.reset}=status ${c.yellow}e${c.reset}=emit ${c.yellow}q${c.reset}=quit\n`);

if (process.stdin.isTTY) {
  process.stdin.setRawMode(true);
}
process.stdin.resume();
process.stdin.setEncoding('utf8');

process.stdin.on('data', async (key: string) => {
  switch (key.toLowerCase()) {
    case 's':
      console.log(`\n${c.yellow}Status:${c.reset} ${agentRegistry.getAll().length} agents, ${eventCount} events`);
      break;
    case 'e':
      eventBus.emit('test:manual', { time: Date.now() });
      console.log(`${c.green}Emitted test:manual${c.reset}`);
      break;
    case 'q':
    case '\u0003':
      console.log(`\n${c.yellow}Shutting down...${c.reset}`);
      await clock.stop();
      await health.stop();
      console.log(`${c.green}Goodbye!${c.reset}`);
      process.exit(0);
  }
});
