#!/usr/bin/env npx tsx
// EVERYTHINGOS - Simple Demo

import { eventBus, agentRegistry, ClockAgent, HealthMonitorAgent } from '../src';

console.log('EverythingOS Demo Starting...\n');

const clock = new ClockAgent({ tickRate: 2000 });
const health = new HealthMonitorAgent({ tickRate: 5000 });

agentRegistry.register(clock);
agentRegistry.register(health);

let tickCount = 0;

eventBus.on('world:tick', () => {
  tickCount++;
  console.log(`⏱  TICK #${tickCount}`);
});

eventBus.on('health:report', (e) => {
  const { status } = e.payload as { status: string };
  console.log(`💚 HEALTH: ${status}`);
});

eventBus.on('agent:started', (e) => {
  const { agentId } = e.payload as { agentId: string };
  console.log(`▶  STARTED ${agentId}`);
});

await clock.start();
await health.start();

console.log('\nRunning! Press Ctrl+C to stop.\n');

process.on('SIGINT', async () => {
  console.log('\nShutting down...');
  await clock.stop();
  await health.stop();
  console.log('Goodbye!');
  process.exit(0);
});
