#!/usr/bin/env npx tsx
// EVERYTHINGOS - Robot Simulation Demo

import { eventBus, agentRegistry } from '../src';
import { SimulatedWorld, createDefaultWorld, SimulatedRobot, RobotAgent } from '../src/simulation';

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

console.log(`${c.cyan}${c.bold}
╔═══════════════════════════════════════════════════════════╗
║           EVERYTHINGOS - Robot Simulation                 ║
╚═══════════════════════════════════════════════════════════╝
${c.reset}`);

const world = createDefaultWorld();
console.log(`${c.green}✓${c.reset} World created (10x10)`);

const robot = new SimulatedRobot({
  id: 'bot-1',
  name: 'Explorer',
  startPosition: { x: 1, y: 1 },
  startHeading: 45,
}, world);
console.log(`${c.green}✓${c.reset} Robot created at (1, 1)`);

const agent = new RobotAgent({
  robot,
  avoidDanger: true,
  patrolPoints: [
    { x: 2, y: 2 },
    { x: 8, y: 2 },
    { x: 8, y: 7 },
    { x: 2, y: 7 },
  ],
});
agentRegistry.register(agent);

eventBus.on('robot:collision', (e) => {
  console.log(`${c.red}💥 COLLISION${c.reset}`);
});

eventBus.on('robot:goal:reached', () => {
  console.log(`${c.green}🎯 GOAL REACHED${c.reset}`);
});

await agent.start();

const printHelp = () => {
  console.log(`
${c.bold}Commands:${c.reset}
  ${c.cyan}w/a/s/d${c.reset} - Move
  ${c.cyan}x${c.reset} - Stop
  ${c.cyan}g${c.reset} - Go to goal
  ${c.cyan}p${c.reset} - Patrol
  ${c.cyan}m${c.reset} - Map
  ${c.cyan}i${c.reset} - Info
  ${c.cyan}q${c.reset} - Quit
`);
};

printHelp();

if (process.stdin.isTTY) {
  process.stdin.setRawMode(true);
}
process.stdin.resume();
process.stdin.setEncoding('utf8');

process.stdin.on('data', async (key: string) => {
  switch (key.toLowerCase()) {
    case 'w':
      eventBus.emit('robot:command:move', { direction: 'forward' });
      break;
    case 'a':
      eventBus.emit('robot:command:move', { direction: 'left' });
      break;
    case 's':
      eventBus.emit('robot:command:move', { direction: 'backward' });
      break;
    case 'd':
      eventBus.emit('robot:command:move', { direction: 'right' });
      break;
    case 'x':
      eventBus.emit('robot:command:move', { direction: 'stop' });
      break;
    case 'g':
      eventBus.emit('robot:command:goto', { position: { x: 9, y: 9 } });
      console.log(`${c.green}Going to goal${c.reset}`);
      break;
    case 'p':
      eventBus.emit('robot:command:patrol', {});
      console.log(`${c.magenta}Patrol started${c.reset}`);
      break;
    case 'm':
      console.log(world.render());
      break;
    case 'i':
      const state = robot.getState();
      console.log(`Pos: (${state.position.x.toFixed(1)}, ${state.position.y.toFixed(1)}) | Battery: ${state.battery.toFixed(0)}%`);
      break;
    case 'q':
    case '\u0003':
      await agent.stop();
      console.log(`${c.green}Goodbye!${c.reset}`);
      process.exit(0);
  }
});
