#!/usr/bin/env npx tsx
// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - UAP Swarm Demo
// Control a fleet of autonomous UAPs
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus, agentRegistry } from '../src';
import { SimulatedUAP, UAPSwarmController } from '../src/simulation';

// Colors
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
  white: '\x1b[37m',
  bgBlack: '\x1b[40m',
};

console.clear();
console.log(`${c.cyan}${c.bold}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     EVERYTHINGOS - UAP SWARM SIMULATION                       ║
║                        Autonomous Fleet Control Demo                          ║
╚═══════════════════════════════════════════════════════════════════════════════╝
${c.reset}`);

// ─────────────────────────────────────────────────────────────────────────────
// Create Swarm
// ─────────────────────────────────────────────────────────────────────────────

const swarm = new UAPSwarmController({
  id: 'alpha',
  name: 'Alpha Squadron',
  basePosition: { x: 0, y: 0, z: 0 },
  formationSpacing: 20,
});

// Create 5 UAPs
const uapConfigs = [
  { id: 'uap-1', name: 'Phoenix', startPosition: { x: 0, y: 0, z: 50 } },
  { id: 'uap-2', name: 'Ghost', startPosition: { x: 20, y: 0, z: 50 } },
  { id: 'uap-3', name: 'Spectre', startPosition: { x: -20, y: 0, z: 50 } },
  { id: 'uap-4', name: 'Shadow', startPosition: { x: 10, y: 20, z: 50 } },
  { id: 'uap-5', name: 'Wraith', startPosition: { x: -10, y: 20, z: 50 } },
];

for (const cfg of uapConfigs) {
  const uap = new SimulatedUAP(cfg);
  swarm.addUAP(uap);
  console.log(`${c.green}✓${c.reset} Created ${c.cyan}${cfg.name}${c.reset} at (${cfg.startPosition.x}, ${cfg.startPosition.y}, ${cfg.startPosition.z})`);
}

console.log(`\n${c.green}✓${c.reset} Swarm "${c.yellow}${swarm.name}${c.reset}" ready with ${c.bold}${swarm.getAllUAPs().length}${c.reset} UAPs\n`);

// ─────────────────────────────────────────────────────────────────────────────
// ASCII Radar Display
// ─────────────────────────────────────────────────────────────────────────────

const RADAR_SIZE = 30;
const RADAR_SCALE = 5; // 1 char = 5 units

function renderRadar(): string {
  const grid: string[][] = [];
  const center = Math.floor(RADAR_SIZE / 2);
  
  // Initialize grid
  for (let y = 0; y < RADAR_SIZE; y++) {
    grid[y] = [];
    for (let x = 0; x < RADAR_SIZE; x++) {
      // Draw radar circles
      const dx = x - center;
      const dy = y - center;
      const dist = Math.sqrt(dx*dx + dy*dy);
      
      if (Math.abs(dist - center * 0.3) < 0.5 ||
          Math.abs(dist - center * 0.6) < 0.5 ||
          Math.abs(dist - center * 0.9) < 0.5) {
        grid[y][x] = `${c.dim}·${c.reset}`;
      } else if (x === center || y === center) {
        grid[y][x] = `${c.dim}+${c.reset}`;
      } else {
        grid[y][x] = ' ';
      }
    }
  }

  // Plot UAPs
  const symbols = ['◆', '◇', '●', '○', '■'];
  const colors = [c.cyan, c.green, c.yellow, c.magenta, c.blue];
  
  let i = 0;
  for (const uap of swarm.getAllUAPs()) {
    const pos = uap.getPosition();
    const rx = Math.round(pos.x / RADAR_SCALE) + center;
    const ry = center - Math.round(pos.y / RADAR_SCALE); // Flip Y
    
    if (rx >= 0 && rx < RADAR_SIZE && ry >= 0 && ry < RADAR_SIZE) {
      const symbol = symbols[i % symbols.length];
      const color = colors[i % colors.length];
      grid[ry][rx] = `${color}${symbol}${c.reset}`;
    }
    i++;
  }

  // Build output
  const border = '─'.repeat(RADAR_SIZE + 2);
  let output = `${c.dim}┌${border}┐${c.reset}\n`;
  for (const row of grid) {
    output += `${c.dim}│${c.reset} ${row.join('')} ${c.dim}│${c.reset}\n`;
  }
  output += `${c.dim}└${border}┘${c.reset}`;
  
  return output;
}

// ─────────────────────────────────────────────────────────────────────────────
// Status Display
// ─────────────────────────────────────────────────────────────────────────────

function showStatus(): void {
  console.clear();
  console.log(`${c.cyan}${c.bold}═══════════════════════════════════════════════════════════════════════════════${c.reset}`);
  console.log(`${c.cyan}${c.bold}                         UAP SWARM COMMAND CENTER                              ${c.reset}`);
  console.log(`${c.cyan}${c.bold}═══════════════════════════════════════════════════════════════════════════════${c.reset}\n`);

  // Radar
  console.log(renderRadar());
  
  // Swarm state
  const state = swarm.getState();
  console.log(`\n${c.bold}Swarm Status:${c.reset}`);
  console.log(`  Mode:       ${c.yellow}${state.mode.toUpperCase()}${c.reset}`);
  console.log(`  Formation:  ${c.cyan}${state.formation}${c.reset}`);
  console.log(`  Leader:     ${c.green}${state.leader || 'none'}${c.reset}`);
  console.log(`  Avg Energy: ${state.avgEnergy > 50 ? c.green : state.avgEnergy > 20 ? c.yellow : c.red}${state.avgEnergy.toFixed(0)}%${c.reset}`);
  
  // Individual UAPs
  console.log(`\n${c.bold}Fleet Status:${c.reset}`);
  for (const uap of swarm.getAllUAPs()) {
    const s = uap.getState();
    const energyColor = s.energy > 50 ? c.green : s.energy > 20 ? c.yellow : c.red;
    const modeColor = s.mode === 'formation' ? c.cyan : s.mode === 'patrol' ? c.magenta : c.white;
    console.log(`  ${c.bold}${s.id}${c.reset}: (${s.position.x.toFixed(0)}, ${s.position.y.toFixed(0)}, ${s.position.z.toFixed(0)}) | ${modeColor}${s.mode}${c.reset} | ${energyColor}${s.energy.toFixed(0)}%${c.reset} | ${s.speed.toFixed(1)} u/s`);
  }
  
  console.log(`\n${c.dim}─────────────────────────────────────────────────────────────────────────────────${c.reset}`);
  printCommands();
}

function printCommands(): void {
  console.log(`
${c.bold}Commands:${c.reset}
  ${c.cyan}1-5${c.reset}  Formations: ${c.dim}1${c.reset}=line ${c.dim}2${c.reset}=V ${c.dim}3${c.reset}=diamond ${c.dim}4${c.reset}=circle ${c.dim}5${c.reset}=sphere
  ${c.cyan}p${c.reset}    Start patrol (square pattern)
  ${c.cyan}s${c.reset}    Scatter (disperse swarm)
  ${c.cyan}c${c.reset}    Converge (reform formation)
  ${c.cyan}i${c.reset}    Intercept target at (100, 100, 50)
  ${c.cyan}b${c.reset}    Return to base
  ${c.cyan}h${c.reset}    Hover (all stop)
  ${c.cyan}r${c.reset}    Recharge all UAPs
  ${c.cyan}m${c.reset}    Refresh display
  ${c.cyan}q${c.reset}    Quit
`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Event Handlers
// ─────────────────────────────────────────────────────────────────────────────

eventBus.on('swarm:patrol:waypoint', (e) => {
  const { index, position } = e.payload as { index: number; position: { x: number; y: number; z: number } };
  console.log(`${c.magenta}📍 Waypoint ${index}${c.reset} → (${position.x}, ${position.y})`);
});

eventBus.on('swarm:formation:set', (e) => {
  const { formation } = e.payload as { formation: string };
  console.log(`${c.cyan}⬡ Formation:${c.reset} ${formation}`);
});

eventBus.on('swarm:energy:low', (e) => {
  const { avgEnergy } = e.payload as { avgEnergy: number };
  console.log(`${c.yellow}⚠️  Low energy warning: ${avgEnergy.toFixed(0)}%${c.reset}`);
});

eventBus.on('uap:arrived', (e) => {
  const { id } = e.payload as { id: string };
  console.log(`${c.green}✓ ${id} arrived${c.reset}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────────────────────────────────────

swarm.start();
showStatus();

// Auto-refresh display
const displayInterval = setInterval(() => {
  showStatus();
}, 2000);

// Input handling
if (process.stdin.isTTY) {
  process.stdin.setRawMode(true);
}
process.stdin.resume();
process.stdin.setEncoding('utf8');

process.stdin.on('data', async (key: string) => {
  switch (key) {
    case '1':
      swarm.setFormation('line');
      console.log(`${c.cyan}→ Line formation${c.reset}`);
      break;
    case '2':
      swarm.setFormation('v');
      console.log(`${c.cyan}→ V formation${c.reset}`);
      break;
    case '3':
      swarm.setFormation('diamond');
      console.log(`${c.cyan}→ Diamond formation${c.reset}`);
      break;
    case '4':
      swarm.setFormation('circle');
      console.log(`${c.cyan}→ Circle formation${c.reset}`);
      break;
    case '5':
      swarm.setFormation('sphere');
      console.log(`${c.cyan}→ Sphere formation${c.reset}`);
      break;
    case 'p':
      swarm.patrol([
        { x: 50, y: 50, z: 60 },
        { x: 50, y: -50, z: 60 },
        { x: -50, y: -50, z: 60 },
        { x: -50, y: 50, z: 60 },
      ]);
      console.log(`${c.magenta}🔄 Patrol started${c.reset}`);
      break;
    case 's':
      swarm.scatter();
      console.log(`${c.yellow}💥 Scatter!${c.reset}`);
      break;
    case 'c':
      swarm.setFormation(swarm.getState().formation);
      console.log(`${c.cyan}⬡ Converging...${c.reset}`);
      break;
    case 'i':
      swarm.intercept({ x: 100, y: 100, z: 50 });
      console.log(`${c.red}🎯 Intercepting target at (100, 100)${c.reset}`);
      break;
    case 'b':
      swarm.returnToBase();
      console.log(`${c.green}🏠 Returning to base${c.reset}`);
      break;
    case 'h':
      swarm.hoverAll();
      console.log(`${c.yellow}■ All hover${c.reset}`);
      break;
    case 'r':
      swarm.rechargeAll();
      console.log(`${c.green}🔋 All UAPs recharged${c.reset}`);
      break;
    case 'm':
      showStatus();
      break;
    case 'q':
    case '\u0003':
      clearInterval(displayInterval);
      swarm.stop();
      console.log(`\n${c.yellow}Swarm shutdown complete.${c.reset}`);
      console.log(`${c.green}Goodbye!${c.reset}\n`);
      process.exit(0);
  }
});

// Cleanup
process.on('SIGINT', () => {
  clearInterval(displayInterval);
  swarm.stop();
  process.exit(0);
});
