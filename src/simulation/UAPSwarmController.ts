// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - UAP Swarm Controller
// Coordinates multiple UAPs as an autonomous fleet
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../core/event-bus/EventBus';
import { SimulatedUAP, Vector3, UAPState } from './SimulatedUAP';

export type FormationType = 'line' | 'v' | 'diamond' | 'circle' | 'grid' | 'sphere';

export interface SwarmConfig {
  id: string;
  name?: string;
  basePosition?: Vector3;
  formationSpacing?: number;
}

export interface SwarmState {
  id: string;
  uapCount: number;
  formation: FormationType;
  center: Vector3;
  leader: string | null;
  mode: 'idle' | 'patrol' | 'intercept' | 'scatter' | 'formation';
  avgEnergy: number;
}

export class UAPSwarmController {
  readonly id: string;
  readonly name: string;
  
  private uaps: Map<string, SimulatedUAP> = new Map();
  private basePosition: Vector3;
  private formationSpacing: number;
  private currentFormation: FormationType = 'v';
  private leaderId: string | null = null;
  private swarmCenter: Vector3 = { x: 0, y: 0, z: 50 };
  private mode: 'idle' | 'patrol' | 'intercept' | 'scatter' | 'formation' = 'idle';
  
  private patrolWaypoints: Vector3[] = [];
  private currentWaypointIndex: number = 0;
  
  private updateInterval: ReturnType<typeof setInterval> | null = null;

  constructor(config: SwarmConfig) {
    this.id = config.id;
    this.name = config.name ?? `Swarm-${config.id}`;
    this.basePosition = config.basePosition ?? { x: 0, y: 0, z: 0 };
    this.formationSpacing = config.formationSpacing ?? 15;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // UAP Management
  // ─────────────────────────────────────────────────────────────────────────────

  addUAP(uap: SimulatedUAP): void {
    this.uaps.set(uap.id, uap);
    
    // First UAP becomes leader
    if (!this.leaderId) {
      this.leaderId = uap.id;
    }
    
    eventBus.emit('swarm:uap:added', { swarmId: this.id, uapId: uap.id, count: this.uaps.size });
  }

  removeUAP(uapId: string): void {
    this.uaps.delete(uapId);
    
    // Elect new leader if needed
    if (this.leaderId === uapId) {
      this.leaderId = this.uaps.size > 0 ? this.uaps.keys().next().value : null;
      if (this.leaderId) {
        eventBus.emit('swarm:leader:elected', { swarmId: this.id, leaderId: this.leaderId });
      }
    }
    
    eventBus.emit('swarm:uap:removed', { swarmId: this.id, uapId, count: this.uaps.size });
  }

  getUAP(id: string): SimulatedUAP | undefined {
    return this.uaps.get(id);
  }

  getAllUAPs(): SimulatedUAP[] {
    return Array.from(this.uaps.values());
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────────

  start(): void {
    // Start all UAPs
    for (const uap of this.uaps.values()) {
      uap.start();
    }

    // Start swarm coordination loop
    this.updateInterval = setInterval(() => this.update(), 200); // 5 Hz
    
    eventBus.emit('swarm:started', { id: this.id, count: this.uaps.size });
  }

  stop(): void {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }

    for (const uap of this.uaps.values()) {
      uap.stop();
    }
    
    eventBus.emit('swarm:stopped', { id: this.id });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Commands
  // ─────────────────────────────────────────────────────────────────────────────

  setFormation(type: FormationType): void {
    this.currentFormation = type;
    this.mode = 'formation';
    this.applyFormation();
    eventBus.emit('swarm:formation:set', { swarmId: this.id, formation: type });
  }

  moveTo(position: Vector3): void {
    this.swarmCenter = { ...position };
    this.mode = 'formation';
    this.applyFormation();
    eventBus.emit('swarm:moveto', { swarmId: this.id, position });
  }

  patrol(waypoints: Vector3[]): void {
    if (waypoints.length === 0) return;
    
    this.patrolWaypoints = waypoints;
    this.currentWaypointIndex = 0;
    this.mode = 'patrol';
    this.swarmCenter = waypoints[0];
    this.applyFormation();
    
    eventBus.emit('swarm:patrol:started', { swarmId: this.id, waypoints });
  }

  intercept(targetPosition: Vector3): void {
    this.mode = 'intercept';
    this.swarmCenter = targetPosition;
    
    // All UAPs converge on target
    for (const uap of this.uaps.values()) {
      uap.intercept('target', targetPosition);
    }
    
    eventBus.emit('swarm:intercept', { swarmId: this.id, targetPosition });
  }

  scatter(): void {
    this.mode = 'scatter';
    
    // Each UAP moves to a random position
    let i = 0;
    for (const uap of this.uaps.values()) {
      const angle = (i / this.uaps.size) * Math.PI * 2;
      const distance = 50 + Math.random() * 50;
      uap.moveTo({
        x: this.swarmCenter.x + Math.cos(angle) * distance,
        y: this.swarmCenter.y + Math.sin(angle) * distance,
        z: this.swarmCenter.z + (Math.random() - 0.5) * 30,
      });
      i++;
    }
    
    eventBus.emit('swarm:scatter', { swarmId: this.id });
  }

  returnToBase(): void {
    this.mode = 'formation';
    this.swarmCenter = { ...this.basePosition, z: 50 };
    this.setFormation('line');
    
    eventBus.emit('swarm:returning', { swarmId: this.id, basePosition: this.basePosition });
  }

  hoverAll(): void {
    this.mode = 'idle';
    for (const uap of this.uaps.values()) {
      uap.hover();
    }
    eventBus.emit('swarm:hover', { swarmId: this.id });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Formation Logic
  // ─────────────────────────────────────────────────────────────────────────────

  private applyFormation(): void {
    const positions = this.calculateFormationPositions();
    let i = 0;
    
    for (const uap of this.uaps.values()) {
      if (positions[i]) {
        uap.joinFormation(this.swarmCenter, i, positions[i]);
      }
      i++;
    }
  }

  private calculateFormationPositions(): Vector3[] {
    const count = this.uaps.size;
    const spacing = this.formationSpacing;
    const positions: Vector3[] = [];

    switch (this.currentFormation) {
      case 'line':
        for (let i = 0; i < count; i++) {
          positions.push({
            x: (i - (count - 1) / 2) * spacing,
            y: 0,
            z: 0,
          });
        }
        break;

      case 'v':
        for (let i = 0; i < count; i++) {
          const side = i % 2 === 0 ? 1 : -1;
          const row = Math.floor((i + 1) / 2);
          positions.push({
            x: row * spacing * side * 0.7,
            y: -row * spacing,
            z: 0,
          });
        }
        break;

      case 'diamond':
        const diamondOrder = [
          { x: 0, y: 1 },   // front
          { x: -1, y: 0 },  // left
          { x: 1, y: 0 },   // right
          { x: 0, y: -1 },  // back
          { x: 0, y: 0 },   // center
        ];
        for (let i = 0; i < count; i++) {
          const pos = diamondOrder[i % diamondOrder.length];
          const ring = Math.floor(i / diamondOrder.length);
          positions.push({
            x: pos.x * spacing * (1 + ring * 0.5),
            y: pos.y * spacing * (1 + ring * 0.5),
            z: ring * spacing * 0.3,
          });
        }
        break;

      case 'circle':
        for (let i = 0; i < count; i++) {
          const angle = (i / count) * Math.PI * 2;
          const radius = spacing * Math.max(1, count / 4);
          positions.push({
            x: Math.cos(angle) * radius,
            y: Math.sin(angle) * radius,
            z: 0,
          });
        }
        break;

      case 'grid':
        const cols = Math.ceil(Math.sqrt(count));
        for (let i = 0; i < count; i++) {
          const row = Math.floor(i / cols);
          const col = i % cols;
          positions.push({
            x: (col - (cols - 1) / 2) * spacing,
            y: (row - Math.floor(count / cols) / 2) * spacing,
            z: 0,
          });
        }
        break;

      case 'sphere':
        // Fibonacci sphere distribution
        const phi = Math.PI * (3 - Math.sqrt(5));
        const radius = spacing * Math.max(1, count / 3);
        for (let i = 0; i < count; i++) {
          const y = 1 - (i / (count - 1)) * 2;
          const r = Math.sqrt(1 - y * y);
          const theta = phi * i;
          positions.push({
            x: Math.cos(theta) * r * radius,
            y: y * radius,
            z: Math.sin(theta) * r * radius,
          });
        }
        break;
    }

    return positions;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Update Loop
  // ─────────────────────────────────────────────────────────────────────────────

  private update(): void {
    // Calculate swarm center (average position)
    let avgX = 0, avgY = 0, avgZ = 0;
    let avgEnergy = 0;
    
    for (const uap of this.uaps.values()) {
      const pos = uap.getPosition();
      avgX += pos.x;
      avgY += pos.y;
      avgZ += pos.z;
      avgEnergy += uap.getEnergy();
    }
    
    const count = this.uaps.size;
    if (count > 0) {
      const actualCenter = {
        x: avgX / count,
        y: avgY / count,
        z: avgZ / count,
      };
      avgEnergy = avgEnergy / count;
      
      // Emit swarm state
      eventBus.emit('swarm:state', {
        id: this.id,
        mode: this.mode,
        formation: this.currentFormation,
        center: actualCenter,
        targetCenter: this.swarmCenter,
        count,
        avgEnergy,
        leaderId: this.leaderId,
      });
    }

    // Handle patrol mode
    if (this.mode === 'patrol' && this.patrolWaypoints.length > 0) {
      const target = this.patrolWaypoints[this.currentWaypointIndex];
      const leader = this.leaderId ? this.uaps.get(this.leaderId) : null;
      
      if (leader) {
        const distance = leader.distanceTo(target);
        if (distance < 10) {
          // Move to next waypoint
          this.currentWaypointIndex = (this.currentWaypointIndex + 1) % this.patrolWaypoints.length;
          const nextTarget = this.patrolWaypoints[this.currentWaypointIndex];
          this.swarmCenter = nextTarget;
          this.applyFormation();
          
          eventBus.emit('swarm:patrol:waypoint', {
            swarmId: this.id,
            index: this.currentWaypointIndex,
            position: nextTarget,
          });
        }
      }
    }

    // Check for low energy and auto-return
    if (avgEnergy < 20 && this.mode !== 'idle') {
      eventBus.emit('swarm:energy:low', { swarmId: this.id, avgEnergy });
    }

    // Run sensor scans
    this.runSensorSweep();
  }

  private runSensorSweep(): void {
    const allUAPs = this.getAllUAPs();
    
    for (const uap of allUAPs) {
      uap.scan(allUAPs);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // State
  // ─────────────────────────────────────────────────────────────────────────────

  getState(): SwarmState {
    let avgEnergy = 0;
    for (const uap of this.uaps.values()) {
      avgEnergy += uap.getEnergy();
    }
    avgEnergy = this.uaps.size > 0 ? avgEnergy / this.uaps.size : 0;

    return {
      id: this.id,
      uapCount: this.uaps.size,
      formation: this.currentFormation,
      center: { ...this.swarmCenter },
      leader: this.leaderId,
      mode: this.mode,
      avgEnergy,
    };
  }

  getAllStates(): UAPState[] {
    return Array.from(this.uaps.values()).map(uap => uap.getState());
  }

  rechargeAll(): void {
    for (const uap of this.uaps.values()) {
      uap.recharge();
    }
    eventBus.emit('swarm:recharged', { swarmId: this.id });
  }
}
