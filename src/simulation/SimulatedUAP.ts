// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Simulated UAP (Unidentified Aerial Phenomenon)
// Autonomous flying craft for swarm coordination demos
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../core/event-bus/EventBus';

export interface Vector3 {
  x: number;
  y: number;
  z: number;
}

export interface UAPState {
  id: string;
  position: Vector3;
  velocity: Vector3;
  heading: number;          // Degrees, 0 = north
  altitude: number;         // Same as position.z but explicit
  speed: number;            // Magnitude of velocity
  energy: number;           // 0-100
  mode: 'idle' | 'patrol' | 'intercept' | 'evade' | 'formation' | 'returning';
  targetId?: string;        // What it's tracking
  formationSlot?: number;   // Position in formation
}

export interface UAPConfig {
  id: string;
  name?: string;
  startPosition: Vector3;
  maxSpeed?: number;
  maxAcceleration?: number;
  sensorRange?: number;
  energyDrain?: number;
}

export class SimulatedUAP {
  readonly id: string;
  readonly name: string;
  
  private state: UAPState;
  private maxSpeed: number;
  private maxAcceleration: number;
  private sensorRange: number;
  private energyDrain: number;
  
  private updateInterval: ReturnType<typeof setInterval> | null = null;
  private targetPosition: Vector3 | null = null;
  private formationCenter: Vector3 | null = null;
  private formationOffset: Vector3 = { x: 0, y: 0, z: 0 };

  constructor(config: UAPConfig) {
    this.id = config.id;
    this.name = config.name ?? `UAP-${config.id}`;
    this.maxSpeed = config.maxSpeed ?? 50;        // units/sec
    this.maxAcceleration = config.maxAcceleration ?? 20;
    this.sensorRange = config.sensorRange ?? 100;
    this.energyDrain = config.energyDrain ?? 0.1; // per second when active

    this.state = {
      id: this.id,
      position: { ...config.startPosition },
      velocity: { x: 0, y: 0, z: 0 },
      heading: 0,
      altitude: config.startPosition.z,
      speed: 0,
      energy: 100,
      mode: 'idle',
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────────

  start(): void {
    if (this.updateInterval) return;

    const tickRate = 50; // 20 Hz
    this.updateInterval = setInterval(() => this.update(tickRate / 1000), tickRate);
    
    eventBus.emit('uap:started', { id: this.id, state: this.getState() });
  }

  stop(): void {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
    
    this.state.mode = 'idle';
    this.state.velocity = { x: 0, y: 0, z: 0 };
    this.state.speed = 0;
    
    eventBus.emit('uap:stopped', { id: this.id });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Commands
  // ─────────────────────────────────────────────────────────────────────────────

  moveTo(target: Vector3): void {
    this.targetPosition = { ...target };
    this.state.mode = 'patrol';
    eventBus.emit('uap:command:moveto', { id: this.id, target });
  }

  patrol(waypoints: Vector3[]): void {
    if (waypoints.length === 0) return;
    this.targetPosition = waypoints[0];
    this.state.mode = 'patrol';
    eventBus.emit('uap:command:patrol', { id: this.id, waypoints });
  }

  intercept(targetId: string, targetPosition: Vector3): void {
    this.state.targetId = targetId;
    this.targetPosition = targetPosition;
    this.state.mode = 'intercept';
    eventBus.emit('uap:command:intercept', { id: this.id, targetId });
  }

  evade(threatPosition: Vector3): void {
    // Move away from threat
    const dx = this.state.position.x - threatPosition.x;
    const dy = this.state.position.y - threatPosition.y;
    const dz = this.state.position.z - threatPosition.z;
    const mag = Math.sqrt(dx*dx + dy*dy + dz*dz) || 1;
    
    this.targetPosition = {
      x: this.state.position.x + (dx / mag) * 50,
      y: this.state.position.y + (dy / mag) * 50,
      z: Math.max(10, this.state.position.z + (dz / mag) * 20),
    };
    this.state.mode = 'evade';
    eventBus.emit('uap:command:evade', { id: this.id, threatPosition });
  }

  joinFormation(center: Vector3, slot: number, offset: Vector3): void {
    this.formationCenter = center;
    this.formationOffset = offset;
    this.state.formationSlot = slot;
    this.state.mode = 'formation';
    eventBus.emit('uap:command:formation', { id: this.id, slot, center });
  }

  returnToBase(basePosition: Vector3): void {
    this.targetPosition = basePosition;
    this.state.mode = 'returning';
    eventBus.emit('uap:command:return', { id: this.id, basePosition });
  }

  hover(): void {
    this.targetPosition = null;
    this.state.mode = 'idle';
    this.state.velocity = { x: 0, y: 0, z: 0 };
    eventBus.emit('uap:command:hover', { id: this.id });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Update Loop
  // ─────────────────────────────────────────────────────────────────────────────

  private update(dt: number): void {
    // Check energy
    if (this.state.energy <= 0) {
      this.state.mode = 'idle';
      this.state.velocity = { x: 0, y: 0, z: 0 };
      this.state.speed = 0;
      eventBus.emit('uap:energy:depleted', { id: this.id });
      return;
    }

    // Determine target based on mode
    let target = this.targetPosition;
    
    if (this.state.mode === 'formation' && this.formationCenter) {
      target = {
        x: this.formationCenter.x + this.formationOffset.x,
        y: this.formationCenter.y + this.formationOffset.y,
        z: this.formationCenter.z + this.formationOffset.z,
      };
    }

    // Move towards target
    if (target) {
      this.moveTowardsTarget(target, dt);
    } else if (this.state.mode === 'idle') {
      // Hover - slowly reduce velocity
      this.state.velocity.x *= 0.95;
      this.state.velocity.y *= 0.95;
      this.state.velocity.z *= 0.95;
    }

    // Update position
    this.state.position.x += this.state.velocity.x * dt;
    this.state.position.y += this.state.velocity.y * dt;
    this.state.position.z += this.state.velocity.z * dt;

    // Keep above ground
    if (this.state.position.z < 5) {
      this.state.position.z = 5;
      this.state.velocity.z = Math.max(0, this.state.velocity.z);
    }

    // Update derived state
    this.state.altitude = this.state.position.z;
    this.state.speed = Math.sqrt(
      this.state.velocity.x ** 2 +
      this.state.velocity.y ** 2 +
      this.state.velocity.z ** 2
    );
    this.state.heading = Math.atan2(this.state.velocity.y, this.state.velocity.x) * 180 / Math.PI;

    // Drain energy when moving
    if (this.state.speed > 1) {
      this.state.energy -= this.energyDrain * dt * (this.state.speed / this.maxSpeed);
      this.state.energy = Math.max(0, this.state.energy);
    }

    // Emit position update (throttled)
    if (Math.random() < 0.2) { // ~4 Hz instead of 20 Hz
      eventBus.emit('uap:position', {
        id: this.id,
        position: { ...this.state.position },
        velocity: { ...this.state.velocity },
        heading: this.state.heading,
        altitude: this.state.altitude,
        speed: this.state.speed,
        mode: this.state.mode,
        energy: this.state.energy,
      });
    }
  }

  private moveTowardsTarget(target: Vector3, dt: number): void {
    const dx = target.x - this.state.position.x;
    const dy = target.y - this.state.position.y;
    const dz = target.z - this.state.position.z;
    const distance = Math.sqrt(dx*dx + dy*dy + dz*dz);

    // Arrived?
    if (distance < 2) {
      if (this.state.mode !== 'formation') {
        this.state.velocity = { x: 0, y: 0, z: 0 };
        this.state.mode = 'idle';
        this.targetPosition = null;
        eventBus.emit('uap:arrived', { id: this.id, position: { ...this.state.position } });
      }
      return;
    }

    // Calculate desired velocity
    const speedFactor = this.state.mode === 'evade' ? 1.2 : 
                        this.state.mode === 'intercept' ? 1.1 : 1.0;
    const desiredSpeed = Math.min(this.maxSpeed * speedFactor, distance * 2);
    
    const desiredVx = (dx / distance) * desiredSpeed;
    const desiredVy = (dy / distance) * desiredSpeed;
    const desiredVz = (dz / distance) * desiredSpeed;

    // Apply acceleration limits
    const accel = this.maxAcceleration * dt;
    this.state.velocity.x += this.clamp(desiredVx - this.state.velocity.x, -accel, accel);
    this.state.velocity.y += this.clamp(desiredVy - this.state.velocity.y, -accel, accel);
    this.state.velocity.z += this.clamp(desiredVz - this.state.velocity.z, -accel, accel);
  }

  private clamp(value: number, min: number, max: number): number {
    return Math.max(min, Math.min(max, value));
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Sensors
  // ─────────────────────────────────────────────────────────────────────────────

  scan(otherUAPs: SimulatedUAP[]): { id: string; distance: number; bearing: number }[] {
    const contacts: { id: string; distance: number; bearing: number }[] = [];

    for (const other of otherUAPs) {
      if (other.id === this.id) continue;

      const otherPos = other.getPosition();
      const dx = otherPos.x - this.state.position.x;
      const dy = otherPos.y - this.state.position.y;
      const dz = otherPos.z - this.state.position.z;
      const distance = Math.sqrt(dx*dx + dy*dy + dz*dz);

      if (distance <= this.sensorRange) {
        const bearing = Math.atan2(dy, dx) * 180 / Math.PI;
        contacts.push({ id: other.id, distance, bearing });
      }
    }

    if (contacts.length > 0) {
      eventBus.emit('uap:contacts', { id: this.id, contacts });
    }

    return contacts;
  }

  distanceTo(position: Vector3): number {
    const dx = position.x - this.state.position.x;
    const dy = position.y - this.state.position.y;
    const dz = position.z - this.state.position.z;
    return Math.sqrt(dx*dx + dy*dy + dz*dz);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // State
  // ─────────────────────────────────────────────────────────────────────────────

  getState(): UAPState {
    return { ...this.state };
  }

  getPosition(): Vector3 {
    return { ...this.state.position };
  }

  getVelocity(): Vector3 {
    return { ...this.state.velocity };
  }

  getEnergy(): number {
    return this.state.energy;
  }

  recharge(): void {
    this.state.energy = 100;
    eventBus.emit('uap:recharged', { id: this.id });
  }

  updateFormationCenter(center: Vector3): void {
    this.formationCenter = center;
  }
}
