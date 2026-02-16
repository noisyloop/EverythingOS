// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Simulated Robot
// A virtual robot for testing agent control without hardware
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../core/event-bus/EventBus';
import { SimulatedWorld, Position } from './SimulatedWorld';

export interface RobotState {
  position: Position;
  heading: number;
  velocity: number;
  angularVelocity: number;
  battery: number;
  status: 'idle' | 'moving' | 'rotating' | 'stopped' | 'error';
}

export interface RobotConfig {
  id: string;
  name: string;
  startPosition: Position;
  startHeading?: number;
  maxVelocity?: number;
  maxAngularVelocity?: number;
  batteryDrain?: number;
}

export interface MoveCommand {
  type: 'forward' | 'backward' | 'left' | 'right' | 'stop' | 'goto';
  value?: number;
  targetPosition?: Position;
}

export class SimulatedRobot {
  readonly id: string;
  readonly name: string;
  
  private state: RobotState;
  private world: SimulatedWorld;
  private maxVelocity: number;
  private maxAngularVelocity: number;
  private batteryDrain: number;
  
  private updateInterval: ReturnType<typeof setInterval> | null = null;
  private targetPosition: Position | null = null;

  constructor(config: RobotConfig, world: SimulatedWorld) {
    this.id = config.id;
    this.name = config.name;
    this.world = world;
    this.maxVelocity = config.maxVelocity ?? 2;
    this.maxAngularVelocity = config.maxAngularVelocity ?? 90;
    this.batteryDrain = config.batteryDrain ?? 0.5;

    this.state = {
      position: { ...config.startPosition },
      heading: config.startHeading ?? 0,
      velocity: 0,
      angularVelocity: 0,
      battery: 100,
      status: 'idle',
    };

    this.world.registerEntity(this.id, this.state.position);
  }

  start(): void {
    if (this.updateInterval) return;
    const tickRate = 100;
    this.updateInterval = setInterval(() => this.update(tickRate / 1000), tickRate);
    eventBus.emit('robot:started', { id: this.id, state: this.getState() });
  }

  stop(): void {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
    this.state.velocity = 0;
    this.state.angularVelocity = 0;
    this.state.status = 'stopped';
    eventBus.emit('robot:stopped', { id: this.id, state: this.getState() });
  }

  execute(command: MoveCommand): void {
    eventBus.emit('robot:command', { id: this.id, command });

    switch (command.type) {
      case 'forward':
        this.state.velocity = this.maxVelocity;
        this.state.angularVelocity = 0;
        this.state.status = 'moving';
        break;
      case 'backward':
        this.state.velocity = -this.maxVelocity * 0.5;
        this.state.angularVelocity = 0;
        this.state.status = 'moving';
        break;
      case 'left':
        this.state.angularVelocity = this.maxAngularVelocity;
        this.state.status = 'rotating';
        break;
      case 'right':
        this.state.angularVelocity = -this.maxAngularVelocity;
        this.state.status = 'rotating';
        break;
      case 'stop':
        this.state.velocity = 0;
        this.state.angularVelocity = 0;
        this.state.status = 'idle';
        this.targetPosition = null;
        break;
      case 'goto':
        if (command.targetPosition) {
          this.targetPosition = command.targetPosition;
          this.state.status = 'moving';
        }
        break;
    }
  }

  private update(dt: number): void {
    if (this.state.battery <= 0) {
      this.state.status = 'error';
      this.state.velocity = 0;
      this.state.angularVelocity = 0;
      eventBus.emit('robot:battery:depleted', { id: this.id });
      return;
    }

    if (this.targetPosition) {
      this.navigateToTarget(dt);
    }

    if (this.state.angularVelocity !== 0) {
      this.state.heading += this.state.angularVelocity * dt;
      this.state.heading = ((this.state.heading % 360) + 360) % 360;
    }

    if (this.state.velocity !== 0) {
      const radians = (this.state.heading * Math.PI) / 180;
      const newPosition = {
        x: this.state.position.x + Math.cos(radians) * this.state.velocity * dt,
        y: this.state.position.y + Math.sin(radians) * this.state.velocity * dt,
      };

      const result = this.world.updateEntityPosition(this.id, newPosition);
      
      if (result.allowed) {
        this.state.position = newPosition;
        this.state.battery -= this.batteryDrain * dt;
        this.state.battery = Math.max(0, this.state.battery);

        eventBus.emit('robot:position', {
          id: this.id,
          position: this.state.position,
          heading: this.state.heading,
          velocity: this.state.velocity,
        });

        if (result.zone?.type === 'goal') {
          eventBus.emit('robot:goal:reached', { id: this.id, zone: result.zone });
          this.execute({ type: 'stop' });
        }
      } else {
        this.state.velocity = 0;
        this.state.status = 'error';
        eventBus.emit('robot:collision', { id: this.id, reason: result.reason });
      }
    }
  }

  private navigateToTarget(dt: number): void {
    if (!this.targetPosition) return;

    const dx = this.targetPosition.x - this.state.position.x;
    const dy = this.targetPosition.y - this.state.position.y;
    const distance = Math.sqrt(dx * dx + dy * dy);

    if (distance < 0.2) {
      this.targetPosition = null;
      this.state.velocity = 0;
      this.state.angularVelocity = 0;
      this.state.status = 'idle';
      eventBus.emit('robot:navigation:complete', { id: this.id, position: this.state.position });
      return;
    }

    const targetHeading = (Math.atan2(dy, dx) * 180) / Math.PI;
    let headingDiff = targetHeading - this.state.heading;
    while (headingDiff > 180) headingDiff -= 360;
    while (headingDiff < -180) headingDiff += 360;

    if (Math.abs(headingDiff) > 5) {
      this.state.angularVelocity = Math.sign(headingDiff) * this.maxAngularVelocity;
      this.state.velocity = this.maxVelocity * 0.3;
    } else {
      this.state.angularVelocity = 0;
      this.state.velocity = this.maxVelocity;
    }
  }

  getDistanceToObstacle(): number {
    return this.world.distanceToNearestObstacle(this.state.position);
  }

  getState(): RobotState {
    return { ...this.state };
  }

  getPosition(): Position {
    return { ...this.state.position };
  }

  getBattery(): number {
    return this.state.battery;
  }

  recharge(): void {
    this.state.battery = 100;
    eventBus.emit('robot:recharged', { id: this.id });
  }
}
