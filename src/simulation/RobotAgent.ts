// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Robot Agent
// An agent that controls a simulated (or real) robot
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent } from '../runtime/Agent';
import { eventBus } from '../core/event-bus/EventBus';
import { SimulatedRobot, MoveCommand, RobotState } from './SimulatedRobot';
import { Position } from './SimulatedWorld';

export interface RobotAgentConfig {
  robot: SimulatedRobot;
  patrolPoints?: Position[];
  avoidDanger?: boolean;
  tickRate?: number;
}

export class RobotAgent extends Agent {
  private robot: SimulatedRobot;
  private patrolPoints: Position[];
  private currentPatrolIndex: number = 0;
  private avoidDanger: boolean;
  private isPatrolling: boolean = false;

  constructor(config: RobotAgentConfig) {
    super({
      id: `robot-agent-${config.robot.id}`,
      name: `Robot Agent (${config.robot.name})`,
      type: 'execution',
      tickRate: config.tickRate ?? 500,
    });

    this.robot = config.robot;
    this.patrolPoints = config.patrolPoints ?? [];
    this.avoidDanger = config.avoidDanger ?? true;
  }

  protected async onStart(): Promise<void> {
    this.robot.start();

    this.subscribe('robot:collision', (e) => this.handleCollision(e.payload));
    this.subscribe('robot:danger:zone', (e) => this.handleDanger(e.payload));
    this.subscribe('robot:goal:reached', (e) => this.handleGoalReached(e.payload));
    this.subscribe('robot:command:move', (e) => this.handleMoveCommand(e.payload));
    this.subscribe('robot:command:goto', (e) => this.handleGotoCommand(e.payload));
    this.subscribe('robot:command:patrol', () => this.handlePatrolCommand());
    this.subscribe('robot:command:stop', () => this.stopAll());

    this.emit('robot:agent:ready', { robotId: this.robot.id });
  }

  protected async onStop(): Promise<void> {
    this.robot.stop();
    this.isPatrolling = false;
  }

  protected async onTick(): Promise<void> {
    const state = this.robot.getState();
    this.emit('robot:state', { robotId: this.robot.id, ...state });

    if (this.isPatrolling && state.status === 'idle' && this.patrolPoints.length > 0) {
      this.continuePatrol();
    }
  }

  private handleMoveCommand(payload: { direction: string }): void {
    const commands: Record<string, MoveCommand> = {
      forward: { type: 'forward' },
      backward: { type: 'backward' },
      left: { type: 'left' },
      right: { type: 'right' },
      stop: { type: 'stop' },
    };
    const command = commands[payload.direction];
    if (command) this.robot.execute(command);
  }

  private handleGotoCommand(payload: { position: Position }): void {
    this.isPatrolling = false;
    this.robot.execute({ type: 'goto', targetPosition: payload.position });
  }

  private handlePatrolCommand(): void {
    if (this.patrolPoints.length > 0) {
      this.isPatrolling = true;
      this.currentPatrolIndex = 0;
      this.continuePatrol();
    }
  }

  private stopAll(): void {
    this.isPatrolling = false;
    this.robot.execute({ type: 'stop' });
  }

  private handleCollision(payload: { id: string; reason: string }): void {
    if (payload.id !== this.robot.id) return;
    this.robot.execute({ type: 'backward' });
    setTimeout(() => this.robot.execute({ type: 'stop' }), 500);
  }

  private handleDanger(payload: { id: string }): void {
    if (payload.id !== this.robot.id || !this.avoidDanger) return;
    this.robot.execute({ type: 'backward' });
    setTimeout(() => this.robot.execute({ type: 'stop' }), 1000);
  }

  private handleGoalReached(payload: { id: string }): void {
    if (payload.id !== this.robot.id) return;
    this.emit('robot:mission:complete', { robotId: this.robot.id });
  }

  private continuePatrol(): void {
    if (this.patrolPoints.length === 0) return;
    const target = this.patrolPoints[this.currentPatrolIndex];
    this.robot.execute({ type: 'goto', targetPosition: target });
    this.currentPatrolIndex = (this.currentPatrolIndex + 1) % this.patrolPoints.length;
  }

  getRobotState(): RobotState {
    return this.robot.getState();
  }

  stopPatrol(): void {
    this.isPatrolling = false;
    this.robot.execute({ type: 'stop' });
  }
}
