// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Motion Controller
// Coordinated multi-actuator movement with trajectory planning
// Handles: Joint synchronization, path interpolation, velocity profiles
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../core/event-bus/EventBus';
import { ActuatorPlugin } from '../hardware/_base/ActuatorPlugin';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface Joint {
  id: string;
  actuator: ActuatorPlugin<number>;
  limits: { min: number; max: number };
  homePosition: number;
  currentPosition: number;
  maxVelocity: number;          // units/sec
  maxAcceleration: number;      // units/sec²
}

export interface JointState {
  positions: Map<string, number>;
  velocities: Map<string, number>;
  timestamp: number;
}

export interface Waypoint {
  positions: Record<string, number>;  // joint_id -> position
  duration?: number;                   // Time to reach this point (ms)
  velocityScale?: number;              // 0-1, scale max velocity
  blendRadius?: number;                // For smooth transitions
}

export interface Trajectory {
  id: string;
  waypoints: Waypoint[];
  totalDuration: number;
  loop: boolean;
}

export interface MotionProfile {
  type: 'trapezoidal' | 'scurve' | 'linear';
  maxVelocity: number;
  maxAcceleration: number;
  maxJerk?: number;              // For S-curve
}

type MotionState = 'idle' | 'moving' | 'paused' | 'error' | 'estopped';

// ─────────────────────────────────────────────────────────────────────────────
// Motion Controller Implementation
// ─────────────────────────────────────────────────────────────────────────────

export class MotionController {
  private joints: Map<string, Joint> = new Map();
  private state: MotionState = 'idle';
  private currentTrajectory?: Trajectory;
  private trajectoryProgress = 0;        // 0-1
  private motionProfile: MotionProfile;
  
  // Timing
  private motionTimer?: ReturnType<typeof setInterval>;
  private lastUpdateTime = 0;
  private readonly updateRate = 20;      // 50Hz update rate (ms)

  constructor(profile?: Partial<MotionProfile>) {
    this.motionProfile = {
      type: 'trapezoidal',
      maxVelocity: 100,
      maxAcceleration: 200,
      ...profile,
    };

    // Listen for emergency stop
    eventBus.on('hardware:emergency_stop', () => this.emergencyStop());
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Joint Management
  // ─────────────────────────────────────────────────────────────────────────

  addJoint(joint: Joint): void {
    this.joints.set(joint.id, joint);
    this.log('info', `Added joint: ${joint.id}`);
  }

  removeJoint(jointId: string): void {
    this.joints.delete(jointId);
  }

  getJoint(jointId: string): Joint | undefined {
    return this.joints.get(jointId);
  }

  getJointState(): JointState {
    const positions = new Map<string, number>();
    const velocities = new Map<string, number>();
    
    for (const [id, joint] of this.joints) {
      positions.set(id, joint.currentPosition);
      velocities.set(id, 0); // Would come from encoder feedback
    }
    
    return { positions, velocities, timestamp: Date.now() };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Single Joint Movement
  // ─────────────────────────────────────────────────────────────────────────

  async moveJoint(jointId: string, position: number, velocity?: number): Promise<void> {
    const joint = this.joints.get(jointId);
    if (!joint) throw new Error(`Unknown joint: ${jointId}`);
    
    // Clamp to limits
    position = Math.max(joint.limits.min, Math.min(joint.limits.max, position));
    
    // Calculate move
    const distance = Math.abs(position - joint.currentPosition);
    const moveVelocity = velocity ?? joint.maxVelocity;
    const duration = this.calculateMoveDuration(distance, moveVelocity, joint.maxAcceleration);
    
    this.state = 'moving';
    eventBus.emit('motion:joint:start', { jointId, target: position, duration });
    
    await joint.actuator.command('set_position', position, { speed: moveVelocity });
    joint.currentPosition = position;
    
    this.state = 'idle';
    eventBus.emit('motion:joint:complete', { jointId, position });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Coordinated Movement
  // ─────────────────────────────────────────────────────────────────────────

  async moveTo(positions: Record<string, number>, duration?: number): Promise<void> {
    if (this.state === 'estopped') {
      throw new Error('Cannot move: emergency stop active');
    }

    // Validate all joints exist and positions are within limits
    for (const [jointId, position] of Object.entries(positions)) {
      const joint = this.joints.get(jointId);
      if (!joint) throw new Error(`Unknown joint: ${jointId}`);
      if (position < joint.limits.min || position > joint.limits.max) {
        throw new Error(`Position ${position} out of limits for joint ${jointId}`);
      }
    }

    // Calculate synchronized move
    const moves = this.planSynchronizedMove(positions, duration);
    
    this.state = 'moving';
    eventBus.emit('motion:move:start', { positions, duration });

    // Execute all moves simultaneously
    const promises = moves.map(async (move) => {
      const joint = this.joints.get(move.jointId)!;
      await joint.actuator.command('set_position', move.target, { 
        speed: move.velocity,
        acceleration: move.acceleration,
      });
      joint.currentPosition = move.target;
    });

    await Promise.all(promises);
    
    this.state = 'idle';
    eventBus.emit('motion:move:complete', { positions });
  }

  private planSynchronizedMove(
    positions: Record<string, number>, 
    duration?: number
  ): Array<{ jointId: string; target: number; velocity: number; acceleration: number }> {
    const moves: Array<{ jointId: string; distance: number; target: number }> = [];
    
    // Calculate distances
    for (const [jointId, target] of Object.entries(positions)) {
      const joint = this.joints.get(jointId)!;
      const distance = Math.abs(target - joint.currentPosition);
      moves.push({ jointId, distance, target });
    }

    // Find the limiting joint (longest move)
    const maxDistance = Math.max(...moves.map(m => m.distance));
    
    // Calculate duration based on longest move if not specified
    if (!duration) {
      const limitingJoint = this.joints.get(
        moves.find(m => m.distance === maxDistance)!.jointId
      )!;
      duration = this.calculateMoveDuration(
        maxDistance, 
        limitingJoint.maxVelocity, 
        limitingJoint.maxAcceleration
      );
    }

    // Scale velocities so all joints arrive simultaneously
    return moves.map(move => {
      const joint = this.joints.get(move.jointId)!;
      const velocity = move.distance > 0 ? (move.distance / duration!) * 1000 : 0;
      
      return {
        jointId: move.jointId,
        target: move.target,
        velocity: Math.min(velocity, joint.maxVelocity),
        acceleration: joint.maxAcceleration,
      };
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Trajectory Execution
  // ─────────────────────────────────────────────────────────────────────────

  async executeTrajectory(trajectory: Trajectory): Promise<void> {
    if (this.state === 'estopped') {
      throw new Error('Cannot execute: emergency stop active');
    }

    if (trajectory.waypoints.length === 0) {
      throw new Error('Trajectory has no waypoints');
    }

    this.currentTrajectory = trajectory;
    this.trajectoryProgress = 0;
    this.state = 'moving';
    
    eventBus.emit('motion:trajectory:start', { id: trajectory.id });

    do {
      for (let i = 0; i < trajectory.waypoints.length; i++) {
        if (this.state !== 'moving') break;
        
        const waypoint = trajectory.waypoints[i];
        this.trajectoryProgress = i / trajectory.waypoints.length;
        
        eventBus.emit('motion:trajectory:waypoint', { 
          id: trajectory.id, 
          waypointIndex: i,
          progress: this.trajectoryProgress,
        });

        await this.moveTo(waypoint.positions, waypoint.duration);
        
        // Handle pause
        while ((this.state as MotionState) === 'paused') {
          await this.sleep(100);
        }
      }
    } while (trajectory.loop && this.state === 'moving');

    this.currentTrajectory = undefined;
    this.trajectoryProgress = 0;
    
    if (this.state === 'moving') {
      this.state = 'idle';
      eventBus.emit('motion:trajectory:complete', { id: trajectory.id });
    }
  }

  pauseTrajectory(): void {
    if (this.state === 'moving') {
      this.state = 'paused';
      eventBus.emit('motion:trajectory:paused', { id: this.currentTrajectory?.id });
    }
  }

  resumeTrajectory(): void {
    if (this.state === 'paused') {
      this.state = 'moving';
      eventBus.emit('motion:trajectory:resumed', { id: this.currentTrajectory?.id });
    }
  }

  cancelTrajectory(): void {
    if (this.currentTrajectory) {
      const id = this.currentTrajectory.id;
      this.currentTrajectory = undefined;
      this.state = 'idle';
      eventBus.emit('motion:trajectory:cancelled', { id });
    }
  }

  getTrajectoryProgress(): number {
    return this.trajectoryProgress;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Homing
  // ─────────────────────────────────────────────────────────────────────────

  async homeAll(): Promise<void> {
    this.log('info', 'Homing all joints...');
    
    const homePositions: Record<string, number> = {};
    for (const [id, joint] of this.joints) {
      homePositions[id] = joint.homePosition;
    }
    
    await this.moveTo(homePositions);
    this.log('info', 'Homing complete');
  }

  async homeJoint(jointId: string): Promise<void> {
    const joint = this.joints.get(jointId);
    if (!joint) throw new Error(`Unknown joint: ${jointId}`);
    
    await this.moveJoint(jointId, joint.homePosition);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Safety
  // ─────────────────────────────────────────────────────────────────────────

  async emergencyStop(): Promise<void> {
    this.state = 'estopped';
    this.currentTrajectory = undefined;
    
    this.log('error', 'EMERGENCY STOP');
    
    // Stop all joints immediately
    const stopPromises = Array.from(this.joints.values()).map(joint => 
      joint.actuator.emergencyStop().catch(e => 
        this.log('error', `Failed to stop ${joint.id}: ${e}`)
      )
    );
    
    await Promise.all(stopPromises);
    eventBus.emit('motion:emergency_stop', {});
  }

  async resetEmergencyStop(): Promise<void> {
    this.state = 'idle';
    
    // Reset all actuators
    for (const joint of this.joints.values()) {
      await joint.actuator.resetEmergencyStop();
    }
    
    this.log('info', 'Emergency stop reset');
    eventBus.emit('motion:emergency_stop_reset', {});
  }

  isEmergencyStopped(): boolean {
    return this.state === 'estopped';
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Motion Profile Calculations
  // ─────────────────────────────────────────────────────────────────────────

  private calculateMoveDuration(distance: number, maxVel: number, maxAccel: number): number {
    if (distance === 0) return 0;
    
    // Trapezoidal profile calculation
    // Time to accelerate to max velocity
    const accelTime = maxVel / maxAccel;
    const accelDistance = 0.5 * maxAccel * accelTime * accelTime;
    
    if (2 * accelDistance >= distance) {
      // Triangle profile (can't reach max velocity)
      return 2 * Math.sqrt(distance / maxAccel) * 1000;
    } else {
      // Trapezoidal profile
      const cruiseDistance = distance - 2 * accelDistance;
      const cruiseTime = cruiseDistance / maxVel;
      return (2 * accelTime + cruiseTime) * 1000;
    }
  }

  interpolatePosition(start: number, end: number, t: number): number {
    // t is 0-1 progress through move
    switch (this.motionProfile.type) {
      case 'linear':
        return start + (end - start) * t;
        
      case 'trapezoidal':
        return this.trapezoidalInterpolate(start, end, t);
        
      case 'scurve':
        return this.sCurveInterpolate(start, end, t);
        
      default:
        return start + (end - start) * t;
    }
  }

  private trapezoidalInterpolate(start: number, end: number, t: number): number {
    // Simplified trapezoidal velocity profile
    const accelPhase = 0.25;
    const decelPhase = 0.75;
    
    let s: number;
    if (t < accelPhase) {
      // Acceleration phase
      s = 2 * (t / accelPhase) ** 2 * accelPhase;
    } else if (t < decelPhase) {
      // Constant velocity phase
      s = accelPhase + (t - accelPhase) * 2;
    } else {
      // Deceleration phase
      const dt = (t - decelPhase) / (1 - decelPhase);
      s = decelPhase * 2 + (1 - (1 - dt) ** 2) * (1 - decelPhase) * 2;
    }
    
    // Normalize s to 0-1
    s = Math.min(1, s / 2);
    return start + (end - start) * s;
  }

  private sCurveInterpolate(start: number, end: number, t: number): number {
    // Smooth S-curve using sine function
    const s = (1 - Math.cos(t * Math.PI)) / 2;
    return start + (end - start) * s;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Status
  // ─────────────────────────────────────────────────────────────────────────

  getState(): MotionState {
    return this.state;
  }

  isMoving(): boolean {
    return this.state === 'moving';
  }

  getJoints(): Joint[] {
    return Array.from(this.joints.values());
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────────────────

  private log(level: 'debug' | 'info' | 'warn' | 'error', message: string): void {
    eventBus.emit('motion:log', { level, message, timestamp: Date.now() });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
