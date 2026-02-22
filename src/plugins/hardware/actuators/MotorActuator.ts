// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Motor Actuator
// DC motor and stepper motor control
// Supports: L298N, TB6612, A4988, DRV8825, TMC2209
// ═══════════════════════════════════════════════════════════════════════════════

import { ActuatorPlugin, ActuatorConfig, CommandResult } from '../_base/ActuatorPlugin';
import { SerialProtocol } from '../../protocols/SerialProtocol';
import { ActuatorCommand, ActuatorState } from '../_base/HardwareTypes';

// ─────────────────────────────────────────────────────────────────────────────
// Motor Configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface MotorConfig extends Omit<ActuatorConfig, 'actuatorType' | 'protocol'> {
  actuatorType: 'motor_dc' | 'motor_stepper';
  protocol: 'serial';
  
  // Serial to microcontroller
  port: string;
  baudRate?: number;
  
  // Motor identification
  motorId: number;             // Motor number on controller
  
  // Motor type specific
  motorType: 'dc' | 'stepper';
  
  // DC motor settings
  pwmFrequency?: number;       // PWM frequency in Hz
  
  // Stepper motor settings
  stepsPerRevolution?: number; // Steps per full rotation (typically 200 or 400)
  microstepping?: 1 | 2 | 4 | 8 | 16 | 32; // Microstepping divisor
  
  // Common settings
  invertDirection?: boolean;
  maxRPM?: number;
  acceleration?: number;       // Steps/s² or RPM/s
  
  // Position tracking (stepper only)
  hasEncoder?: boolean;
  encoderPPR?: number;         // Pulses per revolution
}

export interface MotorState extends ActuatorState {
  position?: number;           // Steps or encoder counts
  velocity?: number;           // Current speed
  targetPosition?: number;
  targetVelocity?: number;
  isMoving?: boolean;
  direction?: 'forward' | 'reverse' | 'stopped';
}

// ─────────────────────────────────────────────────────────────────────────────
// Motor Actuator Implementation
// ─────────────────────────────────────────────────────────────────────────────

export class MotorActuator extends ActuatorPlugin<number> {
  private serial: SerialProtocol;
  private motorConfig: MotorConfig;
  
  // State tracking
  private position = 0;        // Steps or encoder counts
  private velocity = 0;        // Current velocity
  private targetPosition = 0;
  private targetVelocity = 0;
  private isMoving = false;
  private direction: 'forward' | 'reverse' | 'stopped' = 'stopped';

  constructor(config: Omit<MotorConfig, 'type' | 'actuatorType' | 'protocol'> & {
    type?: 'actuator';
    actuatorType?: 'motor_dc' | 'motor_stepper';
    protocol?: 'serial';
  }) {
    const actuatorType = config.motorType === 'stepper' ? 'motor_stepper' : 'motor_dc';
    
    const fullConfig: MotorConfig = {
      ...config,
      type: 'actuator',
      actuatorType,
      protocol: 'serial',
      baudRate: config.baudRate ?? 115200,
      stepsPerRevolution: config.stepsPerRevolution ?? 200,
      microstepping: config.microstepping ?? 1,
      maxRPM: config.maxRPM ?? 300,
      acceleration: config.acceleration ?? 1000,
      requiresApproval: config.requiresApproval ?? true, // Motors can be dangerous
      safetyLimits: {
        maxSpeed: config.maxRPM ?? 300,
        maxAcceleration: config.acceleration ?? 1000,
        ...config.safetyLimits,
      },
      connection: {
        port: config.port,
        baudRate: config.baudRate ?? 115200,
      },
    };

    super(fullConfig);
    this.motorConfig = fullConfig;

    this.serial = new SerialProtocol({
      id: `${config.id}-serial`,
      type: 'serial',
      connection: {
        port: config.port,
        baudRate: config.baudRate ?? 115200,
      },
      parser: 'readline',
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // ActuatorPlugin Implementation
  // ─────────────────────────────────────────────────────────────────────────

  protected async connect(): Promise<void> {
    await this.serial.connect();
    
    this.serial.onMessage((message) => {
      this.handleSerialResponse(message.data.toString());
    });
    
    // Configure motor on controller
    await this.configureMotor();
    
    this.log('info', `Motor ${this.motorConfig.motorId} connected (${this.motorConfig.motorType})`);
  }

  protected async disconnect(): Promise<void> {
    // Stop motor before disconnect
    await this.stopMotor();
    await this.serial.disconnect();
  }

  protected async executeCommand(command: ActuatorCommand<number>): Promise<void> {
    switch (command.command) {
      case 'set_position':
        if (this.motorConfig.motorType !== 'stepper') {
          throw new Error('Position control only available for stepper motors');
        }
        await this.moveTo(command.value!, command.speed, command.acceleration);
        break;
        
      case 'move_relative':
        if (this.motorConfig.motorType !== 'stepper') {
          throw new Error('Position control only available for stepper motors');
        }
        await this.moveRelative(command.value!, command.speed, command.acceleration);
        break;
        
      case 'set_velocity':
        await this.setSpeed(command.value!);
        break;
        
      case 'home':
        await this.homeMotor();
        break;
        
      case 'stop':
        await this.stopMotor();
        break;
        
      case 'enable':
        await this.enableMotor();
        break;
        
      case 'disable':
        await this.disableMotor();
        break;
        
      default:
        throw new Error(`Unknown command: ${command.command}`);
    }
  }

  protected async readState(): Promise<MotorState> {
    // Request state from controller
    await this.serial.writeLine(`STATUS ${this.motorConfig.motorId}`);
    
    return {
      actuatorId: this.config.id,
      actuatorType: this.motorConfig.actuatorType,
      enabled: this.enabled,
      position: this.position,
      velocity: this.velocity,
      targetPosition: this.targetPosition,
      targetVelocity: this.targetVelocity,
      isMoving: this.isMoving,
      direction: this.direction,
      timestamp: Date.now(),
    };
  }

  protected async performEmergencyStop(): Promise<void> {
    // Immediate stop - no deceleration
    await this.serial.writeLine(`ESTOP ${this.motorConfig.motorId}`);
    this.isMoving = false;
    this.velocity = 0;
    this.direction = 'stopped';
  }

  protected async enableHardware(): Promise<void> {
    await this.enableMotor();
  }

  protected async disableHardware(): Promise<void> {
    await this.disableMotor();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Motor Configuration
  // ─────────────────────────────────────────────────────────────────────────

  private async configureMotor(): Promise<void> {
    const cfg = this.motorConfig;
    
    if (cfg.motorType === 'stepper') {
      // Configure stepper parameters
      await this.serial.writeLine(
        `CONFIG ${cfg.motorId} STEPPER ${cfg.stepsPerRevolution} ${cfg.microstepping}`
      );
      await this.serial.writeLine(
        `ACCEL ${cfg.motorId} ${cfg.acceleration}`
      );
      await this.serial.writeLine(
        `MAXSPEED ${cfg.motorId} ${this.rpmToStepsPerSecond(cfg.maxRPM!)}`
      );
    } else {
      // Configure DC motor parameters
      await this.serial.writeLine(
        `CONFIG ${cfg.motorId} DC ${cfg.pwmFrequency ?? 1000}`
      );
    }
    
    if (cfg.invertDirection) {
      await this.serial.writeLine(`INVERT ${cfg.motorId} 1`);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Motor Control
  // ─────────────────────────────────────────────────────────────────────────

  private async moveTo(position: number, speed?: number, acceleration?: number): Promise<void> {
    this.targetPosition = position;
    
    let cmd = `MOVETO ${this.motorConfig.motorId} ${position}`;
    
    if (speed) {
      cmd += ` ${this.rpmToStepsPerSecond(speed)}`;
    }
    if (acceleration) {
      cmd += ` ${acceleration}`;
    }
    
    await this.serial.writeLine(cmd);
    
    this.isMoving = true;
    this.direction = position > this.position ? 'forward' : 'reverse';
    
    this.log('debug', `Moving to position ${position}`);
  }

  private async moveRelative(steps: number, speed?: number, acceleration?: number): Promise<void> {
    await this.moveTo(this.position + steps, speed, acceleration);
  }

  private async setSpeed(speed: number): Promise<void> {
    // Speed in RPM (positive = forward, negative = reverse)
    this.targetVelocity = speed;
    
    if (this.motorConfig.motorType === 'dc') {
      // DC motor: speed is PWM duty cycle (-100 to +100)
      const pwm = Math.max(-100, Math.min(100, (speed / this.motorConfig.maxRPM!) * 100));
      await this.serial.writeLine(`PWM ${this.motorConfig.motorId} ${Math.round(pwm)}`);
    } else {
      // Stepper: continuous rotation at given speed
      const stepsPerSec = this.rpmToStepsPerSecond(Math.abs(speed));
      const direction = speed >= 0 ? 1 : -1;
      await this.serial.writeLine(`RUN ${this.motorConfig.motorId} ${stepsPerSec * direction}`);
    }
    
    this.velocity = speed;
    this.isMoving = speed !== 0;
    this.direction = speed > 0 ? 'forward' : speed < 0 ? 'reverse' : 'stopped';
    
    this.log('debug', `Speed set to ${speed} RPM`);
  }

  private async stopMotor(): Promise<void> {
    await this.serial.writeLine(`STOP ${this.motorConfig.motorId}`);
    this.isMoving = false;
    this.velocity = 0;
    this.targetVelocity = 0;
    this.direction = 'stopped';
    
    this.log('debug', 'Motor stopped');
  }

  private async enableMotor(): Promise<void> {
    await this.serial.writeLine(`ENABLE ${this.motorConfig.motorId}`);
    this.log('debug', 'Motor enabled');
  }

  private async disableMotor(): Promise<void> {
    await this.serial.writeLine(`DISABLE ${this.motorConfig.motorId}`);
    this.log('debug', 'Motor disabled');
  }

  private async homeMotor(): Promise<void> {
    // Home using endstop or stall detection
    await this.serial.writeLine(`HOME ${this.motorConfig.motorId}`);
    this.isMoving = true;
    this.direction = 'reverse'; // Usually home is in reverse direction
    
    this.log('info', 'Homing motor...');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Response Handling
  // ─────────────────────────────────────────────────────────────────────────

  private handleSerialResponse(response: string): void {
    const parts = response.trim().split(' ');
    
    if (parts[0] === 'POS' && parseInt(parts[1]) === this.motorConfig.motorId) {
      // Position update: "POS <id> <position>"
      this.position = parseInt(parts[2]);
    } else if (parts[0] === 'VEL' && parseInt(parts[1]) === this.motorConfig.motorId) {
      // Velocity update: "VEL <id> <velocity>"
      this.velocity = this.stepsPerSecondToRPM(parseInt(parts[2]));
    } else if (parts[0] === 'DONE' && parseInt(parts[1]) === this.motorConfig.motorId) {
      // Move complete
      this.isMoving = false;
      this.direction = 'stopped';
      this.position = this.targetPosition;
      this.emit('move_complete', { position: this.position });
    } else if (parts[0] === 'HOME' && parseInt(parts[1]) === this.motorConfig.motorId) {
      // Homing complete
      this.position = 0;
      this.isMoving = false;
      this.direction = 'stopped';
      this.emit('home_complete', {});
    } else if (parts[0] === 'STALL' && parseInt(parts[1]) === this.motorConfig.motorId) {
      // Stall detected
      this.isMoving = false;
      this.velocity = 0;
      this.log('warn', 'Motor stall detected');
      this.emit('stall', { position: this.position });
    } else if (parts[0] === 'ERR') {
      this.log('error', `Controller error: ${response}`);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Unit Conversion
  // ─────────────────────────────────────────────────────────────────────────

  private rpmToStepsPerSecond(rpm: number): number {
    const stepsPerRev = this.motorConfig.stepsPerRevolution! * this.motorConfig.microstepping!;
    return (rpm / 60) * stepsPerRev;
  }

  private stepsPerSecondToRPM(stepsPerSec: number): number {
    const stepsPerRev = this.motorConfig.stepsPerRevolution! * this.motorConfig.microstepping!;
    return (stepsPerSec / stepsPerRev) * 60;
  }

  stepsToRevolutions(steps: number): number {
    const stepsPerRev = this.motorConfig.stepsPerRevolution! * this.motorConfig.microstepping!;
    return steps / stepsPerRev;
  }

  revolutionsToSteps(revolutions: number): number {
    const stepsPerRev = this.motorConfig.stepsPerRevolution! * this.motorConfig.microstepping!;
    return revolutions * stepsPerRev;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public API Extensions
  // ─────────────────────────────────────────────────────────────────────────

  getPosition(): number {
    return this.position;
  }

  getVelocity(): number {
    return this.velocity;
  }

  isCurrentlyMoving(): boolean {
    return this.isMoving;
  }

  getDirection(): 'forward' | 'reverse' | 'stopped' {
    return this.direction;
  }

  async rotateRevolutions(revolutions: number, speed?: number): Promise<CommandResult> {
    const steps = this.revolutionsToSteps(revolutions);
    return this.command('move_relative', steps, { speed });
  }

  async setRPM(rpm: number): Promise<CommandResult> {
    return this.command('set_velocity', rpm);
  }
}
