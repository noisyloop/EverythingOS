// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Actuator Plugin Base
// Base class for all actuator plugins
// Actuators are OUTPUT devices - they affect the physical world
// CRITICAL: All actuator commands go through safety checks and approval
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus, EventHandler } from '../../../core/event-bus/EventBus';
import { PluginConfig, PluginAction } from '../../../core/registry/PluginRegistry';
import {
  HardwareConfig,
  HardwareStatus,
  HardwareHealth,
  ActuatorType,
  ActuatorCommand,
  ActuatorCommandType,
  ActuatorState,
  SafetyLimits,
  SafetyViolation,
  CalibrationData,
} from './HardwareTypes';

// ─────────────────────────────────────────────────────────────────────────────
// Actuator Configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface ActuatorConfig extends HardwareConfig {
  type: 'actuator';
  actuatorType: ActuatorType;
  
  // Safety
  safetyLimits: SafetyLimits;  // Required for actuators
  requiresApproval?: boolean;   // Commands require human approval (default: true)
  emergencyStopPin?: number;   // Hardware E-stop pin
  
  // Motion parameters (for motion actuators)
  maxSpeed?: number;
  maxAcceleration?: number;
  defaultSpeed?: number;
  homePosition?: number;
  
  // State polling
  stateUpdateRate?: number;    // ms between state reads
  
  // Command queue
  queueCommands?: boolean;     // Queue or reject concurrent commands
  maxQueueSize?: number;
}

export interface CommandResult {
  success: boolean;
  commandId: string;
  actuatorId: string;
  command: ActuatorCommandType;
  startedAt: number;
  completedAt?: number;
  error?: string;
  finalState?: ActuatorState;
}

// ─────────────────────────────────────────────────────────────────────────────
// Actuator Plugin Base Class
// ─────────────────────────────────────────────────────────────────────────────

export abstract class ActuatorPlugin<TValue = number> {
  protected config: ActuatorConfig;
  protected status: HardwareStatus = 'disconnected';
  protected health: HardwareHealth;
  protected calibration?: CalibrationData;
  
  // State
  protected currentState: ActuatorState;
  protected enabled = false;
  protected emergencyStopped = false;
  protected stateTimer?: ReturnType<typeof setInterval>;
  
  // Command tracking
  protected currentCommand?: ActuatorCommand<TValue>;
  protected commandQueue: ActuatorCommand<TValue>[] = [];
  protected commandHistory: CommandResult[] = [];
  protected commandIdCounter = 0;
  
  // Stats
  protected commandCount = 0;
  protected errorCount = 0;
  protected connectedAt?: number;

  constructor(config: ActuatorConfig) {
    this.config = {
      requiresApproval: true,  // Default to requiring approval
      queueCommands: false,
      maxQueueSize: 10,
      stateUpdateRate: 100,
      ...config,
    };
    
    this.health = {
      status: 'disconnected',
      lastSeen: 0,
      errorCount: 0,
    };
    
    this.currentState = {
      actuatorId: config.id,
      actuatorType: config.actuatorType,
      enabled: false,
      timestamp: Date.now(),
    };

    // Listen for emergency stop
    eventBus.on('hardware:emergency_stop', () => this.emergencyStop());
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Abstract Methods - Implement in subclass
  // ─────────────────────────────────────────────────────────────────────────

  /** Connect to the hardware */
  protected abstract connect(): Promise<void>;

  /** Disconnect from the hardware */
  protected abstract disconnect(): Promise<void>;

  /** Execute a command on the actuator */
  protected abstract executeCommand(command: ActuatorCommand<TValue>): Promise<void>;

  /** Read current actuator state */
  protected abstract readState(): Promise<ActuatorState>;

  /** Perform emergency stop - MUST be as fast as possible */
  protected abstract performEmergencyStop(): Promise<void>;

  /** Enable the actuator */
  protected abstract enableHardware(): Promise<void>;

  /** Disable the actuator */
  protected abstract disableHardware(): Promise<void>;

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  async initialize(): Promise<void> {
    this.setStatus('connecting');
    
    try {
      await this.connectWithRetry();
      this.setStatus('initializing');
      
      // Read initial state
      this.currentState = await this.readState();
      
      // Start state polling
      if (this.config.stateUpdateRate && this.config.stateUpdateRate > 0) {
        this.startStatePolling();
      }
      
      this.connectedAt = Date.now();
      this.setStatus('ready');
      
      this.emit('connected', { config: this.config });
      this.log('info', 'Actuator initialized (DISABLED - call enable() to activate)');
      
    } catch (error) {
      this.handleError(error);
      throw error;
    }
  }

  async shutdown(): Promise<void> {
    this.stopStatePolling();
    
    // Disable before disconnect
    if (this.enabled) {
      try {
        await this.disable();
      } catch (error) {
        this.log('warn', `Error disabling during shutdown: ${error}`);
      }
    }
    
    try {
      await this.disconnect();
    } catch (error) {
      this.log('warn', `Error during disconnect: ${error}`);
    }
    
    this.setStatus('disconnected');
    this.emit('disconnected', { reason: 'shutdown' });
  }

  private async connectWithRetry(): Promise<void> {
    const maxAttempts = this.config.retryAttempts ?? 3;
    const retryDelay = this.config.retryDelay ?? 1000;
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        await this.connect();
        return;
      } catch (error) {
        if (attempt === maxAttempts) {
          throw error;
        }
        this.log('warn', `Connection attempt ${attempt} failed, retrying in ${retryDelay}ms`);
        await this.sleep(retryDelay);
      }
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Enable/Disable
  // ─────────────────────────────────────────────────────────────────────────

  async enable(): Promise<void> {
    if (this.emergencyStopped) {
      throw new Error('Cannot enable: emergency stop active. Call resetEmergencyStop() first.');
    }
    
    if (this.status !== 'ready') {
      throw new Error(`Cannot enable: actuator not ready (status: ${this.status})`);
    }

    await this.enableHardware();
    this.enabled = true;
    this.currentState.enabled = true;
    
    this.emit('enabled', {});
    this.log('info', 'Actuator ENABLED');
  }

  async disable(): Promise<void> {
    await this.disableHardware();
    this.enabled = false;
    this.currentState.enabled = false;
    
    this.emit('disabled', {});
    this.log('info', 'Actuator DISABLED');
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Commands
  // ─────────────────────────────────────────────────────────────────────────

  async command(
    commandType: ActuatorCommandType,
    value?: TValue,
    options?: Partial<Omit<ActuatorCommand<TValue>, 'actuatorId' | 'actuatorType' | 'command' | 'value'>>
  ): Promise<CommandResult> {
    const commandId = `cmd_${this.config.id}_${++this.commandIdCounter}`;
    
    const cmd: ActuatorCommand<TValue> = {
      actuatorId: this.config.id,
      actuatorType: this.config.actuatorType,
      command: commandType,
      value,
      ...options,
    };

    // Emergency stop check
    if (this.emergencyStopped && commandType !== 'emergency_stop') {
      return this.failCommand(commandId, cmd, 'Emergency stop active');
    }

    // Enable check (except for enable/disable commands)
    if (!this.enabled && !['enable', 'disable', 'emergency_stop'].includes(commandType)) {
      return this.failCommand(commandId, cmd, 'Actuator not enabled');
    }

    // Status check
    if (this.status !== 'ready' && this.status !== 'busy') {
      return this.failCommand(commandId, cmd, `Actuator not ready: ${this.status}`);
    }

    // Safety check
    const safetyError = this.checkCommandSafety(cmd);
    if (safetyError) {
      return this.failCommand(commandId, cmd, safetyError);
    }

    // Approval check
    if (this.config.requiresApproval && this.needsApproval(commandType)) {
      const approved = await this.requestApproval(cmd);
      if (!approved) {
        return this.failCommand(commandId, cmd, 'Command not approved');
      }
    }

    // Handle concurrent commands
    if (this.currentCommand) {
      if (this.config.queueCommands && this.commandQueue.length < (this.config.maxQueueSize ?? 10)) {
        this.commandQueue.push(cmd);
        this.log('info', `Command queued: ${commandType}`);
        // Return a pending result - actual execution happens later
        return {
          success: true,
          commandId,
          actuatorId: this.config.id,
          command: commandType,
          startedAt: Date.now(),
        };
      } else {
        return this.failCommand(commandId, cmd, 'Actuator busy');
      }
    }

    // Execute
    return this.executeCommandInternal(commandId, cmd);
  }

  private async executeCommandInternal(commandId: string, cmd: ActuatorCommand<TValue>): Promise<CommandResult> {
    const startedAt = Date.now();
    this.currentCommand = cmd;
    this.setStatus('busy');
    
    this.emit('command_sent', { commandId, command: cmd });

    try {
      await this.executeCommand(cmd);
      
      // Update state after command
      this.currentState = await this.readState();
      
      const result: CommandResult = {
        success: true,
        commandId,
        actuatorId: this.config.id,
        command: cmd.command,
        startedAt,
        completedAt: Date.now(),
        finalState: this.currentState,
      };
      
      this.commandCount++;
      this.recordCommand(result);
      
      this.emit('command_completed', result);
      
      return result;
      
    } catch (error) {
      return this.failCommand(commandId, cmd, error instanceof Error ? error.message : String(error), startedAt);
    } finally {
      this.currentCommand = undefined;
      this.setStatus('ready');
      
      // Process queue
      if (this.commandQueue.length > 0) {
        const nextCmd = this.commandQueue.shift()!;
        const nextId = `cmd_${this.config.id}_${++this.commandIdCounter}`;
        // Fire and forget - result goes to event
        this.executeCommandInternal(nextId, nextCmd);
      }
    }
  }

  private failCommand(
    commandId: string, 
    cmd: ActuatorCommand<TValue>, 
    error: string,
    startedAt = Date.now()
  ): CommandResult {
    const result: CommandResult = {
      success: false,
      commandId,
      actuatorId: this.config.id,
      command: cmd.command,
      startedAt,
      completedAt: Date.now(),
      error,
    };
    
    this.errorCount++;
    this.recordCommand(result);
    this.emit('command_failed', result);
    this.log('error', `Command failed: ${cmd.command} - ${error}`);
    
    return result;
  }

  private recordCommand(result: CommandResult): void {
    this.commandHistory.push(result);
    // Keep last 100
    if (this.commandHistory.length > 100) {
      this.commandHistory = this.commandHistory.slice(-50);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Safety
  // ─────────────────────────────────────────────────────────────────────────

  protected checkCommandSafety(cmd: ActuatorCommand<TValue>): string | null {
    const limits = this.config.safetyLimits;
    if (!limits) return null;

    // Check position limits
    if (typeof cmd.value === 'number') {
      if (limits.minPosition !== undefined && cmd.value < limits.minPosition) {
        this.emitSafetyViolation('minPosition', { min: limits.minPosition }, cmd.value);
        return `Position ${cmd.value} below minimum ${limits.minPosition}`;
      }
      if (limits.maxPosition !== undefined && cmd.value > limits.maxPosition) {
        this.emitSafetyViolation('maxPosition', { max: limits.maxPosition }, cmd.value);
        return `Position ${cmd.value} above maximum ${limits.maxPosition}`;
      }
    }

    // Check speed limits
    if (cmd.speed !== undefined) {
      if (limits.maxSpeed !== undefined && cmd.speed > limits.maxSpeed) {
        this.emitSafetyViolation('maxSpeed', { max: limits.maxSpeed }, cmd.speed);
        return `Speed ${cmd.speed} above maximum ${limits.maxSpeed}`;
      }
    }

    // Check acceleration limits
    if (cmd.acceleration !== undefined) {
      if (limits.maxAcceleration !== undefined && cmd.acceleration > limits.maxAcceleration) {
        this.emitSafetyViolation('maxAcceleration', { max: limits.maxAcceleration }, cmd.acceleration);
        return `Acceleration ${cmd.acceleration} above maximum ${limits.maxAcceleration}`;
      }
    }

    // Check force limits
    if (cmd.force !== undefined) {
      if (limits.maxForce !== undefined && cmd.force > limits.maxForce) {
        this.emitSafetyViolation('maxForce', { max: limits.maxForce }, cmd.force);
        return `Force ${cmd.force} above maximum ${limits.maxForce}`;
      }
    }

    return null; // No safety issues
  }

  protected emitSafetyViolation(
    limit: string, 
    expected: { min?: number; max?: number }, 
    actual: number
  ): void {
    const violation: SafetyViolation = {
      hardwareId: this.config.id,
      limit,
      expected,
      actual,
      timestamp: Date.now(),
      action: 'blocked',
    };
    
    this.emit('safety_violation', violation);
    eventBus.emit('hardware:safety:violation', violation);
    this.log('warn', `SAFETY VIOLATION: ${limit} - expected ${JSON.stringify(expected)}, got ${actual}`);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Emergency Stop
  // ─────────────────────────────────────────────────────────────────────────

  async emergencyStop(): Promise<void> {
    this.log('error', '🛑 EMERGENCY STOP TRIGGERED');
    this.emergencyStopped = true;
    
    // Clear command queue
    this.commandQueue = [];
    
    // Perform hardware-level stop
    try {
      await this.performEmergencyStop();
    } catch (error) {
      // Log but don't throw - e-stop must succeed
      this.log('error', `E-stop hardware error: ${error}`);
    }
    
    this.enabled = false;
    this.currentState.enabled = false;
    this.setStatus('error');
    
    this.emit('emergency_stop', { timestamp: Date.now() });
    eventBus.emit('hardware:emergency_stopped', { actuatorId: this.config.id });
  }

  async resetEmergencyStop(): Promise<void> {
    this.log('info', 'Emergency stop reset requested');
    this.emergencyStopped = false;
    this.setStatus('ready');
    this.emit('emergency_stop_reset', { timestamp: Date.now() });
  }

  isEmergencyStopped(): boolean {
    return this.emergencyStopped;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Approval
  // ─────────────────────────────────────────────────────────────────────────

  protected needsApproval(commandType: ActuatorCommandType): boolean {
    // These never need approval
    const noApprovalNeeded: ActuatorCommandType[] = ['stop', 'emergency_stop', 'disable'];
    return !noApprovalNeeded.includes(commandType);
  }

  protected async requestApproval(cmd: ActuatorCommand<TValue>): Promise<boolean> {
    return new Promise((resolve) => {
      const approvalId = `actuator_${this.config.id}_${Date.now()}`;
      
      // Emit approval request
      eventBus.emit('hardware:approval:request', {
        approvalId,
        type: 'actuator_command',
        actuatorId: this.config.id,
        command: cmd,
        timestamp: Date.now(),
      });

      // Listen for response
      const timeout = setTimeout(() => {
        cleanup();
        this.log('warn', `Approval timeout for ${cmd.command}`);
        resolve(false);
      }, 60000); // 1 minute timeout

      const handleApproval: EventHandler<{ approvalId: string; approved: boolean }> = (event) => {
        if (event.payload.approvalId === approvalId) {
          cleanup();
          resolve(event.payload.approved);
        }
      };

      const cleanup = () => {
        clearTimeout(timeout);
        eventBus.off('hardware:approval:response', handleApproval as EventHandler);
      };

      eventBus.on<{ approvalId: string; approved: boolean }>('hardware:approval:response', handleApproval);
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // State Polling
  // ─────────────────────────────────────────────────────────────────────────

  private startStatePolling(): void {
    if (this.stateTimer) return;
    
    this.stateTimer = setInterval(async () => {
      try {
        const newState = await this.readState();
        this.currentState = newState;
        this.health.lastSeen = Date.now();
      } catch (error) {
        this.log('warn', `State read error: ${error}`);
      }
    }, this.config.stateUpdateRate);
  }

  private stopStatePolling(): void {
    if (this.stateTimer) {
      clearInterval(this.stateTimer);
      this.stateTimer = undefined;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Status & Health
  // ─────────────────────────────────────────────────────────────────────────

  protected setStatus(status: HardwareStatus): void {
    const previous = this.status;
    this.status = status;
    this.health.status = status;
    
    if (previous !== status) {
      this.emit('status_changed', { previous, current: status });
    }
  }

  getStatus(): HardwareStatus {
    return this.status;
  }

  getState(): ActuatorState {
    return { ...this.currentState };
  }

  getHealth(): HardwareHealth {
    return {
      ...this.health,
      uptime: this.connectedAt ? Date.now() - this.connectedAt : undefined,
    };
  }

  getConfig(): ActuatorConfig {
    return { ...this.config };
  }

  getCommandHistory(): CommandResult[] {
    return [...this.commandHistory];
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Error Handling
  // ─────────────────────────────────────────────────────────────────────────

  protected handleError(error: unknown): void {
    this.errorCount++;
    this.health.errorCount++;
    this.health.lastError = error instanceof Error ? error.message : String(error);
    
    this.setStatus('error');
    this.emit('error', { error: this.health.lastError });
    this.log('error', `Actuator error: ${this.health.lastError}`);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────────────────

  protected emit(event: string, data: unknown): void {
    eventBus.emit(`actuator:${this.config.id}:${event}`, data);
    eventBus.emit(`actuator:${event}`, { actuatorId: this.config.id, ...data as object });
  }

  protected log(level: 'debug' | 'info' | 'warn' | 'error', message: string): void {
    eventBus.emit('hardware:log', {
      hardwareId: this.config.id,
      type: 'actuator',
      level,
      message,
      timestamp: Date.now(),
    });
  }

  protected sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Convenience Commands
  // ─────────────────────────────────────────────────────────────────────────

  async setPosition(position: TValue, speed?: number): Promise<CommandResult> {
    return this.command('set_position', position, { speed });
  }

  async setVelocity(velocity: TValue): Promise<CommandResult> {
    return this.command('set_velocity', velocity);
  }

  async home(): Promise<CommandResult> {
    return this.command('home');
  }

  async stop(): Promise<CommandResult> {
    return this.command('stop');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Plugin Interface
  // ─────────────────────────────────────────────────────────────────────────

  toPluginConfig(): PluginConfig {
    return {
      id: `actuator-${this.config.id}`,
      name: this.config.name,
      version: '1.0.0',
      description: `${this.config.actuatorType} actuator: ${this.config.name}`,
      actions: this.getPluginActions(),
      initialize: async () => this.initialize(),
      shutdown: async () => this.shutdown(),
    };
  }

  protected getPluginActions(): PluginAction[] {
    return [
      {
        name: 'enable',
        description: 'Enable the actuator',
        handler: async () => { await this.enable(); return { success: true }; },
        requiredPermissions: ['hardware'],
      },
      {
        name: 'disable',
        description: 'Disable the actuator',
        handler: async () => { await this.disable(); return { success: true }; },
        requiredPermissions: ['hardware'],
      },
      {
        name: 'command',
        description: 'Send command to actuator',
        handler: async (input) => {
          const { command, value, ...options } = input as { command: ActuatorCommandType; value?: TValue };
          return this.command(command, value, options);
        },
        requiredPermissions: ['hardware'],
      },
      {
        name: 'stop',
        description: 'Stop the actuator',
        handler: async () => this.stop(),
        requiredPermissions: ['hardware'],
      },
      {
        name: 'emergency_stop',
        description: 'Emergency stop',
        handler: async () => { await this.emergencyStop(); return { success: true }; },
      },
      {
        name: 'get_state',
        description: 'Get current actuator state',
        handler: async () => this.getState(),
      },
      {
        name: 'get_status',
        description: 'Get actuator status and health',
        handler: async () => ({ status: this.getStatus(), health: this.getHealth(), enabled: this.enabled }),
      },
    ];
  }
}
