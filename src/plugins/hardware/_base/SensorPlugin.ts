// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Sensor Plugin Base
// Base class for all sensor plugins
// Sensors are INPUT devices - they read data from the physical world
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../../core/event-bus/EventBus';
import { PluginConfig, PluginContext, PluginAction } from '../../../core/registry/PluginRegistry';
import {
  HardwareConfig,
  HardwareStatus,
  HardwareHealth,
  SensorType,
  SensorReading,
  SafetyLimits,
  SafetyViolation,
  CalibrationData,
} from './HardwareTypes';

// ─────────────────────────────────────────────────────────────────────────────
// Sensor Configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface SensorConfig extends HardwareConfig {
  type: 'sensor';
  sensorType: SensorType;
  
  // Polling
  pollRate: number;           // ms between reads
  bufferSize?: number;        // Number of readings to buffer
  
  // Filtering
  filter?: {
    type: 'none' | 'moving_average' | 'median' | 'kalman' | 'low_pass';
    windowSize?: number;
    alpha?: number;           // For low-pass filter
  };
  
  // Thresholds for event emission
  changeThreshold?: number;   // Only emit if value changed by this much
  eventOnEveryRead?: boolean; // Emit event on every read vs only on change
}

// ─────────────────────────────────────────────────────────────────────────────
// Sensor Plugin Base Class
// ─────────────────────────────────────────────────────────────────────────────

export abstract class SensorPlugin<T = unknown> {
  protected config: SensorConfig;
  protected status: HardwareStatus = 'disconnected';
  protected health: HardwareHealth;
  protected calibration?: CalibrationData;
  
  // Reading state
  protected lastReading?: SensorReading<T>;
  protected readingBuffer: SensorReading<T>[] = [];
  protected pollTimer?: ReturnType<typeof setInterval>;
  
  // Stats
  protected readCount = 0;
  protected errorCount = 0;
  protected connectedAt?: number;

  constructor(config: SensorConfig) {
    this.config = {
      bufferSize: 10,
      eventOnEveryRead: false,
      ...config,
    };
    
    this.health = {
      status: 'disconnected',
      lastSeen: 0,
      errorCount: 0,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Abstract Methods - Implement in subclass
  // ─────────────────────────────────────────────────────────────────────────

  /** Connect to the hardware */
  protected abstract connect(): Promise<void>;

  /** Disconnect from the hardware */
  protected abstract disconnect(): Promise<void>;

  /** Read raw data from the sensor */
  protected abstract readRaw(): Promise<T>;

  /** Validate the reading (optional override) */
  protected validateReading(data: T): boolean {
    return data !== null && data !== undefined;
  }

  /** Apply calibration to raw data (optional override) */
  protected applyCalibration(data: T): T {
    return data;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  async initialize(): Promise<void> {
    this.setStatus('connecting');
    
    try {
      await this.connectWithRetry();
      this.setStatus('initializing');
      
      // Run initial read to verify connection
      await this.read();
      
      this.connectedAt = Date.now();
      this.setStatus('ready');
      
      // Start polling if configured
      if (this.config.pollRate > 0) {
        this.startPolling();
      }
      
      this.emit('connected', { config: this.config });
      
    } catch (error) {
      this.handleError(error);
      throw error;
    }
  }

  async shutdown(): Promise<void> {
    this.stopPolling();
    
    try {
      await this.disconnect();
    } catch (error) {
      // Log but don't throw on shutdown
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
  // Reading
  // ─────────────────────────────────────────────────────────────────────────

  async read(): Promise<SensorReading<T>> {
    if (this.status !== 'ready' && this.status !== 'busy') {
      throw new Error(`Sensor not ready: ${this.status}`);
    }

    const previousStatus = this.status;
    this.setStatus('busy');

    try {
      // Read raw data
      let data = await this.readRaw() as T;
      
      // Validate
      if (!this.validateReading(data)) {
        throw new Error('Invalid sensor reading');
      }
      
      // Apply calibration
      if (this.calibration?.valid) {
        data = this.applyCalibration(data);
      }
      
      // Apply filter
      data = this.applyFilter(data);
      
      // Check safety limits
      this.checkSafetyLimits(data);
      
      // Create reading
      const reading: SensorReading<T> = {
        sensorId: this.config.id,
        sensorType: this.config.sensorType,
        timestamp: Date.now(),
        data,
      };
      
      // Buffer management
      this.readingBuffer.push(reading);
      if (this.readingBuffer.length > (this.config.bufferSize ?? 10)) {
        this.readingBuffer.shift();
      }
      
      // Update stats
      this.readCount++;
      this.health.lastSeen = Date.now();
      
      // Emit event if needed
      const shouldEmit = this.config.eventOnEveryRead || 
        this.hasSignificantChange(reading, this.lastReading);
      
      this.lastReading = reading;
      
      if (shouldEmit) {
        this.emit('data', reading);
      }
      
      return reading;
      
    } catch (error) {
      this.handleError(error);
      throw error;
    } finally {
      this.setStatus(previousStatus === 'busy' ? 'ready' : previousStatus);
    }
  }

  getLastReading(): SensorReading<T> | undefined {
    return this.lastReading;
  }

  getReadingBuffer(): SensorReading<T>[] {
    return [...this.readingBuffer];
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Polling
  // ─────────────────────────────────────────────────────────────────────────

  startPolling(): void {
    if (this.pollTimer) return;
    
    this.pollTimer = setInterval(async () => {
      try {
        await this.read();
      } catch (error) {
        // Error already handled in read()
      }
    }, this.config.pollRate);
    
    this.log('info', `Started polling at ${this.config.pollRate}ms intervals`);
  }

  stopPolling(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = undefined;
      this.log('info', 'Stopped polling');
    }
  }

  setPollRate(ms: number): void {
    this.config.pollRate = ms;
    if (this.pollTimer) {
      this.stopPolling();
      this.startPolling();
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Filtering
  // ─────────────────────────────────────────────────────────────────────────

  protected applyFilter(data: T): T {
    if (!this.config.filter || this.config.filter.type === 'none') {
      return data;
    }

    // For numeric data only
    if (typeof data !== 'number') {
      return data;
    }

    const values = this.readingBuffer
      .map(r => r.data as unknown as number)
      .slice(-(this.config.filter.windowSize ?? 5));
    
    values.push(data as unknown as number);

    switch (this.config.filter.type) {
      case 'moving_average':
        return (values.reduce((a, b) => a + b, 0) / values.length) as unknown as T;
      
      case 'median':
        const sorted = [...values].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);
        return (sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2) as unknown as T;
      
      case 'low_pass':
        const alpha = this.config.filter.alpha ?? 0.1;
        const prev = this.lastReading?.data as unknown as number ?? data as unknown as number;
        return (alpha * (data as unknown as number) + (1 - alpha) * prev) as unknown as T;
      
      default:
        return data;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Safety
  // ─────────────────────────────────────────────────────────────────────────

  protected checkSafetyLimits(data: T): void {
    if (!this.config.safetyLimits) return;
    
    // For numeric data, check against limits
    if (typeof data === 'number') {
      const limits = this.config.safetyLimits;
      
      // Temperature check (common for many sensors)
      if (limits.minTemperature !== undefined && data < limits.minTemperature) {
        this.emitSafetyViolation('minTemperature', { min: limits.minTemperature }, data);
      }
      if (limits.maxTemperature !== undefined && data > limits.maxTemperature) {
        this.emitSafetyViolation('maxTemperature', { max: limits.maxTemperature }, data);
      }
    }
    
    // Subclasses can override for specific checks
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
      action: 'warned',
    };
    
    this.emit('safety_violation', violation);
    eventBus.emit('hardware:safety:violation', violation);
    this.log('warn', `Safety violation: ${limit} - expected ${JSON.stringify(expected)}, got ${actual}`);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Calibration
  // ─────────────────────────────────────────────────────────────────────────

  setCalibration(calibration: CalibrationData): void {
    this.calibration = calibration;
    this.emit('calibration_updated', calibration);
  }

  getCalibration(): CalibrationData | undefined {
    return this.calibration;
  }

  needsCalibration(): boolean {
    if (!this.calibration) return true;
    if (!this.calibration.valid) return true;
    if (this.calibration.expiresAt && Date.now() > this.calibration.expiresAt) return true;
    return false;
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

  getHealth(): HardwareHealth {
    return {
      ...this.health,
      uptime: this.connectedAt ? Date.now() - this.connectedAt : undefined,
    };
  }

  getConfig(): SensorConfig {
    return { ...this.config };
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
    this.log('error', `Sensor error: ${this.health.lastError}`);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────────────────

  protected hasSignificantChange(current: SensorReading<T>, previous?: SensorReading<T>): boolean {
    if (!previous) return true;
    if (!this.config.changeThreshold) return true;
    
    // For numeric data
    if (typeof current.data === 'number' && typeof previous.data === 'number') {
      return Math.abs(current.data - previous.data) >= this.config.changeThreshold;
    }
    
    // For other data, always consider it changed
    return true;
  }

  protected emit(event: string, data: unknown): void {
    eventBus.emit(`sensor:${this.config.id}:${event}`, data);
    eventBus.emit(`sensor:${event}`, { sensorId: this.config.id, ...data as object });
  }

  protected log(level: 'debug' | 'info' | 'warn' | 'error', message: string): void {
    eventBus.emit('hardware:log', {
      hardwareId: this.config.id,
      type: 'sensor',
      level,
      message,
      timestamp: Date.now(),
    });
  }

  protected sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Plugin Interface
  // ─────────────────────────────────────────────────────────────────────────

  toPluginConfig(): PluginConfig {
    return {
      id: `sensor-${this.config.id}`,
      name: this.config.name,
      version: '1.0.0',
      description: `${this.config.sensorType} sensor: ${this.config.name}`,
      actions: this.getPluginActions(),
      initialize: async () => this.initialize(),
      shutdown: async () => this.shutdown(),
    };
  }

  protected getPluginActions(): PluginAction[] {
    return [
      {
        name: 'read',
        description: 'Read current sensor value',
        handler: async () => this.read(),
      },
      {
        name: 'get_last_reading',
        description: 'Get last sensor reading without new read',
        handler: async () => this.getLastReading(),
      },
      {
        name: 'get_buffer',
        description: 'Get buffered readings',
        handler: async () => this.getReadingBuffer(),
      },
      {
        name: 'get_status',
        description: 'Get sensor status',
        handler: async () => ({ status: this.getStatus(), health: this.getHealth() }),
      },
      {
        name: 'start_polling',
        description: 'Start automatic polling',
        handler: async () => { this.startPolling(); return { success: true }; },
      },
      {
        name: 'stop_polling',
        description: 'Stop automatic polling',
        handler: async () => { this.stopPolling(); return { success: true }; },
      },
    ];
  }
}
