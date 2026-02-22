// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Protocol Base
// Abstract base class for all communication protocols
// Protocols handle the low-level communication with hardware
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../core/event-bus/EventBus';
import { ConnectionConfig, ProtocolType } from '../hardware/_base/HardwareTypes';

// ─────────────────────────────────────────────────────────────────────────────
// Protocol Types
// ─────────────────────────────────────────────────────────────────────────────

export type ProtocolStatus = 
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'error'
  | 'reconnecting';

export interface ProtocolConfig {
  id: string;
  type: ProtocolType;
  connection: ConnectionConfig;
  
  // Timeouts
  connectTimeout?: number;      // ms
  readTimeout?: number;         // ms
  writeTimeout?: number;        // ms
  
  // Reconnection
  autoReconnect?: boolean;
  reconnectDelay?: number;      // ms
  maxReconnectAttempts?: number;
  
  // Buffering
  bufferSize?: number;          // bytes
  
  // Debug
  debug?: boolean;
}

export interface ProtocolStats {
  bytesRead: number;
  bytesWritten: number;
  messagesRead: number;
  messagesWritten: number;
  errors: number;
  reconnects: number;
  connectedAt?: number;
  lastActivity?: number;
}

export interface ProtocolMessage {
  data: Buffer | Uint8Array | string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol Base Class
// ─────────────────────────────────────────────────────────────────────────────

export abstract class ProtocolBase {
  protected config: ProtocolConfig;
  protected status: ProtocolStatus = 'disconnected';
  protected stats: ProtocolStats;
  
  // Reconnection state
  protected reconnectAttempts = 0;
  protected reconnectTimer?: ReturnType<typeof setTimeout>;
  
  // Message handlers
  protected messageHandlers: Array<(message: ProtocolMessage) => void> = [];
  protected errorHandlers: Array<(error: Error) => void> = [];

  constructor(config: ProtocolConfig) {
    this.config = {
      connectTimeout: 5000,
      readTimeout: 1000,
      writeTimeout: 1000,
      autoReconnect: true,
      reconnectDelay: 1000,
      maxReconnectAttempts: 5,
      bufferSize: 4096,
      debug: false,
      ...config,
    };

    this.stats = {
      bytesRead: 0,
      bytesWritten: 0,
      messagesRead: 0,
      messagesWritten: 0,
      errors: 0,
      reconnects: 0,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Abstract Methods - Implement in subclass
  // ─────────────────────────────────────────────────────────────────────────

  /** Open the connection */
  protected abstract openConnection(): Promise<void>;

  /** Close the connection */
  protected abstract closeConnection(): Promise<void>;

  /** Write raw data to the connection */
  protected abstract writeRaw(data: Buffer | Uint8Array): Promise<number>;

  /** Read raw data from the connection (if synchronous reading supported) */
  protected abstract readRaw(length: number): Promise<Buffer | Uint8Array>;

  /** Check if connection is actually open */
  protected abstract isConnectionOpen(): boolean;

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  async connect(): Promise<void> {
    if (this.status === 'connected') {
      this.log('debug', 'Already connected');
      return;
    }

    this.setStatus('connecting');
    this.reconnectAttempts = 0;

    try {
      await this.withTimeout(
        this.openConnection(),
        this.config.connectTimeout!,
        'Connection timeout'
      );

      this.stats.connectedAt = Date.now();
      this.stats.lastActivity = Date.now();
      this.setStatus('connected');
      
      this.emit('connected', { config: this.config });
      this.log('info', `Connected via ${this.config.type}`);

    } catch (error) {
      this.handleConnectionError(error);
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    this.cancelReconnect();

    if (this.status === 'disconnected') {
      return;
    }

    try {
      await this.closeConnection();
    } catch (error) {
      this.log('warn', `Error during disconnect: ${error}`);
    }

    this.setStatus('disconnected');
    this.emit('disconnected', { reason: 'manual' });
    this.log('info', 'Disconnected');
  }

  async reconnect(): Promise<void> {
    await this.disconnect();
    await this.connect();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Data Transfer
  // ─────────────────────────────────────────────────────────────────────────

  async write(data: Buffer | Uint8Array | string): Promise<number> {
    this.ensureConnected();

    const buffer = typeof data === 'string' 
      ? Buffer.from(data) 
      : data instanceof Uint8Array 
        ? Buffer.from(data) 
        : data;

    try {
      const bytesWritten = await this.withTimeout(
        this.writeRaw(buffer),
        this.config.writeTimeout!,
        'Write timeout'
      );

      this.stats.bytesWritten += bytesWritten;
      this.stats.messagesWritten++;
      this.stats.lastActivity = Date.now();

      this.log('debug', `Wrote ${bytesWritten} bytes`);
      this.emit('data_sent', { bytes: bytesWritten });

      return bytesWritten;

    } catch (error) {
      this.handleError(error);
      throw error;
    }
  }

  async read(length: number): Promise<Buffer | Uint8Array> {
    this.ensureConnected();

    try {
      const data = await this.withTimeout(
        this.readRaw(length),
        this.config.readTimeout!,
        'Read timeout'
      );

      this.stats.bytesRead += data.length;
      this.stats.messagesRead++;
      this.stats.lastActivity = Date.now();

      this.log('debug', `Read ${data.length} bytes`);

      return data;

    } catch (error) {
      this.handleError(error);
      throw error;
    }
  }

  async writeAndRead(
    data: Buffer | Uint8Array | string, 
    expectedLength: number,
    delay = 0
  ): Promise<Buffer | Uint8Array> {
    await this.write(data);
    
    if (delay > 0) {
      await this.sleep(delay);
    }
    
    return this.read(expectedLength);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Message Handling (for async data arrival)
  // ─────────────────────────────────────────────────────────────────────────

  onMessage(handler: (message: ProtocolMessage) => void): () => void {
    this.messageHandlers.push(handler);
    return () => {
      const index = this.messageHandlers.indexOf(handler);
      if (index > -1) {
        this.messageHandlers.splice(index, 1);
      }
    };
  }

  onError(handler: (error: Error) => void): () => void {
    this.errorHandlers.push(handler);
    return () => {
      const index = this.errorHandlers.indexOf(handler);
      if (index > -1) {
        this.errorHandlers.splice(index, 1);
      }
    };
  }

  /** Call this from subclass when data arrives asynchronously */
  protected handleIncomingData(data: Buffer | Uint8Array | string): void {
    this.stats.bytesRead += typeof data === 'string' ? data.length : data.length;
    this.stats.messagesRead++;
    this.stats.lastActivity = Date.now();

    const message: ProtocolMessage = {
      data: typeof data === 'string' ? data : Buffer.from(data),
      timestamp: Date.now(),
    };

    for (const handler of this.messageHandlers) {
      try {
        handler(message);
      } catch (error) {
        this.log('error', `Message handler error: ${error}`);
      }
    }

    this.emit('data_received', message);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Auto-Reconnection
  // ─────────────────────────────────────────────────────────────────────────

  protected handleConnectionError(error: unknown): void {
    this.stats.errors++;
    this.setStatus('error');
    
    const errorMessage = error instanceof Error ? error.message : String(error);
    this.log('error', `Connection error: ${errorMessage}`);
    this.emit('error', { error: errorMessage });

    // Notify error handlers
    for (const handler of this.errorHandlers) {
      try {
        handler(error instanceof Error ? error : new Error(errorMessage));
      } catch (e) {
        this.log('error', `Error handler error: ${e}`);
      }
    }

    // Attempt reconnection if enabled
    if (this.config.autoReconnect && this.reconnectAttempts < this.config.maxReconnectAttempts!) {
      this.scheduleReconnect();
    }
  }

  protected handleError(error: unknown): void {
    this.stats.errors++;
    const errorMessage = error instanceof Error ? error.message : String(error);
    this.log('error', `Protocol error: ${errorMessage}`);
    this.emit('error', { error: errorMessage });

    // Check if connection is still valid
    if (!this.isConnectionOpen()) {
      this.handleConnectionError(error);
    }
  }

  protected scheduleReconnect(): void {
    if (this.reconnectTimer) return;

    this.reconnectAttempts++;
    this.stats.reconnects++;
    this.setStatus('reconnecting');

    const delay = this.config.reconnectDelay! * Math.pow(2, this.reconnectAttempts - 1); // Exponential backoff
    
    this.log('info', `Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.config.maxReconnectAttempts})`);

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = undefined;
      
      try {
        await this.openConnection();
        this.stats.connectedAt = Date.now();
        this.setStatus('connected');
        this.reconnectAttempts = 0;
        this.emit('reconnected', { attempts: this.reconnectAttempts });
        this.log('info', 'Reconnected successfully');
      } catch (error) {
        this.handleConnectionError(error);
      }
    }, delay);
  }

  protected cancelReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Status & Stats
  // ─────────────────────────────────────────────────────────────────────────

  protected setStatus(status: ProtocolStatus): void {
    const previous = this.status;
    this.status = status;
    
    if (previous !== status) {
      this.emit('status_changed', { previous, current: status });
    }
  }

  getStatus(): ProtocolStatus {
    return this.status;
  }

  isConnected(): boolean {
    return this.status === 'connected' && this.isConnectionOpen();
  }

  getStats(): ProtocolStats {
    return { ...this.stats };
  }

  getConfig(): ProtocolConfig {
    return { ...this.config };
  }

  resetStats(): void {
    this.stats = {
      bytesRead: 0,
      bytesWritten: 0,
      messagesRead: 0,
      messagesWritten: 0,
      errors: 0,
      reconnects: 0,
      connectedAt: this.stats.connectedAt,
      lastActivity: this.stats.lastActivity,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────────────────

  protected ensureConnected(): void {
    if (!this.isConnected()) {
      throw new Error(`Protocol not connected (status: ${this.status})`);
    }
  }

  protected async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    errorMessage: string
  ): Promise<T> {
    return Promise.race([
      promise,
      new Promise<T>((_, reject) =>
        setTimeout(() => reject(new Error(errorMessage)), timeoutMs)
      ),
    ]);
  }

  protected emit(event: string, data: unknown): void {
    eventBus.emit(`protocol:${this.config.id}:${event}`, data);
    eventBus.emit(`protocol:${event}`, { protocolId: this.config.id, type: this.config.type, ...data as object });
  }

  protected log(level: 'debug' | 'info' | 'warn' | 'error', message: string): void {
    if (level === 'debug' && !this.config.debug) return;

    eventBus.emit('hardware:log', {
      hardwareId: this.config.id,
      type: 'protocol',
      protocol: this.config.type,
      level,
      message,
      timestamp: Date.now(),
    });

    if (this.config.debug) {
      console.log(`[${this.config.type}:${this.config.id}] ${level.toUpperCase()}: ${message}`);
    }
  }

  protected sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Static Helpers
  // ─────────────────────────────────────────────────────────────────────────

  static bufferToHex(buffer: Buffer | Uint8Array): string {
    return Array.from(buffer)
      .map(b => b.toString(16).padStart(2, '0'))
      .join(' ');
  }

  static hexToBuffer(hex: string): Buffer {
    const bytes = hex.split(/\s+/).map(h => parseInt(h, 16));
    return Buffer.from(bytes);
  }
}
