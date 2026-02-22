// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - WebSocket Protocol
// Real-time bidirectional communication
// Used for: streaming data, remote control, browser-based interfaces
// ═══════════════════════════════════════════════════════════════════════════════

import { ProtocolBase, ProtocolConfig, ProtocolMessage } from './ProtocolBase';
import { ConnectionConfig } from '../hardware/_base/HardwareTypes';

// ─────────────────────────────────────────────────────────────────────────────
// WebSocket Configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface WebSocketConfig extends ProtocolConfig {
  type: 'websocket';
  connection: WebSocketConnectionConfig;
  
  // Message handling
  messageFormat?: 'raw' | 'json' | 'msgpack';
  
  // Ping/pong
  pingInterval?: number;        // ms, 0 to disable
  pongTimeout?: number;         // ms
  
  // Compression
  perMessageDeflate?: boolean;
}

export interface WebSocketConnectionConfig extends ConnectionConfig {
  host: string;
  portNumber?: number;          // Default: 80 (ws) or 443 (wss)
  path?: string;                // Default: '/'
  protocol?: 'ws' | 'wss';
  
  // Headers
  headers?: Record<string, string>;
  
  // Subprotocols
  protocols?: string[];
}

export type WebSocketReadyState = 
  | 'CONNECTING'
  | 'OPEN'
  | 'CLOSING'
  | 'CLOSED';

// ─────────────────────────────────────────────────────────────────────────────
// WebSocket Protocol Implementation
// ─────────────────────────────────────────────────────────────────────────────

export class WebSocketProtocol extends ProtocolBase {
  protected wsConfig: WebSocketConfig;
  private socket: MockWebSocket | WebSocket | null = null;
  private pingTimer?: ReturnType<typeof setInterval>;
  private pongTimer?: ReturnType<typeof setTimeout>;
  private messageQueue: Array<Buffer | string> = [];

  constructor(config: Omit<WebSocketConfig, 'type'> & { type?: 'websocket' }) {
    const fullConfig: WebSocketConfig = {
      ...config,
      type: 'websocket',
      messageFormat: config.messageFormat ?? 'raw',
      pingInterval: config.pingInterval ?? 30000,
      pongTimeout: config.pongTimeout ?? 5000,
      connection: {
        portNumber: 80,
        path: '/',
        protocol: 'ws',
        ...config.connection,
      },
    };

    super(fullConfig);
    this.wsConfig = fullConfig;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Connection
  // ─────────────────────────────────────────────────────────────────────────

  protected async openConnection(): Promise<void> {
    const conn = this.wsConfig.connection;
    const url = this.buildUrl();
    
    this.log('info', `Connecting to WebSocket ${url}`);

    // Try native WebSocket first (browser or Node.js with ws package)
    if (typeof WebSocket !== 'undefined') {
      this.socket = new WebSocket(url, this.wsConfig.connection.protocols);
    } else {
      // Try Node.js ws package
      try {
        this.socket = await this.createNodeWebSocket(url);
      } catch (error) {
        this.log('warn', `Native WebSocket not available: ${error}. Using mock.`);
        this.socket = new MockWebSocket(url);
      }
    }

    // Wait for connection
    await this.waitForOpen();

    // Set up event handlers
    this.setupSocketHandlers();

    // Start ping interval
    if (this.wsConfig.pingInterval && this.wsConfig.pingInterval > 0) {
      this.startPingInterval();
    }
  }

  protected async closeConnection(): Promise<void> {
    this.stopPingInterval();
    
    if (this.socket) {
      if ('close' in this.socket) {
        this.socket.close(1000, 'Normal closure');
      }
      this.socket = null;
    }
  }

  protected isConnectionOpen(): boolean {
    if (!this.socket) return false;
    
    if ('readyState' in this.socket) {
      return this.socket.readyState === 1; // WebSocket.OPEN
    }
    
    return false;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Data Transfer
  // ─────────────────────────────────────────────────────────────────────────

  protected async writeRaw(data: Buffer | Uint8Array): Promise<number> {
    this.ensureConnected();
    if (!this.socket) throw new Error('Socket not open');

    this.socket.send(data);
    return data.length;
  }

  protected async readRaw(length: number): Promise<Buffer | Uint8Array> {
    // WebSocket uses event-based message handling
    // This method drains from the message queue
    
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Read timeout'));
      }, this.config.readTimeout);

      const checkQueue = () => {
        if (this.messageQueue.length > 0) {
          clearTimeout(timeout);
          const message = this.messageQueue.shift()!;
          const buffer = typeof message === 'string' 
            ? Buffer.from(message) 
            : message;
          resolve(buffer);
        } else {
          setTimeout(checkQueue, 10);
        }
      };

      checkQueue();
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // WebSocket-Specific Methods
  // ─────────────────────────────────────────────────────────────────────────

  /** Send a text message */
  async sendText(message: string): Promise<void> {
    this.ensureConnected();
    if (!this.socket) throw new Error('Socket not open');

    this.socket.send(message);
    
    this.stats.bytesWritten += message.length;
    this.stats.messagesWritten++;
    this.stats.lastActivity = Date.now();

    this.log('debug', `Sent text: ${message.substring(0, 100)}...`);
  }

  /** Send a JSON message */
  async sendJSON(data: object): Promise<void> {
    await this.sendText(JSON.stringify(data));
  }

  /** Send binary data */
  async sendBinary(data: Buffer | Uint8Array | ArrayBuffer): Promise<void> {
    this.ensureConnected();
    if (!this.socket) throw new Error('Socket not open');

    this.socket.send(data);
    
    const length = data instanceof ArrayBuffer ? data.byteLength : data.length;
    this.stats.bytesWritten += length;
    this.stats.messagesWritten++;
    this.stats.lastActivity = Date.now();

    this.log('debug', `Sent binary: ${length} bytes`);
  }

  /** Get the current ready state */
  getReadyState(): WebSocketReadyState {
    if (!this.socket) return 'CLOSED';
    
    const states: WebSocketReadyState[] = ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'];
    const readyState = 'readyState' in this.socket ? this.socket.readyState : 3;
    return states[readyState] ?? 'CLOSED';
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Event Handlers
  // ─────────────────────────────────────────────────────────────────────────

  private setupSocketHandlers(): void {
    if (!this.socket) return;

    this.socket.onmessage = (event: MessageEvent | { data: unknown }) => {
      this.handleSocketMessage(event);
    };

    this.socket.onerror = (event: Event | { error?: Error }) => {
      const error = 'error' in event && event.error ? event.error : new Error('WebSocket error');
      this.handleError(error);
    };

    this.socket.onclose = (event: CloseEvent | { code?: number; reason?: string }) => {
      const code = 'code' in event ? event.code : 1000;
      const reason = 'reason' in event ? event.reason : 'Unknown';
      
      this.log('info', `WebSocket closed: ${code} - ${reason}`);
      
      if (this.status === 'connected') {
        this.handleConnectionError(new Error(`Connection closed: ${reason}`));
      }
    };
  }

  private handleSocketMessage(event: MessageEvent | { data: unknown }): void {
    const data = event.data;
    
    let buffer: Buffer;
    let stringData: string | undefined;

    if (typeof data === 'string') {
      buffer = Buffer.from(data);
      stringData = data;
    } else if (data instanceof ArrayBuffer) {
      buffer = Buffer.from(data);
    } else if (data instanceof Blob) {
      // Handle Blob asynchronously
      data.arrayBuffer().then(ab => {
        this.handleSocketMessage({ data: ab });
      });
      return;
    } else if (Buffer.isBuffer(data)) {
      buffer = data;
    } else {
      this.log('warn', `Unknown message type: ${typeof data}`);
      return;
    }

    this.stats.bytesRead += buffer.length;
    this.stats.messagesRead++;
    this.stats.lastActivity = Date.now();

    // Reset pong timer if we're using ping/pong
    if (this.pongTimer) {
      clearTimeout(this.pongTimer);
      this.pongTimer = undefined;
    }

    // Parse based on message format
    let parsed: unknown = buffer;
    
    if (this.wsConfig.messageFormat === 'json' && stringData) {
      try {
        parsed = JSON.parse(stringData);
      } catch (error) {
        this.log('warn', `Failed to parse JSON: ${error}`);
      }
    }

    // Add to queue for readRaw()
    this.messageQueue.push(buffer);

    // Emit to handlers
    const message: ProtocolMessage = {
      data: buffer,
      timestamp: Date.now(),
      metadata: { parsed },
    };

    this.handleIncomingData(buffer);
    this.emit('message', { data: stringData ?? buffer, parsed });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Ping/Pong
  // ─────────────────────────────────────────────────────────────────────────

  private startPingInterval(): void {
    this.pingTimer = setInterval(() => {
      if (!this.isConnectionOpen()) return;

      // Send ping
      try {
        // Standard WebSocket ping (if available)
        if (this.socket && 'ping' in this.socket && typeof this.socket.ping === 'function') {
          this.socket.ping();
        } else {
          // Fallback: send a text ping message
          this.sendText('ping');
        }

        // Set pong timeout
        this.pongTimer = setTimeout(() => {
          this.log('warn', 'Pong timeout - connection may be dead');
          this.handleConnectionError(new Error('Pong timeout'));
        }, this.wsConfig.pongTimeout);

      } catch (error) {
        this.log('error', `Ping failed: ${error}`);
      }
    }, this.wsConfig.pingInterval);
  }

  private stopPingInterval(): void {
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = undefined;
    }
    if (this.pongTimer) {
      clearTimeout(this.pongTimer);
      this.pongTimer = undefined;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────────────────

  private buildUrl(): string {
    const conn = this.wsConfig.connection;
    const protocol = conn.protocol ?? 'ws';
    const port = conn.portNumber ?? (protocol === 'wss' ? 443 : 80);
    const path = conn.path ?? '/';
    
    return `${protocol}://${conn.host}:${port}${path}`;
  }

  private waitForOpen(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.socket) {
        reject(new Error('Socket not created'));
        return;
      }

      const timeout = setTimeout(() => {
        reject(new Error('Connection timeout'));
      }, this.config.connectTimeout);

      if ('readyState' in this.socket && this.socket.readyState === 1) {
        clearTimeout(timeout);
        resolve();
        return;
      }

      this.socket.onopen = () => {
        clearTimeout(timeout);
        resolve();
      };

      const originalOnError = this.socket.onerror;
      this.socket.onerror = (event: Event) => {
        clearTimeout(timeout);
        reject(new Error('Connection failed'));
        if (originalOnError) {
          (originalOnError as (ev: Event) => void).call(this.socket, event);
        }
      };
    });
  }

  private async createNodeWebSocket(url: string): Promise<WebSocket> {
    // This would use the 'ws' npm package:
    //
    // const { WebSocket } = await import('ws');
    // return new WebSocket(url, {
    //   headers: this.wsConfig.connection.headers,
    //   perMessageDeflate: this.wsConfig.perMessageDeflate,
    // });

    throw new Error('Node.js WebSocket not implemented - install ws package');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock WebSocket (for testing/development without browser/ws)
// ─────────────────────────────────────────────────────────────────────────────

class MockWebSocket {
  readyState: number = 0; // CONNECTING
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror: ((event: { error?: Error }) => void) | null = null;
  onclose: ((event: { code: number; reason: string }) => void) | null = null;

  private url: string;
  private messageInterval?: ReturnType<typeof setInterval>;

  constructor(url: string) {
    this.url = url;
    
    // Simulate connection
    setTimeout(() => {
      this.readyState = 1; // OPEN
      console.log(`[MockWebSocket] Connected to ${url}`);
      this.onopen?.();
      
      // Start simulating incoming messages
      this.startMessageSimulation();
    }, 100);
  }

  send(data: string | Buffer | Uint8Array | ArrayBuffer): void {
    if (this.readyState !== 1) {
      throw new Error('WebSocket not open');
    }
    
    const str = typeof data === 'string' ? data : Buffer.from(data as Uint8Array).toString();
    console.log(`[MockWebSocket] Send: ${str.substring(0, 100)}`);
    
    // Echo back for testing
    setTimeout(() => {
      if (this.readyState === 1 && this.onmessage) {
        this.onmessage({ data: `echo: ${str}` });
      }
    }, 50);
  }

  close(code = 1000, reason = 'Normal closure'): void {
    this.stopMessageSimulation();
    this.readyState = 3; // CLOSED
    console.log(`[MockWebSocket] Closed: ${code} - ${reason}`);
    this.onclose?.({ code, reason });
  }

  private startMessageSimulation(): void {
    // Simulate periodic data for testing
    this.messageInterval = setInterval(() => {
      if (this.readyState !== 1 || !this.onmessage) return;

      const mockData = {
        type: 'sensor_data',
        value: Math.random() * 100,
        timestamp: Date.now(),
      };

      this.onmessage({ data: JSON.stringify(mockData) });
    }, 3000); // Every 3 seconds
  }

  private stopMessageSimulation(): void {
    if (this.messageInterval) {
      clearInterval(this.messageInterval);
      this.messageInterval = undefined;
    }
  }
}
