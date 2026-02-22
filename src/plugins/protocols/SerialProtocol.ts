// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Serial Protocol
// USB/UART serial communication
// Most common protocol for Arduino, ESP32, STM32, etc.
// ═══════════════════════════════════════════════════════════════════════════════

import { ProtocolBase, ProtocolConfig, ProtocolStatus } from './ProtocolBase';
import { ConnectionConfig } from '../hardware/_base/HardwareTypes';

// ─────────────────────────────────────────────────────────────────────────────
// Serial Configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface SerialConfig extends ProtocolConfig {
  type: 'serial';
  connection: SerialConnectionConfig;
  
  // Line handling
  lineEnding?: '\n' | '\r' | '\r\n';
  
  // Parser mode
  parser?: 'raw' | 'readline' | 'delimiter' | 'length';
  delimiter?: string | number[];
  packetLength?: number;
}

export interface SerialConnectionConfig extends ConnectionConfig {
  port: string;                    // e.g., '/dev/ttyUSB0', 'COM3'
  baudRate: number;                // e.g., 9600, 115200
  dataBits?: 5 | 6 | 7 | 8;
  stopBits?: 1 | 2;
  parity?: 'none' | 'even' | 'odd';
  rtscts?: boolean;                // Hardware flow control
  xon?: boolean;                   // Software flow control
  xoff?: boolean;
  xany?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Serial Protocol Implementation
// ─────────────────────────────────────────────────────────────────────────────

export class SerialProtocol extends ProtocolBase {
  protected serialConfig: SerialConfig;
  
  // Native serial port (platform-specific)
  // In Node.js: serialport package
  // In browser: Web Serial API
  // For now: mock implementation
  private port: MockSerialPort | null = null;
  private readBuffer: Buffer = Buffer.alloc(0);

  constructor(config: Omit<SerialConfig, 'type'> & { type?: 'serial' }) {
    const fullConfig: SerialConfig = {
      ...config,
      type: 'serial',
      connection: {
        dataBits: 8,
        stopBits: 1,
        parity: 'none',
        rtscts: false,
        ...config.connection,
      },
      lineEnding: config.lineEnding ?? '\n',
      parser: config.parser ?? 'raw',
    };

    super(fullConfig);
    this.serialConfig = fullConfig;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Connection
  // ─────────────────────────────────────────────────────────────────────────

  protected async openConnection(): Promise<void> {
    const conn = this.serialConfig.connection;
    
    this.log('info', `Opening serial port ${conn.port} at ${conn.baudRate} baud`);

    // Check if we're in Node.js and serialport is available
    if (typeof process !== 'undefined' && process.versions?.node) {
      // Try to use native serialport
      try {
        this.port = await this.openNativeSerialPort();
      } catch (error) {
        this.log('warn', `Native serialport not available: ${error}. Using mock.`);
        this.port = new MockSerialPort(conn);
      }
    } else if (typeof navigator !== 'undefined' && 'serial' in navigator) {
      // Web Serial API
      this.port = await this.openWebSerialPort();
    } else {
      // Fallback to mock
      this.log('warn', 'No serial implementation available. Using mock.');
      this.port = new MockSerialPort(conn);
    }

    await this.port.open();
    
    // Set up data listener
    this.port.onData((data) => {
      this.handleSerialData(data);
    });

    this.port.onError((error) => {
      this.handleError(error);
    });

    this.port.onClose(() => {
      if (this.status === 'connected') {
        this.handleConnectionError(new Error('Port closed unexpectedly'));
      }
    });
  }

  protected async closeConnection(): Promise<void> {
    if (this.port) {
      await this.port.close();
      this.port = null;
    }
    this.readBuffer = Buffer.alloc(0);
  }

  protected isConnectionOpen(): boolean {
    return this.port?.isOpen() ?? false;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Data Transfer
  // ─────────────────────────────────────────────────────────────────────────

  protected async writeRaw(data: Buffer | Uint8Array): Promise<number> {
    if (!this.port) {
      throw new Error('Port not open');
    }
    return this.port.write(data);
  }

  protected async readRaw(length: number): Promise<Buffer | Uint8Array> {
    // For serial, we typically use async data arrival
    // This method pulls from the internal buffer
    
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Read timeout'));
      }, this.config.readTimeout);

      const checkBuffer = () => {
        if (this.readBuffer.length >= length) {
          clearTimeout(timeout);
          const data = this.readBuffer.subarray(0, length);
          this.readBuffer = this.readBuffer.subarray(length);
          resolve(data);
        } else {
          setTimeout(checkBuffer, 10);
        }
      };

      checkBuffer();
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Data Handling
  // ─────────────────────────────────────────────────────────────────────────

  private handleSerialData(data: Buffer): void {
    this.readBuffer = Buffer.concat([this.readBuffer, data]);

    switch (this.serialConfig.parser) {
      case 'readline':
        this.parseLines();
        break;
      case 'delimiter':
        this.parseDelimited();
        break;
      case 'length':
        this.parseFixedLength();
        break;
      case 'raw':
      default:
        // Emit raw data
        this.handleIncomingData(data);
        this.readBuffer = Buffer.alloc(0);
        break;
    }
  }

  private parseLines(): void {
    const ending = this.serialConfig.lineEnding ?? '\n';
    let index: number;

    while ((index = this.readBuffer.indexOf(ending)) !== -1) {
      const line = this.readBuffer.subarray(0, index).toString();
      this.readBuffer = this.readBuffer.subarray(index + ending.length);
      this.handleIncomingData(line);
    }
  }

  private parseDelimited(): void {
    const delimiter = this.serialConfig.delimiter;
    if (!delimiter) return;

    const delimBuffer = typeof delimiter === 'string' 
      ? Buffer.from(delimiter) 
      : Buffer.from(delimiter);

    let index: number;
    while ((index = this.readBuffer.indexOf(delimBuffer)) !== -1) {
      const packet = this.readBuffer.subarray(0, index);
      this.readBuffer = this.readBuffer.subarray(index + delimBuffer.length);
      this.handleIncomingData(packet);
    }
  }

  private parseFixedLength(): void {
    const length = this.serialConfig.packetLength;
    if (!length) return;

    while (this.readBuffer.length >= length) {
      const packet = this.readBuffer.subarray(0, length);
      this.readBuffer = this.readBuffer.subarray(length);
      this.handleIncomingData(packet);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Convenience Methods
  // ─────────────────────────────────────────────────────────────────────────

  async writeLine(line: string): Promise<number> {
    const data = line + (this.serialConfig.lineEnding ?? '\n');
    return this.write(data);
  }

  async writeCommand(command: string, waitForResponse = true, timeout = 1000): Promise<string | null> {
    await this.writeLine(command);

    if (!waitForResponse) {
      return null;
    }

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        cleanup();
        reject(new Error('Command timeout'));
      }, timeout);

      const handler = (message: { data: Buffer | string }) => {
        cleanup();
        resolve(typeof message.data === 'string' ? message.data : message.data.toString());
      };

      const cleanup = () => {
        clearTimeout(timeoutId);
        const index = this.messageHandlers.indexOf(handler as any);
        if (index > -1) this.messageHandlers.splice(index, 1);
      };

      this.messageHandlers.push(handler as any);
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Port Enumeration (static)
  // ─────────────────────────────────────────────────────────────────────────

  static async listPorts(): Promise<SerialPortInfo[]> {
    // In Node.js with serialport package:
    // const { SerialPort } = require('serialport');
    // return SerialPort.list();

    // In browser with Web Serial API:
    // return navigator.serial.getPorts();

    // Mock for now
    return [
      { path: '/dev/ttyUSB0', manufacturer: 'Mock', productId: '0001', vendorId: '0001' },
      { path: '/dev/ttyACM0', manufacturer: 'Arduino', productId: '0043', vendorId: '2341' },
      { path: 'COM3', manufacturer: 'Silicon Labs', productId: 'EA60', vendorId: '10C4' },
    ];
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Native Port Implementations (platform-specific)
  // ─────────────────────────────────────────────────────────────────────────

  private async openNativeSerialPort(): Promise<MockSerialPort> {
    // This would use the 'serialport' npm package in a real implementation:
    //
    // const { SerialPort } = await import('serialport');
    // return new SerialPort({
    //   path: this.serialConfig.connection.port,
    //   baudRate: this.serialConfig.connection.baudRate,
    //   dataBits: this.serialConfig.connection.dataBits,
    //   stopBits: this.serialConfig.connection.stopBits,
    //   parity: this.serialConfig.connection.parity,
    // });

    throw new Error('Native serialport not implemented - install serialport package');
  }

  private async openWebSerialPort(): Promise<MockSerialPort> {
    // This would use the Web Serial API in a browser:
    //
    // const port = await navigator.serial.requestPort();
    // await port.open({
    //   baudRate: this.serialConfig.connection.baudRate,
    //   dataBits: this.serialConfig.connection.dataBits,
    //   stopBits: this.serialConfig.connection.stopBits,
    //   parity: this.serialConfig.connection.parity,
    // });

    throw new Error('Web Serial API not available');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Serial Port Info
// ─────────────────────────────────────────────────────────────────────────────

export interface SerialPortInfo {
  path: string;
  manufacturer?: string;
  serialNumber?: string;
  pnpId?: string;
  locationId?: string;
  productId?: string;
  vendorId?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock Serial Port (for testing/development)
// ─────────────────────────────────────────────────────────────────────────────

class MockSerialPort {
  private config: SerialConnectionConfig;
  private opened = false;
  private dataHandlers: Array<(data: Buffer) => void> = [];
  private errorHandlers: Array<(error: Error) => void> = [];
  private closeHandlers: Array<() => void> = [];

  constructor(config: SerialConnectionConfig) {
    this.config = config;
  }

  async open(): Promise<void> {
    // Simulate connection delay
    await new Promise(resolve => setTimeout(resolve, 100));
    this.opened = true;
    console.log(`[MockSerial] Opened ${this.config.port} at ${this.config.baudRate} baud`);
  }

  async close(): Promise<void> {
    this.opened = false;
    this.closeHandlers.forEach(h => h());
    console.log(`[MockSerial] Closed ${this.config.port}`);
  }

  isOpen(): boolean {
    return this.opened;
  }

  async write(data: Buffer | Uint8Array): Promise<number> {
    if (!this.opened) throw new Error('Port not open');
    
    console.log(`[MockSerial] Write: ${data.toString()}`);
    
    // Simulate echo response for testing
    setTimeout(() => {
      if (this.opened) {
        const response = Buffer.from(`OK: ${data.toString().trim()}\n`);
        this.dataHandlers.forEach(h => h(response));
      }
    }, 50);

    return data.length;
  }

  onData(handler: (data: Buffer) => void): void {
    this.dataHandlers.push(handler);
  }

  onError(handler: (error: Error) => void): void {
    this.errorHandlers.push(handler);
  }

  onClose(handler: () => void): void {
    this.closeHandlers.push(handler);
  }
}
