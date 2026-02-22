// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - I2C Protocol
// I2C (Inter-Integrated Circuit) bus communication
// Common for sensors: accelerometers, gyroscopes, temperature, pressure, etc.
// ═══════════════════════════════════════════════════════════════════════════════

import { ProtocolBase, ProtocolConfig } from './ProtocolBase';
import { ConnectionConfig } from '../hardware/_base/HardwareTypes';

// ─────────────────────────────────────────────────────────────────────────────
// I2C Configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface I2CConfig extends ProtocolConfig {
  type: 'i2c';
  connection: I2CConnectionConfig;
}

export interface I2CConnectionConfig extends ConnectionConfig {
  bus: number;            // I2C bus number (e.g., 1 for /dev/i2c-1)
  address: number;        // Device address (7-bit, e.g., 0x68 for MPU6050)
}

// ─────────────────────────────────────────────────────────────────────────────
// I2C Protocol Implementation
// ─────────────────────────────────────────────────────────────────────────────

export class I2CProtocol extends ProtocolBase {
  protected i2cConfig: I2CConfig;
  private bus: MockI2CBus | null = null;

  constructor(config: Omit<I2CConfig, 'type'> & { type?: 'i2c' }) {
    const fullConfig: I2CConfig = {
      ...config,
      type: 'i2c',
    };

    super(fullConfig);
    this.i2cConfig = fullConfig;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Connection
  // ─────────────────────────────────────────────────────────────────────────

  protected async openConnection(): Promise<void> {
    const conn = this.i2cConfig.connection;
    
    this.log('info', `Opening I2C bus ${conn.bus}, address 0x${conn.address.toString(16)}`);

    // In a real implementation, this would use:
    // - Node.js: i2c-bus package
    // - Linux: /dev/i2c-N device files
    // - Raspberry Pi: pigpio or similar
    
    try {
      this.bus = await this.openNativeBus();
    } catch (error) {
      this.log('warn', `Native I2C not available: ${error}. Using mock.`);
      this.bus = new MockI2CBus(conn.bus, conn.address);
    }

    await this.bus.open();
  }

  protected async closeConnection(): Promise<void> {
    if (this.bus) {
      await this.bus.close();
      this.bus = null;
    }
  }

  protected isConnectionOpen(): boolean {
    return this.bus?.isOpen() ?? false;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Data Transfer
  // ─────────────────────────────────────────────────────────────────────────

  protected async writeRaw(data: Buffer | Uint8Array): Promise<number> {
    if (!this.bus) throw new Error('Bus not open');
    return this.bus.write(data);
  }

  protected async readRaw(length: number): Promise<Buffer | Uint8Array> {
    if (!this.bus) throw new Error('Bus not open');
    return this.bus.read(length);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // I2C-Specific Operations
  // ─────────────────────────────────────────────────────────────────────────

  /** Read a single byte from a register */
  async readByte(register: number): Promise<number> {
    if (!this.bus) throw new Error('Bus not open');
    
    this.stats.bytesWritten += 1;
    this.stats.bytesRead += 1;
    this.stats.messagesRead++;
    this.stats.lastActivity = Date.now();

    return this.bus.readByte(register);
  }

  /** Write a single byte to a register */
  async writeByte(register: number, value: number): Promise<void> {
    if (!this.bus) throw new Error('Bus not open');
    
    this.stats.bytesWritten += 2;
    this.stats.messagesWritten++;
    this.stats.lastActivity = Date.now();

    return this.bus.writeByte(register, value);
  }

  /** Read a word (2 bytes) from a register */
  async readWord(register: number, littleEndian = false): Promise<number> {
    if (!this.bus) throw new Error('Bus not open');
    
    this.stats.bytesWritten += 1;
    this.stats.bytesRead += 2;
    this.stats.messagesRead++;
    this.stats.lastActivity = Date.now();

    return this.bus.readWord(register, littleEndian);
  }

  /** Write a word (2 bytes) to a register */
  async writeWord(register: number, value: number, littleEndian = false): Promise<void> {
    if (!this.bus) throw new Error('Bus not open');
    
    this.stats.bytesWritten += 3;
    this.stats.messagesWritten++;
    this.stats.lastActivity = Date.now();

    return this.bus.writeWord(register, value, littleEndian);
  }

  /** Read multiple bytes starting from a register */
  async readBlock(register: number, length: number): Promise<Buffer> {
    if (!this.bus) throw new Error('Bus not open');
    
    this.stats.bytesWritten += 1;
    this.stats.bytesRead += length;
    this.stats.messagesRead++;
    this.stats.lastActivity = Date.now();

    return this.bus.readBlock(register, length);
  }

  /** Write multiple bytes starting at a register */
  async writeBlock(register: number, data: Buffer | number[]): Promise<void> {
    if (!this.bus) throw new Error('Bus not open');
    
    const buffer = Array.isArray(data) ? Buffer.from(data) : data;
    
    this.stats.bytesWritten += 1 + buffer.length;
    this.stats.messagesWritten++;
    this.stats.lastActivity = Date.now();

    return this.bus.writeBlock(register, buffer);
  }

  /** Read and modify specific bits in a register */
  async modifyBits(register: number, mask: number, value: number): Promise<void> {
    const current = await this.readByte(register);
    const newValue = (current & ~mask) | (value & mask);
    await this.writeByte(register, newValue);
  }

  /** Check if a bit is set in a register */
  async isBitSet(register: number, bit: number): Promise<boolean> {
    const value = await this.readByte(register);
    return (value & (1 << bit)) !== 0;
  }

  /** Set a bit in a register */
  async setBit(register: number, bit: number): Promise<void> {
    await this.modifyBits(register, 1 << bit, 1 << bit);
  }

  /** Clear a bit in a register */
  async clearBit(register: number, bit: number): Promise<void> {
    await this.modifyBits(register, 1 << bit, 0);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Device Detection
  // ─────────────────────────────────────────────────────────────────────────

  /** Scan for devices on the I2C bus */
  static async scan(busNumber: number): Promise<number[]> {
    const devices: number[] = [];
    
    // Scan addresses 0x03 to 0x77 (valid 7-bit I2C addresses)
    for (let address = 0x03; address <= 0x77; address++) {
      try {
        const bus = new MockI2CBus(busNumber, address);
        await bus.open();
        
        // Try to read a byte - if device exists, it won't throw
        await bus.read(1);
        devices.push(address);
        
        await bus.close();
      } catch {
        // No device at this address
      }
    }

    return devices;
  }

  /** Get human-readable name for common I2C addresses */
  static getDeviceName(address: number): string | null {
    const knownDevices: Record<number, string> = {
      0x1E: 'HMC5883L (Magnetometer)',
      0x20: 'PCF8574 (I/O Expander)',
      0x27: 'LCD (HD44780)',
      0x3C: 'SSD1306 (OLED Display)',
      0x3D: 'SSD1306 (OLED Display Alt)',
      0x40: 'INA219 (Power Monitor)',
      0x48: 'ADS1115 (ADC)',
      0x50: 'AT24C32 (EEPROM)',
      0x53: 'ADXL345 (Accelerometer)',
      0x57: 'DS3231 (RTC EEPROM)',
      0x68: 'MPU6050 / DS3231 (IMU/RTC)',
      0x69: 'MPU6050 Alt (IMU)',
      0x76: 'BME280/BMP280 (Environment)',
      0x77: 'BMP180/BME280 Alt (Pressure)',
    };

    return knownDevices[address] ?? null;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Native Implementation
  // ─────────────────────────────────────────────────────────────────────────

  private async openNativeBus(): Promise<MockI2CBus> {
    // This would use the 'i2c-bus' npm package:
    //
    // const i2c = await import('i2c-bus');
    // const bus = await i2c.openPromisified(this.i2cConfig.connection.bus);
    // return new NativeI2CBusWrapper(bus, this.i2cConfig.connection.address);

    throw new Error('Native I2C not implemented - install i2c-bus package');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock I2C Bus (for testing/development)
// ─────────────────────────────────────────────────────────────────────────────

class MockI2CBus {
  private busNumber: number;
  private address: number;
  private opened = false;
  private registers: Map<number, number> = new Map();

  constructor(busNumber: number, address: number) {
    this.busNumber = busNumber;
    this.address = address;
    
    // Initialize some mock registers
    this.initMockRegisters();
  }

  private initMockRegisters(): void {
    // Simulate MPU6050 registers for testing
    if (this.address === 0x68) {
      this.registers.set(0x75, 0x68);  // WHO_AM_I
      this.registers.set(0x6B, 0x40);  // PWR_MGMT_1 (sleep mode)
      this.registers.set(0x3B, 0x00);  // ACCEL_XOUT_H
      this.registers.set(0x3C, 0x00);  // ACCEL_XOUT_L
    }
    
    // Simulate BME280 registers
    if (this.address === 0x76 || this.address === 0x77) {
      this.registers.set(0xD0, 0x60);  // CHIP_ID (BME280)
      this.registers.set(0xF7, 0x80);  // PRESS_MSB
      this.registers.set(0xFA, 0x80);  // TEMP_MSB
    }
  }

  async open(): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, 10));
    this.opened = true;
    console.log(`[MockI2C] Opened bus ${this.busNumber}, address 0x${this.address.toString(16)}`);
  }

  async close(): Promise<void> {
    this.opened = false;
    console.log(`[MockI2C] Closed bus ${this.busNumber}`);
  }

  isOpen(): boolean {
    return this.opened;
  }

  async write(data: Buffer | Uint8Array): Promise<number> {
    if (!this.opened) throw new Error('Bus not open');
    console.log(`[MockI2C] Write: ${ProtocolBase.bufferToHex(Buffer.from(data))}`);
    return data.length;
  }

  async read(length: number): Promise<Buffer> {
    if (!this.opened) throw new Error('Bus not open');
    const data = Buffer.alloc(length);
    console.log(`[MockI2C] Read ${length} bytes`);
    return data;
  }

  async readByte(register: number): Promise<number> {
    if (!this.opened) throw new Error('Bus not open');
    const value = this.registers.get(register) ?? 0;
    console.log(`[MockI2C] ReadByte 0x${register.toString(16)} = 0x${value.toString(16)}`);
    return value;
  }

  async writeByte(register: number, value: number): Promise<void> {
    if (!this.opened) throw new Error('Bus not open');
    this.registers.set(register, value & 0xFF);
    console.log(`[MockI2C] WriteByte 0x${register.toString(16)} = 0x${value.toString(16)}`);
  }

  async readWord(register: number, littleEndian = false): Promise<number> {
    const high = await this.readByte(register);
    const low = await this.readByte(register + 1);
    return littleEndian ? (low << 8) | high : (high << 8) | low;
  }

  async writeWord(register: number, value: number, littleEndian = false): Promise<void> {
    if (littleEndian) {
      await this.writeByte(register, value & 0xFF);
      await this.writeByte(register + 1, (value >> 8) & 0xFF);
    } else {
      await this.writeByte(register, (value >> 8) & 0xFF);
      await this.writeByte(register + 1, value & 0xFF);
    }
  }

  async readBlock(register: number, length: number): Promise<Buffer> {
    if (!this.opened) throw new Error('Bus not open');
    const data = Buffer.alloc(length);
    for (let i = 0; i < length; i++) {
      data[i] = this.registers.get(register + i) ?? 0;
    }
    console.log(`[MockI2C] ReadBlock 0x${register.toString(16)} x${length} = ${ProtocolBase.bufferToHex(data)}`);
    return data;
  }

  async writeBlock(register: number, data: Buffer): Promise<void> {
    if (!this.opened) throw new Error('Bus not open');
    for (let i = 0; i < data.length; i++) {
      this.registers.set(register + i, data[i]);
    }
    console.log(`[MockI2C] WriteBlock 0x${register.toString(16)} = ${ProtocolBase.bufferToHex(data)}`);
  }
}
