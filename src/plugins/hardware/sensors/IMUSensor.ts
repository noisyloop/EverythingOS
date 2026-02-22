// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - IMU Sensor
// Inertial Measurement Unit (accelerometer, gyroscope, magnetometer)
// Supports: MPU6050, MPU9250, LSM6DS3, BNO055
// ═══════════════════════════════════════════════════════════════════════════════

import { SensorPlugin, SensorConfig } from '../_base/SensorPlugin';
import { I2CProtocol } from '../../protocols/I2CProtocol';
import { OrientationData, VelocityData } from '../_base/HardwareTypes';

// ─────────────────────────────────────────────────────────────────────────────
// IMU Configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface IMUSensorConfig extends Omit<SensorConfig, 'sensorType' | 'protocol'> {
  sensorType: 'imu';
  protocol: 'i2c';
  
  // I2C settings
  bus: number;
  address: number;
  
  // Chip type
  chip: 'mpu6050' | 'mpu9250' | 'lsm6ds3' | 'bno055';
  
  // Ranges
  accelRange?: '2g' | '4g' | '8g' | '16g';
  gyroRange?: '250dps' | '500dps' | '1000dps' | '2000dps';
  
  // Output
  outputMode?: 'raw' | 'calibrated' | 'quaternion';
}

export interface IMUReading {
  // Accelerometer (m/s² or g)
  accel: { x: number; y: number; z: number };
  accelUnit: 'm/s²' | 'g';
  
  // Gyroscope (deg/s or rad/s)
  gyro: { x: number; y: number; z: number };
  gyroUnit: 'deg/s' | 'rad/s';
  
  // Magnetometer (if available)
  mag?: { x: number; y: number; z: number };
  magUnit?: 'uT' | 'gauss';
  
  // Derived orientation (if calculated)
  orientation?: OrientationData;
  
  // Temperature (most IMUs have internal temp sensor)
  temperature?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Chip Register Maps
// ─────────────────────────────────────────────────────────────────────────────

const MPU6050_REGISTERS = {
  WHO_AM_I: 0x75,
  WHO_AM_I_VALUE: 0x68,
  PWR_MGMT_1: 0x6B,
  PWR_MGMT_2: 0x6C,
  SMPLRT_DIV: 0x19,
  CONFIG: 0x1A,
  GYRO_CONFIG: 0x1B,
  ACCEL_CONFIG: 0x1C,
  ACCEL_XOUT_H: 0x3B,
  ACCEL_XOUT_L: 0x3C,
  ACCEL_YOUT_H: 0x3D,
  ACCEL_YOUT_L: 0x3E,
  ACCEL_ZOUT_H: 0x3F,
  ACCEL_ZOUT_L: 0x40,
  TEMP_OUT_H: 0x41,
  TEMP_OUT_L: 0x42,
  GYRO_XOUT_H: 0x43,
  GYRO_XOUT_L: 0x44,
  GYRO_YOUT_H: 0x45,
  GYRO_YOUT_L: 0x46,
  GYRO_ZOUT_H: 0x47,
  GYRO_ZOUT_L: 0x48,
};

// Scale factors
const ACCEL_SCALE = {
  '2g': 16384.0,
  '4g': 8192.0,
  '8g': 4096.0,
  '16g': 2048.0,
};

const GYRO_SCALE = {
  '250dps': 131.0,
  '500dps': 65.5,
  '1000dps': 32.8,
  '2000dps': 16.4,
};

// ─────────────────────────────────────────────────────────────────────────────
// IMU Sensor Implementation
// ─────────────────────────────────────────────────────────────────────────────

export class IMUSensor extends SensorPlugin<IMUReading> {
  private i2c: I2CProtocol;
  private imuConfig: IMUSensorConfig;
  
  // Calibration offsets
  private accelOffset = { x: 0, y: 0, z: 0 };
  private gyroOffset = { x: 0, y: 0, z: 0 };

  constructor(config: Omit<IMUSensorConfig, 'type' | 'sensorType' | 'protocol'> & {
    type?: 'sensor';
    sensorType?: 'imu';
    protocol?: 'i2c';
  }) {
    const fullConfig: IMUSensorConfig = {
      ...config,
      type: 'sensor',
      sensorType: 'imu',
      protocol: 'i2c',
      accelRange: config.accelRange ?? '2g',
      gyroRange: config.gyroRange ?? '250dps',
      outputMode: config.outputMode ?? 'calibrated',
      pollRate: config.pollRate ?? 100, // 100ms = 10Hz default
      connection: {
        bus: config.bus,
        address: config.address,
      },
    };

    super(fullConfig);
    this.imuConfig = fullConfig;

    this.i2c = new I2CProtocol({
      id: `${config.id}-i2c`,
      type: 'i2c',
      connection: {
        bus: config.bus,
        address: config.address,
      },
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // SensorPlugin Implementation
  // ─────────────────────────────────────────────────────────────────────────

  protected async connect(): Promise<void> {
    await this.i2c.connect();
    
    // Verify WHO_AM_I
    if (this.imuConfig.chip === 'mpu6050' || this.imuConfig.chip === 'mpu9250') {
      const whoAmI = await this.i2c.readByte(MPU6050_REGISTERS.WHO_AM_I);
      if (whoAmI !== MPU6050_REGISTERS.WHO_AM_I_VALUE && whoAmI !== 0x71) { // 0x71 for MPU9250
        this.log('warn', `Unexpected WHO_AM_I: 0x${whoAmI.toString(16)}`);
      }
    }

    await this.initializeSensor();
  }

  protected async disconnect(): Promise<void> {
    // Put sensor to sleep
    if (this.imuConfig.chip === 'mpu6050' || this.imuConfig.chip === 'mpu9250') {
      await this.i2c.writeByte(MPU6050_REGISTERS.PWR_MGMT_1, 0x40); // Sleep mode
    }
    
    await this.i2c.disconnect();
  }

  protected async readRaw(): Promise<IMUReading> {
    switch (this.imuConfig.chip) {
      case 'mpu6050':
      case 'mpu9250':
        return this.readMPU6050();
      default:
        return this.readMPU6050(); // Default to MPU6050 protocol
    }
  }

  protected applyCalibration(data: IMUReading): IMUReading {
    if (this.imuConfig.outputMode === 'raw') {
      return data;
    }

    return {
      ...data,
      accel: {
        x: data.accel.x - this.accelOffset.x,
        y: data.accel.y - this.accelOffset.y,
        z: data.accel.z - this.accelOffset.z,
      },
      gyro: {
        x: data.gyro.x - this.gyroOffset.x,
        y: data.gyro.y - this.gyroOffset.y,
        z: data.gyro.z - this.gyroOffset.z,
      },
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Initialization
  // ─────────────────────────────────────────────────────────────────────────

  private async initializeSensor(): Promise<void> {
    if (this.imuConfig.chip === 'mpu6050' || this.imuConfig.chip === 'mpu9250') {
      await this.initMPU6050();
    }
  }

  private async initMPU6050(): Promise<void> {
    const reg = MPU6050_REGISTERS;

    // Wake up the sensor (clear sleep bit)
    await this.i2c.writeByte(reg.PWR_MGMT_1, 0x00);
    await this.sleep(100); // Wait for wake up

    // Set clock source to PLL with X-axis gyro
    await this.i2c.writeByte(reg.PWR_MGMT_1, 0x01);

    // Configure sample rate divider (1kHz / (1 + SMPLRT_DIV))
    await this.i2c.writeByte(reg.SMPLRT_DIV, 0x07); // 125Hz

    // Configure DLPF (Digital Low Pass Filter)
    await this.i2c.writeByte(reg.CONFIG, 0x06); // 5Hz bandwidth

    // Configure accelerometer range
    const accelConfig = this.getAccelConfigByte();
    await this.i2c.writeByte(reg.ACCEL_CONFIG, accelConfig);

    // Configure gyroscope range
    const gyroConfig = this.getGyroConfigByte();
    await this.i2c.writeByte(reg.GYRO_CONFIG, gyroConfig);

    this.log('info', `MPU6050 initialized (accel: ${this.imuConfig.accelRange}, gyro: ${this.imuConfig.gyroRange})`);
  }

  private getAccelConfigByte(): number {
    switch (this.imuConfig.accelRange) {
      case '2g': return 0x00;
      case '4g': return 0x08;
      case '8g': return 0x10;
      case '16g': return 0x18;
      default: return 0x00;
    }
  }

  private getGyroConfigByte(): number {
    switch (this.imuConfig.gyroRange) {
      case '250dps': return 0x00;
      case '500dps': return 0x08;
      case '1000dps': return 0x10;
      case '2000dps': return 0x18;
      default: return 0x00;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Reading
  // ─────────────────────────────────────────────────────────────────────────

  private async readMPU6050(): Promise<IMUReading> {
    const reg = MPU6050_REGISTERS;

    // Read all sensor data in one burst (more efficient)
    // ACCEL_XOUT_H to GYRO_ZOUT_L = 14 bytes
    const data = await this.i2c.readBlock(reg.ACCEL_XOUT_H, 14);

    // Parse accelerometer (big-endian, signed 16-bit)
    const accelXRaw = this.toSigned16((data[0] << 8) | data[1]);
    const accelYRaw = this.toSigned16((data[2] << 8) | data[3]);
    const accelZRaw = this.toSigned16((data[4] << 8) | data[5]);

    // Parse temperature
    const tempRaw = this.toSigned16((data[6] << 8) | data[7]);

    // Parse gyroscope
    const gyroXRaw = this.toSigned16((data[8] << 8) | data[9]);
    const gyroYRaw = this.toSigned16((data[10] << 8) | data[11]);
    const gyroZRaw = this.toSigned16((data[12] << 8) | data[13]);

    // Scale to physical units
    const accelScale = ACCEL_SCALE[this.imuConfig.accelRange ?? '2g'];
    const gyroScale = GYRO_SCALE[this.imuConfig.gyroRange ?? '250dps'];

    const reading: IMUReading = {
      accel: {
        x: accelXRaw / accelScale,
        y: accelYRaw / accelScale,
        z: accelZRaw / accelScale,
      },
      accelUnit: 'g',
      gyro: {
        x: gyroXRaw / gyroScale,
        y: gyroYRaw / gyroScale,
        z: gyroZRaw / gyroScale,
      },
      gyroUnit: 'deg/s',
      temperature: tempRaw / 340.0 + 36.53, // MPU6050 temperature formula
    };

    return reading;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Calibration
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Calibrate the sensor by averaging readings while stationary.
   * Place the sensor flat and still during calibration.
   */
  async calibrate(samples = 100): Promise<void> {
    this.log('info', `Starting calibration with ${samples} samples...`);
    
    let accelSum = { x: 0, y: 0, z: 0 };
    let gyroSum = { x: 0, y: 0, z: 0 };

    for (let i = 0; i < samples; i++) {
      const reading = await this.readRaw();
      
      accelSum.x += reading.accel.x;
      accelSum.y += reading.accel.y;
      accelSum.z += reading.accel.z;
      
      gyroSum.x += reading.gyro.x;
      gyroSum.y += reading.gyro.y;
      gyroSum.z += reading.gyro.z;

      await this.sleep(10);
    }

    // Calculate offsets
    this.accelOffset = {
      x: accelSum.x / samples,
      y: accelSum.y / samples,
      z: accelSum.z / samples - 1.0, // Subtract 1g for gravity on Z-axis (assuming flat)
    };

    this.gyroOffset = {
      x: gyroSum.x / samples,
      y: gyroSum.y / samples,
      z: gyroSum.z / samples,
    };

    this.log('info', `Calibration complete. Accel offset: ${JSON.stringify(this.accelOffset)}, Gyro offset: ${JSON.stringify(this.gyroOffset)}`);
  }

  getCalibrationOffsets(): { accel: { x: number; y: number; z: number }; gyro: { x: number; y: number; z: number } } {
    return {
      accel: { ...this.accelOffset },
      gyro: { ...this.gyroOffset },
    };
  }

  setCalibrationOffsets(offsets: { accel?: { x: number; y: number; z: number }; gyro?: { x: number; y: number; z: number } }): void {
    if (offsets.accel) this.accelOffset = offsets.accel;
    if (offsets.gyro) this.gyroOffset = offsets.gyro;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────────────────

  private toSigned16(value: number): number {
    return value > 32767 ? value - 65536 : value;
  }
}
