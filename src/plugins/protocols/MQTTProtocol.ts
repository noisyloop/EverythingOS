// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - MQTT Protocol
// MQTT (Message Queuing Telemetry Transport) for IoT messaging
// Lightweight pub/sub protocol for sensors, actuators, and IoT devices
// ═══════════════════════════════════════════════════════════════════════════════

import { ProtocolBase, ProtocolConfig, ProtocolMessage } from './ProtocolBase';
import { ConnectionConfig } from '../hardware/_base/HardwareTypes';

// ─────────────────────────────────────────────────────────────────────────────
// MQTT Configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface MQTTConfig extends ProtocolConfig {
  type: 'mqtt';
  connection: MQTTConnectionConfig;
  
  // Client options
  clientId?: string;
  cleanSession?: boolean;
  keepalive?: number;           // seconds
  
  // Subscriptions
  subscriptions?: MQTTSubscription[];
  
  // Last Will and Testament
  will?: {
    topic: string;
    payload: string;
    qos?: QoS;
    retain?: boolean;
  };
}

export interface MQTTConnectionConfig extends ConnectionConfig {
  host: string;                 // Broker host
  portNumber?: number;          // Default: 1883 (or 8883 for TLS)
  protocol?: 'mqtt' | 'mqtts' | 'ws' | 'wss';
  username?: string;
  password?: string;
  
  // TLS options
  useTLS?: boolean;
  ca?: string;                  // CA certificate
  cert?: string;                // Client certificate
  key?: string;                 // Client private key
  rejectUnauthorized?: boolean;
}

export interface MQTTSubscription {
  topic: string;
  qos?: QoS;
  handler?: (topic: string, message: Buffer, packet: MQTTPacket) => void;
}

export type QoS = 0 | 1 | 2;    // At most once, At least once, Exactly once

export interface MQTTPacket {
  topic: string;
  payload: Buffer;
  qos: QoS;
  retain: boolean;
  messageId?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// MQTT Protocol Implementation
// ─────────────────────────────────────────────────────────────────────────────

export class MQTTProtocol extends ProtocolBase {
  protected mqttConfig: MQTTConfig;
  private client: MockMQTTClient | null = null;
  private subscriptionHandlers: Map<string, MQTTSubscription['handler'][]> = new Map();

  constructor(config: Omit<MQTTConfig, 'type'> & { type?: 'mqtt' }) {
    const fullConfig: MQTTConfig = {
      ...config,
      type: 'mqtt',
      clientId: config.clientId ?? `everythingos_${Math.random().toString(36).slice(2, 10)}`,
      cleanSession: config.cleanSession ?? true,
      keepalive: config.keepalive ?? 60,
      connection: {
        portNumber: 1883,
        protocol: 'mqtt',
        rejectUnauthorized: true,
        ...config.connection,
      },
    };

    super(fullConfig);
    this.mqttConfig = fullConfig;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Connection
  // ─────────────────────────────────────────────────────────────────────────

  protected async openConnection(): Promise<void> {
    const conn = this.mqttConfig.connection;
    
    this.log('info', `Connecting to MQTT broker ${conn.host}:${conn.portNumber}`);

    try {
      this.client = await this.connectNative();
    } catch (error) {
      this.log('warn', `Native MQTT not available: ${error}. Using mock.`);
      this.client = new MockMQTTClient(this.mqttConfig);
    }

    await this.client.connect();

    // Set up message handler
    this.client.onMessage((topic, payload, packet) => {
      this.handleMQTTMessage(topic, payload, packet);
    });

    this.client.onError((error) => {
      this.handleError(error);
    });

    this.client.onClose(() => {
      if (this.status === 'connected') {
        this.handleConnectionError(new Error('MQTT connection closed'));
      }
    });

    // Subscribe to configured topics
    if (this.mqttConfig.subscriptions) {
      for (const sub of this.mqttConfig.subscriptions) {
        await this.subscribe(sub.topic, sub.qos, sub.handler);
      }
    }
  }

  protected async closeConnection(): Promise<void> {
    if (this.client) {
      await this.client.disconnect();
      this.client = null;
    }
    this.subscriptionHandlers.clear();
  }

  protected isConnectionOpen(): boolean {
    return this.client?.isConnected() ?? false;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Base Protocol Methods (not typically used for MQTT)
  // ─────────────────────────────────────────────────────────────────────────

  protected async writeRaw(data: Buffer | Uint8Array): Promise<number> {
    // MQTT uses publish instead of raw write
    throw new Error('Use publish() for MQTT');
  }

  protected async readRaw(length: number): Promise<Buffer | Uint8Array> {
    // MQTT uses subscribe/message handlers instead of raw read
    throw new Error('Use subscribe() for MQTT');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // MQTT Operations
  // ─────────────────────────────────────────────────────────────────────────

  /** Publish a message to a topic */
  async publish(
    topic: string, 
    payload: string | Buffer | object,
    options?: { qos?: QoS; retain?: boolean }
  ): Promise<void> {
    this.ensureConnected();
    if (!this.client) throw new Error('Not connected');

    const data = typeof payload === 'object' && !Buffer.isBuffer(payload)
      ? JSON.stringify(payload)
      : payload;

    const buffer = typeof data === 'string' ? Buffer.from(data) : data;

    await this.client.publish(topic, buffer, {
      qos: options?.qos ?? 0,
      retain: options?.retain ?? false,
    });

    this.stats.bytesWritten += buffer.length;
    this.stats.messagesWritten++;
    this.stats.lastActivity = Date.now();

    this.log('debug', `Published to ${topic}: ${buffer.length} bytes`);
    this.emit('published', { topic, bytes: buffer.length });
  }

  /** Subscribe to a topic */
  async subscribe(
    topic: string, 
    qos: QoS = 0,
    handler?: MQTTSubscription['handler']
  ): Promise<void> {
    this.ensureConnected();
    if (!this.client) throw new Error('Not connected');

    await this.client.subscribe(topic, qos);

    if (handler) {
      const handlers = this.subscriptionHandlers.get(topic) ?? [];
      handlers.push(handler);
      this.subscriptionHandlers.set(topic, handlers);
    }

    this.log('info', `Subscribed to ${topic} (QoS ${qos})`);
    this.emit('subscribed', { topic, qos });
  }

  /** Unsubscribe from a topic */
  async unsubscribe(topic: string): Promise<void> {
    this.ensureConnected();
    if (!this.client) throw new Error('Not connected');

    await this.client.unsubscribe(topic);
    this.subscriptionHandlers.delete(topic);

    this.log('info', `Unsubscribed from ${topic}`);
    this.emit('unsubscribed', { topic });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Message Handling
  // ─────────────────────────────────────────────────────────────────────────

  private handleMQTTMessage(topic: string, payload: Buffer, packet: MQTTPacket): void {
    this.stats.bytesRead += payload.length;
    this.stats.messagesRead++;
    this.stats.lastActivity = Date.now();

    // Call topic-specific handlers
    for (const [pattern, handlers] of this.subscriptionHandlers) {
      if (this.topicMatches(pattern, topic)) {
        for (const handler of handlers) {
          try {
            handler?.(topic, payload, packet);
          } catch (error) {
            this.log('error', `Handler error for ${topic}: ${error}`);
          }
        }
      }
    }

    // Emit to general listeners
    const message: ProtocolMessage = {
      data: payload,
      timestamp: Date.now(),
      metadata: { topic, qos: packet.qos, retain: packet.retain },
    };

    this.handleIncomingData(payload);
    this.emit('message', { topic, payload: payload.toString(), packet });
  }

  /** Check if a topic matches a subscription pattern (supports + and # wildcards) */
  private topicMatches(pattern: string, topic: string): boolean {
    if (pattern === topic) return true;
    if (pattern === '#') return true;

    const patternParts = pattern.split('/');
    const topicParts = topic.split('/');

    for (let i = 0; i < patternParts.length; i++) {
      const p = patternParts[i];

      if (p === '#') {
        return true; // # matches everything from here on
      }

      if (p === '+') {
        continue; // + matches single level
      }

      if (i >= topicParts.length || p !== topicParts[i]) {
        return false;
      }
    }

    return patternParts.length === topicParts.length;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Convenience Methods
  // ─────────────────────────────────────────────────────────────────────────

  /** Publish JSON data */
  async publishJSON(topic: string, data: object, options?: { qos?: QoS; retain?: boolean }): Promise<void> {
    await this.publish(topic, JSON.stringify(data), options);
  }

  /** Subscribe and parse JSON messages */
  subscribeJSON<T = unknown>(
    topic: string,
    handler: (topic: string, data: T) => void,
    qos: QoS = 0
  ): Promise<void> {
    return this.subscribe(topic, qos, (t, payload) => {
      try {
        const data = JSON.parse(payload.toString()) as T;
        handler(t, data);
      } catch (error) {
        this.log('warn', `Failed to parse JSON from ${t}: ${error}`);
      }
    });
  }

  /** Request-response pattern */
  async request(
    requestTopic: string,
    responseTopic: string,
    payload: string | Buffer | object,
    timeout = 5000
  ): Promise<Buffer> {
    return new Promise(async (resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.unsubscribe(responseTopic);
        reject(new Error('Request timeout'));
      }, timeout);

      const handler: MQTTSubscription['handler'] = (topic, response) => {
        clearTimeout(timeoutId);
        this.unsubscribe(responseTopic);
        resolve(response);
      };

      await this.subscribe(responseTopic, 1, handler);
      await this.publish(requestTopic, payload, { qos: 1 });
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Native Implementation
  // ─────────────────────────────────────────────────────────────────────────

  private async connectNative(): Promise<MockMQTTClient> {
    // This would use the 'mqtt' npm package:
    //
    // const mqtt = await import('mqtt');
    // const url = `${this.mqttConfig.connection.protocol}://${this.mqttConfig.connection.host}:${this.mqttConfig.connection.portNumber}`;
    // return mqtt.connect(url, {
    //   clientId: this.mqttConfig.clientId,
    //   clean: this.mqttConfig.cleanSession,
    //   keepalive: this.mqttConfig.keepalive,
    //   username: this.mqttConfig.connection.username,
    //   password: this.mqttConfig.connection.password,
    //   will: this.mqttConfig.will,
    // });

    throw new Error('Native MQTT not implemented - install mqtt package');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock MQTT Client (for testing/development)
// ─────────────────────────────────────────────────────────────────────────────

class MockMQTTClient {
  private config: MQTTConfig;
  private connected = false;
  private subscriptions: Map<string, QoS> = new Map();
  private messageHandlers: Array<(topic: string, payload: Buffer, packet: MQTTPacket) => void> = [];
  private errorHandlers: Array<(error: Error) => void> = [];
  private closeHandlers: Array<() => void> = [];
  private messageInterval?: ReturnType<typeof setInterval>;

  constructor(config: MQTTConfig) {
    this.config = config;
  }

  async connect(): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, 100));
    this.connected = true;
    console.log(`[MockMQTT] Connected to ${this.config.connection.host}:${this.config.connection.portNumber}`);
    
    // Start simulating incoming messages
    this.startMessageSimulation();
  }

  async disconnect(): Promise<void> {
    this.stopMessageSimulation();
    this.connected = false;
    this.closeHandlers.forEach(h => h());
    console.log('[MockMQTT] Disconnected');
  }

  isConnected(): boolean {
    return this.connected;
  }

  async publish(topic: string, payload: Buffer, options: { qos: QoS; retain: boolean }): Promise<void> {
    if (!this.connected) throw new Error('Not connected');
    console.log(`[MockMQTT] Publish ${topic}: ${payload.toString()}`);
  }

  async subscribe(topic: string, qos: QoS): Promise<void> {
    if (!this.connected) throw new Error('Not connected');
    this.subscriptions.set(topic, qos);
    console.log(`[MockMQTT] Subscribe ${topic} (QoS ${qos})`);
  }

  async unsubscribe(topic: string): Promise<void> {
    if (!this.connected) throw new Error('Not connected');
    this.subscriptions.delete(topic);
    console.log(`[MockMQTT] Unsubscribe ${topic}`);
  }

  onMessage(handler: (topic: string, payload: Buffer, packet: MQTTPacket) => void): void {
    this.messageHandlers.push(handler);
  }

  onError(handler: (error: Error) => void): void {
    this.errorHandlers.push(handler);
  }

  onClose(handler: () => void): void {
    this.closeHandlers.push(handler);
  }

  private startMessageSimulation(): void {
    // Simulate periodic sensor data for subscribed topics
    this.messageInterval = setInterval(() => {
      if (!this.connected) return;

      for (const [topic] of this.subscriptions) {
        // Simulate sensor data
        if (topic.includes('sensor') || topic.includes('temperature') || topic.includes('#')) {
          const mockData = {
            value: Math.random() * 100,
            unit: '°C',
            timestamp: Date.now(),
          };

          const payload = Buffer.from(JSON.stringify(mockData));
          const packet: MQTTPacket = {
            topic: topic.replace('#', 'mock/sensor/1').replace('+', 'device1'),
            payload,
            qos: 0,
            retain: false,
          };

          this.messageHandlers.forEach(h => h(packet.topic, payload, packet));
        }
      }
    }, 5000); // Every 5 seconds
  }

  private stopMessageSimulation(): void {
    if (this.messageInterval) {
      clearInterval(this.messageInterval);
      this.messageInterval = undefined;
    }
  }
}
