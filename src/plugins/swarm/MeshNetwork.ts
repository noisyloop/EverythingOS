// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Mesh Network
// Peer-to-peer communication for robot swarms
// Handles: Discovery, routing, message relay, network topology
// ═══════════════════════════════════════════════════════════════════════════════

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { eventBus } from '../../core/event-bus/EventBus';
import { WebSocketProtocol } from '../hardware/protocols/WebSocketProtocol';
import { MQTTProtocol } from '../hardware/protocols/MQTTProtocol';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface MeshConfig {
  nodeId: string;
  transport?: 'websocket' | 'mqtt' | 'hybrid';
  
  // WebSocket (direct P2P)
  wsPort?: number;
  wsHost?: string;
  
  // MQTT (broker-based)
  mqttBroker?: string;
  mqttPort?: number;
  mqttBaseTopic?: string;
  
  // Network settings
  maxPeers?: number;
  discoveryInterval?: number;    // ms
  pingInterval?: number;         // ms
  peerTimeout?: number;          // ms
  maxHops?: number;              // For message relay

  /**
   * HMAC secret for message authentication. When set, all outbound messages
   * are signed and inbound messages without a valid signature are dropped.
   * Use a 32-byte random hex string: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   * If unset, signing is skipped (development mode only).
   */
  meshSecret?: string;
}

export interface MeshPeer {
  id: string;
  address?: string;              // IP:port for direct connection
  lastSeen: number;
  latency?: number;              // ms
  hops: number;                  // 0 = direct, 1+ = relayed
  connected: boolean;
  metadata?: Record<string, unknown>;
}

export interface MeshMessage {
  id: string;
  type: string;
  from: string;
  to: string | 'broadcast';
  payload: unknown;
  timestamp: number;
  ttl: number;                   // Remaining hops
  path: string[];                // Nodes traversed
  /** HMAC-SHA256 of "id:from:to:timestamp" — present when meshSecret is configured */
  hmac?: string;
}

export type MessageHandler = (message: MeshMessage) => void;

// ─────────────────────────────────────────────────────────────────────────────
// Mesh Network Implementation
// ─────────────────────────────────────────────────────────────────────────────

export class MeshNetwork {
  private config: MeshConfig;
  private peers: Map<string, MeshPeer> = new Map();
  private messageHandlers: Map<string, MessageHandler[]> = new Map();
  private seenMessages: Set<string> = new Set();
  
  // Transport
  private mqtt?: MQTTProtocol;
  private wsConnections: Map<string, WebSocketProtocol> = new Map();
  
  // Timers
  private discoveryTimer?: ReturnType<typeof setInterval>;
  private pingTimer?: ReturnType<typeof setInterval>;
  private messageCounter = 0;

  constructor(config: MeshConfig) {
    this.config = {
      transport: 'mqtt',
      wsPort: 8765,
      mqttPort: 1883,
      mqttBaseTopic: 'swarm/mesh',
      maxPeers: 50,
      discoveryInterval: 5000,
      pingInterval: 2000,
      peerTimeout: 10000,
      maxHops: 5,
      ...config,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  async start(): Promise<void> {
    // Initialize transport
    if (this.config.transport === 'mqtt' || this.config.transport === 'hybrid') {
      await this.initMQTT();
    }

    // Start discovery
    this.discoveryTimer = setInterval(() => {
      this.discover();
    }, this.config.discoveryInterval);

    // Start ping
    this.pingTimer = setInterval(() => {
      this.pingPeers();
      this.cleanupPeers();
    }, this.config.pingInterval);

    // Initial discovery
    this.discover();

    this.log('info', `Mesh network started (node: ${this.config.nodeId})`);
    eventBus.emit('mesh:started', { nodeId: this.config.nodeId });
  }

  async stop(): Promise<void> {
    if (this.discoveryTimer) {
      clearInterval(this.discoveryTimer);
      this.discoveryTimer = undefined;
    }
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = undefined;
    }

    // Announce departure
    this.broadcast('mesh:leave', { nodeId: this.config.nodeId });

    // Close connections
    if (this.mqtt) {
      await this.mqtt.disconnect();
    }
    for (const ws of this.wsConnections.values()) {
      await ws.disconnect();
    }

    this.log('info', 'Mesh network stopped');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Transport: MQTT
  // ─────────────────────────────────────────────────────────────────────────

  private async initMQTT(): Promise<void> {
    this.mqtt = new MQTTProtocol({
      id: `mesh-${this.config.nodeId}`,
      type: 'mqtt',
      connection: {
        host: this.config.mqttBroker ?? 'localhost',
        portNumber: this.config.mqttPort,
      },
      clientId: `mesh_${this.config.nodeId}`,
    });

    await this.mqtt.connect();

    // Subscribe to mesh topics
    const baseTopic = this.config.mqttBaseTopic;
    
    // Broadcast channel
    await this.mqtt.subscribe(`${baseTopic}/broadcast`, 1, (topic, payload) => {
      this.handleMQTTMessage(payload);
    });

    // Direct messages to this node
    await this.mqtt.subscribe(`${baseTopic}/node/${this.config.nodeId}`, 1, (topic, payload) => {
      this.handleMQTTMessage(payload);
    });

    // Discovery channel
    await this.mqtt.subscribe(`${baseTopic}/discovery`, 0, (topic, payload) => {
      this.handleDiscovery(payload);
    });
  }

  private handleMQTTMessage(payload: Buffer): void {
    try {
      const message = JSON.parse(payload.toString()) as MeshMessage;
      this.receiveMessage(message);
    } catch (error) {
      this.log('error', `Failed to parse MQTT message: ${error}`);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Discovery
  // ─────────────────────────────────────────────────────────────────────────

  private discover(): void {
    const announcement = {
      nodeId: this.config.nodeId,
      address: this.config.wsHost ? `${this.config.wsHost}:${this.config.wsPort}` : undefined,
      timestamp: Date.now(),
    };

    if (this.mqtt) {
      this.mqtt.publish(
        `${this.config.mqttBaseTopic}/discovery`,
        JSON.stringify(announcement),
        { qos: 0 }
      );
    }
  }

  private handleDiscovery(payload: Buffer): void {
    try {
      const announcement = JSON.parse(payload.toString());
      
      if (announcement.nodeId === this.config.nodeId) return;

      const existing = this.peers.get(announcement.nodeId);
      
      if (existing) {
        existing.lastSeen = Date.now();
        existing.address = announcement.address;
      } else {
        // New peer
        const peer: MeshPeer = {
          id: announcement.nodeId,
          address: announcement.address,
          lastSeen: Date.now(),
          hops: 1, // Via MQTT = 1 hop
          connected: true,
        };
        this.peers.set(peer.id, peer);

        this.log('info', `Peer discovered: ${peer.id}`);
        eventBus.emit('mesh:peer:joined', { peer });
      }
    } catch (error) {
      this.log('error', `Failed to parse discovery: ${error}`);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Messaging
  // ─────────────────────────────────────────────────────────────────────────

  // ─────────────────────────────────────────────────────────────────────────
  // Message HMAC authentication (STRIDE R-2: peer injection prevention)
  // ─────────────────────────────────────────────────────────────────────────

  private signMessage(message: MeshMessage): string {
    const payload = `${message.id}:${message.from}:${message.to}:${message.timestamp}`;
    return createHmac('sha256', this.config.meshSecret!).update(payload).digest('hex');
  }

  private verifyMessage(message: MeshMessage): boolean {
    if (!this.config.meshSecret) return true; // signing disabled
    if (!message.hmac) return false;
    if (message.hmac.length !== 64) return false;
    const expected = this.signMessage(message);
    try {
      return timingSafeEqual(Buffer.from(message.hmac, 'hex'), Buffer.from(expected, 'hex'));
    } catch {
      return false;
    }
  }

  send(to: string, type: string, payload: unknown): string {
    const ts = Date.now();
    const id = `${this.config.nodeId}_${++this.messageCounter}_${ts}`;
    const message: MeshMessage = {
      id,
      type,
      from: this.config.nodeId,
      to,
      payload,
      timestamp: ts,
      ttl: this.config.maxHops!,
      path: [this.config.nodeId],
    };

    if (this.config.meshSecret) {
      message.hmac = this.signMessage(message);
    }

    this.routeMessage(message);
    return message.id;
  }

  broadcast(type: string, payload: unknown): string {
    return this.send('broadcast', type, payload);
  }

  private routeMessage(message: MeshMessage): void {
    // Mark as seen
    this.seenMessages.add(message.id);
    
    // Cleanup old seen messages
    if (this.seenMessages.size > 10000) {
      const arr = Array.from(this.seenMessages);
      this.seenMessages = new Set(arr.slice(-5000));
    }

    if (message.to === 'broadcast') {
      // Broadcast via MQTT
      if (this.mqtt) {
        this.mqtt.publish(
          `${this.config.mqttBaseTopic}/broadcast`,
          JSON.stringify(message),
          { qos: 1 }
        );
      }
    } else {
      // Direct message
      const peer = this.peers.get(message.to);
      
      if (peer?.connected) {
        // Send via MQTT direct topic
        if (this.mqtt) {
          this.mqtt.publish(
            `${this.config.mqttBaseTopic}/node/${message.to}`,
            JSON.stringify(message),
            { qos: 1 }
          );
        }
      } else if (message.ttl > 0) {
        // Relay through other peers
        this.relayMessage(message);
      } else {
        this.log('warn', `Cannot route message to ${message.to}: not reachable`);
      }
    }
  }

  private relayMessage(message: MeshMessage): void {
    // Find peers that might be closer to destination
    const candidates = Array.from(this.peers.values())
      .filter(p => p.connected && !message.path.includes(p.id));

    if (candidates.length === 0) {
      this.log('warn', `No relay candidates for message to ${message.to}`);
      return;
    }

    // Send to all candidates (flooding with TTL)
    const relayedMessage = {
      ...message,
      ttl: message.ttl - 1,
      path: [...message.path, this.config.nodeId],
    };

    for (const peer of candidates) {
      if (this.mqtt) {
        this.mqtt.publish(
          `${this.config.mqttBaseTopic}/node/${peer.id}`,
          JSON.stringify(relayedMessage),
          { qos: 1 }
        );
      }
    }
  }

  private receiveMessage(message: MeshMessage): void {
    // Ignore own messages
    if (message.from === this.config.nodeId) return;

    // Verify HMAC before processing — drop forged/tampered messages
    if (this.config.meshSecret && !this.verifyMessage(message)) {
      this.log('warn', `Dropped message ${message.id} from ${message.from}: HMAC verification failed`);
      return;
    }

    // Ignore already seen messages
    if (this.seenMessages.has(message.id)) return;
    this.seenMessages.add(message.id);

    // Check if this message is for us
    if (message.to === this.config.nodeId || message.to === 'broadcast') {
      // Deliver locally
      this.deliverMessage(message);
    }

    // Relay if needed (and TTL allows)
    if (message.to !== 'broadcast' && message.to !== this.config.nodeId && message.ttl > 0) {
      this.relayMessage(message);
    }
  }

  private deliverMessage(message: MeshMessage): void {
    // Update peer info from path
    if (message.path.length > 0) {
      const senderId = message.from;
      const peer = this.peers.get(senderId);
      if (peer) {
        peer.lastSeen = Date.now();
        peer.hops = message.path.length;
      }
    }

    // Call handlers
    const handlers = this.messageHandlers.get(message.type) ?? [];
    const wildcardHandlers = this.messageHandlers.get('*') ?? [];

    for (const handler of [...handlers, ...wildcardHandlers]) {
      try {
        handler(message);
      } catch (error) {
        this.log('error', `Message handler error: ${error}`);
      }
    }

    // Emit event
    eventBus.emit('mesh:message', message);
    eventBus.emit(`mesh:message:${message.type}`, message);
  }

  on(type: string, handler: MessageHandler): () => void {
    const handlers = this.messageHandlers.get(type) ?? [];
    handlers.push(handler);
    this.messageHandlers.set(type, handlers);

    return () => {
      const idx = handlers.indexOf(handler);
      if (idx > -1) handlers.splice(idx, 1);
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Peer Management
  // ─────────────────────────────────────────────────────────────────────────

  private pingPeers(): void {
    this.broadcast('mesh:ping', {
      from: this.config.nodeId,
      timestamp: Date.now(),
    });
  }

  private cleanupPeers(): void {
    const now = Date.now();
    
    for (const [id, peer] of this.peers) {
      if (now - peer.lastSeen > this.config.peerTimeout!) {
        peer.connected = false;
        
        if (now - peer.lastSeen > this.config.peerTimeout! * 3) {
          this.peers.delete(id);
          this.log('info', `Peer removed: ${id}`);
          eventBus.emit('mesh:peer:left', { peerId: id });
        }
      }
    }
  }

  getPeer(peerId: string): MeshPeer | undefined {
    return this.peers.get(peerId);
  }

  getAllPeers(): MeshPeer[] {
    return Array.from(this.peers.values());
  }

  getConnectedPeers(): MeshPeer[] {
    return this.getAllPeers().filter(p => p.connected);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Request/Response Pattern
  // ─────────────────────────────────────────────────────────────────────────

  async request<T = unknown>(to: string, type: string, payload: unknown, timeout = 5000): Promise<T> {
    return new Promise((resolve, reject) => {
      const requestId = this.send(to, type, { ...payload as object, _requestId: Date.now() });
      const responseType = `${type}:response`;

      const timeoutId = setTimeout(() => {
        cleanup();
        reject(new Error(`Request timeout: ${type}`));
      }, timeout);

      const handler = (message: MeshMessage) => {
        const msgPayload = message.payload as { _requestId?: number };
        if (message.from === to && msgPayload._requestId) {
          cleanup();
          resolve(message.payload as T);
        }
      };

      const cleanup = () => {
        clearTimeout(timeoutId);
        const handlers = this.messageHandlers.get(responseType) ?? [];
        const idx = handlers.indexOf(handler);
        if (idx > -1) handlers.splice(idx, 1);
      };

      this.on(responseType, handler);
    });
  }

  respond(originalMessage: MeshMessage, payload: unknown): void {
    const originalPayload = originalMessage.payload as { _requestId?: number };
    this.send(originalMessage.from, `${originalMessage.type}:response`, {
      ...payload as object,
      _requestId: originalPayload._requestId,
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────────────────

  private log(level: 'debug' | 'info' | 'warn' | 'error', message: string): void {
    eventBus.emit('mesh:log', { level, message, nodeId: this.config.nodeId, timestamp: Date.now() });
  }

  getStatus(): {
    nodeId: string;
    peerCount: number;
    connectedPeers: number;
    transport: string;
  } {
    return {
      nodeId: this.config.nodeId,
      peerCount: this.peers.size,
      connectedPeers: this.getConnectedPeers().length,
      transport: this.config.transport ?? 'mqtt',
    };
  }
}
