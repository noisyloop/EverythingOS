// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Mesh Network
// Peer-to-peer communication for robot swarms
// Handles: Discovery, routing, message relay, network topology
// ═══════════════════════════════════════════════════════════════════════════════

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';
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
   * and discovery announcements are signed; inbound traffic without a valid,
   * fresh, non-replayed signature is dropped. A node on the same network
   * segment without this secret cannot inject as a peer.
   * Use a 32-byte random hex string: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   * If unset, signing is skipped (development mode only — the mesh is open).
   */
  meshSecret?: string;

  /**
   * Maximum accepted clock skew (ms) for signed messages and discovery
   * announcements. Anything older/newer than this is rejected as a possible
   * replay. Generous enough for multi-hop relay. Default: 60000.
   */
  maxClockSkewMs?: number;
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
  /** Per-message random nonce — replay defense. Present when meshSecret is set. */
  nonce?: string;
  /**
   * HMAC-SHA256 over the canonical envelope (id, type, from, to, timestamp,
   * nonce, and a hash of payload). Present when meshSecret is configured.
   * Covers type and payload — a captured message cannot be re-purposed.
   */
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
  // Replay defense — every accepted signed nonce is remembered until the
  // freshness window guarantees it can no longer be replayed.
  private seenNonces: Set<string> = new Set();
  
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
      maxClockSkewMs: 60000,
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

    if (!this.config.meshSecret) {
      this.log(
        'warn',
        'Mesh network started WITHOUT meshSecret — peer enrollment and ' +
          'messages are unauthenticated. Any node on the segment can inject ' +
          'as a peer. Set meshSecret in production.',
      );
    }

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

  // Domain-separated signing material — the "discovery" tag prevents a
  // message HMAC from being replayed as a valid enrollment announcement.
  private discoveryMaterial(a: {
    nodeId: string;
    address?: string;
    timestamp: number;
    nonce: string;
  }): string {
    return JSON.stringify({
      ctx: 'discovery',
      nodeId: a.nodeId,
      address: a.address ?? '',
      ts: a.timestamp,
      nonce: a.nonce,
    });
  }

  private discover(): void {
    const announcement: {
      nodeId: string;
      address?: string;
      timestamp: number;
      nonce?: string;
      sig?: string;
    } = {
      nodeId: this.config.nodeId,
      address: this.config.wsHost ? `${this.config.wsHost}:${this.config.wsPort}` : undefined,
      timestamp: Date.now(),
    };

    if (this.config.meshSecret) {
      announcement.nonce = randomBytes(16).toString('hex');
      announcement.sig = this.hmacHex(
        this.discoveryMaterial({
          nodeId: announcement.nodeId,
          address: announcement.address,
          timestamp: announcement.timestamp,
          nonce: announcement.nonce,
        }),
      );
    }

    if (this.mqtt) {
      this.mqtt.publish(
        `${this.config.mqttBaseTopic}/discovery`,
        JSON.stringify(announcement),
        { qos: 0 }
      );
    }
  }

  // Authenticates an enrollment announcement. When meshSecret is set, an
  // announcement must carry a fresh, non-replayed, correctly-signed proof of
  // the deployment secret — otherwise an attacker on the segment could
  // register itself as a trusted peer simply by announcing an id.
  private authenticateAnnouncement(a: {
    nodeId?: unknown;
    address?: unknown;
    timestamp?: unknown;
    nonce?: unknown;
    sig?: unknown;
  }): boolean {
    if (typeof a.nodeId !== 'string' || a.nodeId.length === 0 || a.nodeId.length > 256) {
      return false;
    }
    if (!this.config.meshSecret) return true; // dev mode — open mesh

    if (typeof a.timestamp !== 'number' || typeof a.nonce !== 'string' || typeof a.sig !== 'string') {
      return false;
    }
    if (!this.isFresh(a.timestamp)) return false;

    const expected = this.hmacHex(
      this.discoveryMaterial({
        nodeId: a.nodeId,
        address: typeof a.address === 'string' ? a.address : undefined,
        timestamp: a.timestamp,
        nonce: a.nonce,
      }),
    );
    if (!this.constantTimeEqualHex(a.sig, expected)) return false;
    return this.consumeNonce(`disc:${a.nonce}`);
  }

  private handleDiscovery(payload: Buffer): void {
    try {
      const announcement = JSON.parse(payload.toString());

      if (announcement.nodeId === this.config.nodeId) return;

      if (!this.authenticateAnnouncement(announcement)) {
        this.log(
          'warn',
          `Rejected unauthenticated enrollment for "${announcement?.nodeId}" — ` +
            `missing/invalid/stale/replayed signature`,
        );
        eventBus.emit('mesh:peer:rejected', {
          claimedId: typeof announcement?.nodeId === 'string' ? announcement.nodeId : '<invalid>',
          reason: 'enrollment_authentication_failed',
          timestamp: Date.now(),
        });
        return;
      }

      const existing = this.peers.get(announcement.nodeId);

      if (existing) {
        existing.lastSeen = Date.now();
        existing.address = announcement.address;
      } else {
        // New peer — admitted only after passing enrollment authentication
        const peer: MeshPeer = {
          id: announcement.nodeId,
          address: announcement.address,
          lastSeen: Date.now(),
          hops: 1, // Via MQTT = 1 hop
          connected: true,
        };
        this.peers.set(peer.id, peer);

        this.log('info', `Peer enrolled: ${peer.id}`);
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

  private hmacHex(material: string): string {
    return createHmac('sha256', this.config.meshSecret!).update(material).digest('hex');
  }

  private constantTimeEqualHex(a: string, b: string): boolean {
    if (a.length !== 64 || b.length !== 64) return false;
    try {
      return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
    } catch {
      return false;
    }
  }

  // Canonical, unambiguous signing material. JSON-encoded fixed shape so a
  // ':'-containing id/from/to cannot be re-segmented, and a hash of the
  // payload + the type are bound in — a captured message cannot be tampered
  // or re-purposed and still verify.
  private signingMaterial(message: MeshMessage): string {
    const payloadHash = createHash('sha256')
      .update(JSON.stringify(message.payload ?? null))
      .digest('hex');
    return JSON.stringify({
      id: message.id,
      type: message.type,
      from: message.from,
      to: message.to,
      ts: message.timestamp,
      nonce: message.nonce ?? '',
      ph: payloadHash,
    });
  }

  private signMessage(message: MeshMessage): string {
    return this.hmacHex(this.signingMaterial(message));
  }

  private isFresh(timestamp: number): boolean {
    const skew = this.config.maxClockSkewMs!;
    return Math.abs(Date.now() - timestamp) <= skew;
  }

  // Records a nonce as consumed. Returns false if it was already seen
  // (replay). Bounded — old entries are evicted past the freshness window.
  private consumeNonce(nonce: string): boolean {
    if (this.seenNonces.has(nonce)) return false;
    this.seenNonces.add(nonce);
    if (this.seenNonces.size > 20000) {
      this.seenNonces = new Set(Array.from(this.seenNonces).slice(-10000));
    }
    return true;
  }

  private verifyMessage(message: MeshMessage): boolean {
    if (!this.config.meshSecret) return true; // signing disabled (dev mode)
    if (!message.hmac || !message.nonce) return false;
    if (!this.isFresh(message.timestamp)) return false;
    const expected = this.signMessage(message);
    if (!this.constantTimeEqualHex(message.hmac, expected)) return false;
    // Signature valid — enforce single-use to defeat replay.
    return this.consumeNonce(`msg:${message.nonce}`);
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
      message.nonce = randomBytes(16).toString('hex');
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
