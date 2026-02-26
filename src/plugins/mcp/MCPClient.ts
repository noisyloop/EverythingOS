// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - MCP Client
// Manages the full MCP session lifecycle: connection, capability negotiation,
// JSON-RPC request/response routing, and auto-reconnection.
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../core/event-bus/EventBus';
import { MCPTransportBase, MCPIncomingMessage } from './transports/MCPTransportBase';
import {
  MCPTool,
  MCPResource,
  MCPPrompt,
  MCPClientStatus,
  MCPInitializeParams,
  MCPInitializeResult,
  MCPServerCapabilities,
  MCPToolCallResult,
  MCPReadResourceResult,
  JSONRPCRequest,
  JSONRPCNotification,
  JSONRPCResponse,
  MCP_PROTOCOL_VERSION,
} from './MCPTypes';

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

export interface MCPClientConfig {
  /** Human-readable name for this server connection, used for namespacing */
  serverName: string;
  /** MCP protocol version to advertise in the initialize handshake */
  protocolVersion?: string;
  /** Name reported to the server in clientInfo */
  clientName?: string;
  /** Version reported to the server in clientInfo */
  clientVersion?: string;
  /** Timeout (ms) for individual JSON-RPC requests */
  requestTimeout?: number;
  /** Base delay (ms) for reconnect back-off */
  reconnectDelay?: number;
  /** Maximum reconnect attempts before giving up */
  maxReconnectAttempts?: number;
  /** Whether to automatically reconnect after an unexpected disconnect */
  autoReconnect?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: pending JSON-RPC request
// ─────────────────────────────────────────────────────────────────────────────

interface PendingRequest {
  resolve: (result: unknown) => void;
  reject:  (error:  Error)   => void;
  timeout: ReturnType<typeof setTimeout>;
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Client
// ─────────────────────────────────────────────────────────────────────────────

export class MCPClient {
  private transport: MCPTransportBase;
  private config: Required<MCPClientConfig>;

  private status: MCPClientStatus = 'disconnected';
  private nextId = 1;
  private pendingRequests = new Map<string | number, PendingRequest>();
  private serverCapabilities: MCPServerCapabilities | null = null;

  private reconnectAttempts = 0;
  private reconnectTimer?: ReturnType<typeof setTimeout>;

  constructor(transport: MCPTransportBase, config: MCPClientConfig) {
    this.transport = transport;
    this.config = {
      protocolVersion:      MCP_PROTOCOL_VERSION,
      clientName:           'EverythingOS',
      clientVersion:        '1.0.0',
      requestTimeout:       30_000,
      reconnectDelay:       2_000,
      maxReconnectAttempts: 5,
      autoReconnect:        true,
      ...config,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  async connect(): Promise<void> {
    if (this.status !== 'disconnected') return;
    this.setStatus('connecting');

    this.transport.onMessage((msg) => this.handleIncoming(msg));
    this.transport.onError((err)   => this.handleTransportError(err));
    this.transport.onClose(()      => this.handleTransportClose());

    await this.transport.connect();
    await this.initialize();
  }

  async disconnect(): Promise<void> {
    this.cancelReconnect();
    this.rejectAllPending('Client disconnected');
    this.setStatus('disconnected');
    await this.transport.disconnect();
    eventBus.emit('mcp:disconnected', { serverName: this.config.serverName });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Core Protocol Operations
  // ─────────────────────────────────────────────────────────────────────────

  async listTools(): Promise<MCPTool[]> {
    const result = await this.request<{ tools: MCPTool[] }>('tools/list', {});
    return result.tools ?? [];
  }

  async callTool(name: string, args?: Record<string, unknown>): Promise<MCPToolCallResult> {
    return this.request<MCPToolCallResult>('tools/call', {
      name,
      arguments: args ?? {},
    });
  }

  async listResources(): Promise<MCPResource[]> {
    if (!this.serverCapabilities?.resources) return [];
    const result = await this.request<{ resources: MCPResource[] }>('resources/list', {});
    return result.resources ?? [];
  }

  async readResource(uri: string): Promise<MCPReadResourceResult> {
    return this.request<MCPReadResourceResult>('resources/read', { uri });
  }

  async listPrompts(): Promise<MCPPrompt[]> {
    if (!this.serverCapabilities?.prompts) return [];
    const result = await this.request<{ prompts: MCPPrompt[] }>('prompts/list', {});
    return result.prompts ?? [];
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Accessors
  // ─────────────────────────────────────────────────────────────────────────

  getStatus(): MCPClientStatus { return this.status; }
  isReady():   boolean         { return this.status === 'ready'; }
  getServerCapabilities(): MCPServerCapabilities | null { return this.serverCapabilities; }
  getServerName(): string { return this.config.serverName; }

  // ─────────────────────────────────────────────────────────────────────────
  // Initialize Handshake
  // ─────────────────────────────────────────────────────────────────────────

  private async initialize(): Promise<void> {
    this.setStatus('initializing');

    const params: MCPInitializeParams = {
      protocolVersion: this.config.protocolVersion,
      capabilities:    { roots: { listChanged: false } },
      clientInfo:      { name: this.config.clientName, version: this.config.clientVersion },
    };

    const result = await this.request<MCPInitializeResult>('initialize', params);
    this.serverCapabilities = result.capabilities;

    // Acknowledge initialization — fire-and-forget notification
    await this.notify('notifications/initialized', {});

    this.setStatus('ready');
    this.reconnectAttempts = 0;

    eventBus.emit('mcp:connected', {
      serverName:   this.config.serverName,
      serverInfo:   result.serverInfo,
      capabilities: result.capabilities,
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // JSON-RPC: Request (expects a response)
  // ─────────────────────────────────────────────────────────────────────────

  private request<T>(method: string, params: unknown): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const id = this.nextId++;

      const timeout = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`MCP request timeout: ${method} (id=${id})`));
      }, this.config.requestTimeout);

      this.pendingRequests.set(id, {
        resolve: resolve as (r: unknown) => void,
        reject,
        timeout,
      });

      const message: JSONRPCRequest = {
        jsonrpc: '2.0',
        id,
        method,
        params: params as Record<string, unknown>,
      };

      this.transport.send(message).catch((err) => {
        clearTimeout(timeout);
        this.pendingRequests.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      });
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // JSON-RPC: Notification (no response)
  // ─────────────────────────────────────────────────────────────────────────

  private async notify(method: string, params: unknown): Promise<void> {
    const message: JSONRPCNotification = {
      jsonrpc: '2.0',
      method,
      params: params as Record<string, unknown>,
    };
    await this.transport.send(message);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Incoming Message Routing
  // ─────────────────────────────────────────────────────────────────────────

  private handleIncoming(msg: MCPIncomingMessage): void {
    // Messages with an `id` are responses to our requests
    if ('id' in msg && msg.id !== undefined && msg.id !== null) {
      const response = msg as JSONRPCResponse;
      const pending  = this.pendingRequests.get(response.id);
      if (!pending) return;

      clearTimeout(pending.timeout);
      this.pendingRequests.delete(response.id);

      if (response.error) {
        pending.reject(
          new Error(`MCP error ${response.error.code}: ${response.error.message}`)
        );
      } else {
        pending.resolve(response.result);
      }
      return;
    }

    // Otherwise it's a server-initiated notification
    const notification = msg as JSONRPCNotification;
    eventBus.emit(`mcp:notification`, {
      serverName: this.config.serverName,
      method:     notification.method,
      params:     notification.params,
    });

    if (notification.method === 'notifications/tools/list_changed') {
      eventBus.emit('mcp:tool:list_changed', { serverName: this.config.serverName });
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Reconnection
  // ─────────────────────────────────────────────────────────────────────────

  private handleTransportError(err: Error): void {
    eventBus.emit('mcp:error', { serverName: this.config.serverName, error: err.message });
  }

  private handleTransportClose(): void {
    if (this.status === 'disconnected') return;
    this.setStatus('disconnected');
    this.rejectAllPending('Transport closed unexpectedly');
    eventBus.emit('mcp:disconnected', { serverName: this.config.serverName });

    if (this.config.autoReconnect && this.reconnectAttempts < this.config.maxReconnectAttempts) {
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    this.reconnectAttempts++;
    this.setStatus('reconnecting');

    const delay = this.config.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = undefined;
      try {
        await this.transport.connect();
        await this.initialize();
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        eventBus.emit('mcp:error', { serverName: this.config.serverName, error: msg });
        if (this.reconnectAttempts < this.config.maxReconnectAttempts) {
          this.scheduleReconnect();
        } else {
          this.setStatus('error');
        }
      }
    }, delay);
  }

  private cancelReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
  }

  private rejectAllPending(reason: string): void {
    for (const [id, pending] of this.pendingRequests) {
      clearTimeout(pending.timeout);
      pending.reject(new Error(reason));
      this.pendingRequests.delete(id);
    }
  }

  private setStatus(status: MCPClientStatus): void {
    const previous = this.status;
    this.status = status;
    if (previous !== status) {
      eventBus.emit('mcp:status', {
        serverName: this.config.serverName,
        previous,
        current: status,
      });
    }
  }
}
