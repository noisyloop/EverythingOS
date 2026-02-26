// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - MCP Transport Base
// Abstract base for all MCP transports (stdio, SSE).
// Handles message/error/close dispatch and EventBus integration.
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../../core/event-bus/EventBus';
import {
  JSONRPCRequest,
  JSONRPCNotification,
  JSONRPCResponse,
} from '../MCPTypes';

// ─────────────────────────────────────────────────────────────────────────────
// Transport Types
// ─────────────────────────────────────────────────────────────────────────────

export type MCPTransportStatus = 'disconnected' | 'connecting' | 'connected' | 'error';

/**
 * Any message arriving from the MCP server is either a JSON-RPC response
 * (has an `id`) or a JSON-RPC notification (no `id`).
 */
export type MCPIncomingMessage = JSONRPCResponse | JSONRPCNotification;

// ─────────────────────────────────────────────────────────────────────────────
// Abstract Transport Base
// ─────────────────────────────────────────────────────────────────────────────

export abstract class MCPTransportBase {
  protected clientId: string;
  protected status: MCPTransportStatus = 'disconnected';

  private messageHandlers: Array<(msg: MCPIncomingMessage) => void> = [];
  private errorHandlers:   Array<(err: Error) => void> = [];
  private closeHandlers:   Array<() => void> = [];

  constructor(clientId: string) {
    this.clientId = clientId;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Abstract Interface — implement in subclass
  // ─────────────────────────────────────────────────────────────────────────

  /** Establish the connection to the MCP server. */
  abstract connect(): Promise<void>;

  /** Tear down the connection cleanly. */
  abstract disconnect(): Promise<void>;

  /**
   * Send a JSON-RPC request or notification to the server.
   * Requests have an `id`; notifications do not.
   */
  abstract send(message: JSONRPCRequest | JSONRPCNotification): Promise<void>;

  // ─────────────────────────────────────────────────────────────────────────
  // Status
  // ─────────────────────────────────────────────────────────────────────────

  isConnected(): boolean {
    return this.status === 'connected';
  }

  getStatus(): MCPTransportStatus {
    return this.status;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Event Registration
  // Consumers register handlers here; subclasses fire them via the protected
  // helpers below.  All events are also forwarded onto the EventBus so that
  // the rest of EverythingOS can observe MCP activity.
  // ─────────────────────────────────────────────────────────────────────────

  onMessage(handler: (msg: MCPIncomingMessage) => void): () => void {
    this.messageHandlers.push(handler);
    return () => {
      const idx = this.messageHandlers.indexOf(handler);
      if (idx > -1) this.messageHandlers.splice(idx, 1);
    };
  }

  onError(handler: (err: Error) => void): () => void {
    this.errorHandlers.push(handler);
    return () => {
      const idx = this.errorHandlers.indexOf(handler);
      if (idx > -1) this.errorHandlers.splice(idx, 1);
    };
  }

  onClose(handler: () => void): () => void {
    this.closeHandlers.push(handler);
    return () => {
      const idx = this.closeHandlers.indexOf(handler);
      if (idx > -1) this.closeHandlers.splice(idx, 1);
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Protected Dispatch Helpers — call from subclass
  // ─────────────────────────────────────────────────────────────────────────

  protected handleMessage(msg: MCPIncomingMessage): void {
    for (const handler of this.messageHandlers) {
      try { handler(msg); } catch { /* handler errors must not propagate */ }
    }
    // Broadcast on EventBus for observability
    eventBus.emit(`mcp:${this.clientId}:message`, msg);
  }

  protected handleError(error: Error): void {
    this.status = 'error';
    for (const handler of this.errorHandlers) {
      try { handler(error); } catch { /* handler errors must not propagate */ }
    }
    eventBus.emit(`mcp:${this.clientId}:error`, { error: error.message });
    eventBus.emit('mcp:error', { clientId: this.clientId, error: error.message });
  }

  /**
   * Signal that the transport has closed.
   * Guards against double-firing: if already disconnected, this is a no-op.
   */
  protected handleClose(): void {
    if (this.status === 'disconnected') return;
    this.status = 'disconnected';
    for (const handler of this.closeHandlers) {
      try { handler(); } catch { /* handler errors must not propagate */ }
    }
    eventBus.emit(`mcp:${this.clientId}:close`, {});
    eventBus.emit('mcp:disconnected', { clientId: this.clientId });
  }
}
