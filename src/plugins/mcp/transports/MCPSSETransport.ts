// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - MCP SSE Transport
// HTTP + Server-Sent Events transport for MCP.
//
// Protocol:
//   1. Client opens a persistent GET /sse connection.
//   2. Server sends an `endpoint` SSE event whose data is the URL to POST to.
//   3. Client POSTs JSON-RPC requests to that URL.
//   4. Server streams JSON-RPC responses/notifications back on the SSE channel.
// ═══════════════════════════════════════════════════════════════════════════════

import { MCPTransportBase } from './MCPTransportBase';
import { JSONRPCRequest, JSONRPCNotification } from '../MCPTypes';

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

export interface MCPSSEConfig {
  /** URL of the MCP server's SSE endpoint (GET /sse) */
  serverUrl: string;
  /** Extra headers sent on both SSE and POST requests (auth tokens, etc.) */
  headers?: Record<string, string>;
  /** Timeout (ms) waiting for the server `endpoint` event on connect */
  connectTimeout?: number;
  /** Timeout (ms) for individual POST requests */
  requestTimeout?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// SSE Transport
// ─────────────────────────────────────────────────────────────────────────────

export class MCPSSETransport extends MCPTransportBase {
  private config: Required<MCPSSEConfig>;

  /** URL to POST requests to — populated from the server `endpoint` SSE event */
  private postEndpoint: string | null = null;
  private sseController: AbortController | null = null;

  /** Resolves with the POST endpoint URL once the server sends it */
  private endpointResolve: ((url: string) => void) | null = null;
  private endpointReject:  ((err: Error)    => void) | null = null;

  constructor(clientId: string, config: MCPSSEConfig) {
    super(clientId);
    this.config = {
      headers:        config.headers        ?? {},
      connectTimeout: config.connectTimeout ?? 10_000,
      requestTimeout: config.requestTimeout ?? 30_000,
      ...config,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  async connect(): Promise<void> {
    if (this.status === 'connected') return;
    this.status = 'connecting';

    // Promise that resolves when the server sends the `endpoint` SSE event.
    const endpointReady = new Promise<string>((resolve, reject) => {
      this.endpointResolve = resolve;
      this.endpointReject  = reject;
    });

    this.sseController = new AbortController();

    // Start streaming in the background — we'll await the endpoint URL below.
    this.runSSEStream().catch((err) => {
      const error = err instanceof Error ? err : new Error(String(err));
      if (this.endpointReject) {
        this.endpointReject(error);
        this.endpointReject = null;
        this.endpointResolve = null;
      } else {
        this.handleError(error);
      }
    });

    // Wait until the server tells us where to POST, or timeout.
    const endpoint = await Promise.race([
      endpointReady,
      new Promise<string>((_, reject) =>
        setTimeout(
          () => reject(new Error('MCPSSETransport: connect timeout — no endpoint received')),
          this.config.connectTimeout,
        )
      ),
    ]);

    this.postEndpoint = endpoint;
    this.status = 'connected';
  }

  async disconnect(): Promise<void> {
    this.sseController?.abort();
    this.sseController  = null;
    this.postEndpoint   = null;
    this.endpointResolve = null;
    this.endpointReject  = null;
    this.handleClose();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Sending
  // ─────────────────────────────────────────────────────────────────────────

  async send(message: JSONRPCRequest | JSONRPCNotification): Promise<void> {
    if (this.status !== 'connected') {
      throw new Error(`MCPSSETransport: not connected (status: ${this.status})`);
    }

    const url = this.postEndpoint!;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeout);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.config.headers,
        },
        body:   JSON.stringify(message),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`MCPSSETransport: POST failed — HTTP ${response.status} ${response.statusText}`);
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // SSE Stream Processing
  // ─────────────────────────────────────────────────────────────────────────

  private async runSSEStream(): Promise<void> {
    const response = await fetch(this.config.serverUrl, {
      method:  'GET',
      headers: {
        'Accept':        'text/event-stream',
        'Cache-Control': 'no-cache',
        ...this.config.headers,
      },
      signal: this.sseController!.signal,
    });

    if (!response.ok) {
      throw new Error(
        `MCPSSETransport: SSE connection failed — HTTP ${response.status} ${response.statusText}`,
      );
    }

    if (!response.body) {
      throw new Error('MCPSSETransport: SSE response has no body');
    }

    await this.parseSSEStream(response.body);
  }

  private async parseSSEStream(body: ReadableStream<Uint8Array>): Promise<void> {
    const reader  = body.getReader();
    const decoder = new TextDecoder();

    let buffer    = '';
    let eventType = '';
    let eventData = '';

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        // Process complete lines
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? ''; // keep the incomplete trailing line

        for (const raw of lines) {
          const line = raw.replace(/\r$/, ''); // strip CRLF

          if (line.startsWith('event:')) {
            eventType = line.slice(6).trim();
          } else if (line.startsWith('data:')) {
            eventData += line.slice(5).trim();
          } else if (line === '') {
            // Blank line → dispatch accumulated event
            if (eventData) {
              this.dispatchSSEEvent(eventType, eventData);
            }
            eventType = '';
            eventData = '';
          }
          // Lines starting with ':' are SSE comments — ignore.
        }
      }
    } finally {
      reader.releaseLock();
      // Stream ended (server closed or abort)
      if (this.status !== 'disconnected') {
        this.handleClose();
      }
    }
  }

  private dispatchSSEEvent(type: string, data: string): void {
    // ── endpoint event: server tells us where to POST ─────────────────────
    if (type === 'endpoint') {
      const url = data.trim();
      if (this.endpointResolve) {
        this.endpointResolve(url);
        this.endpointResolve = null;
        this.endpointReject  = null;
      } else {
        // POST endpoint changed after initial connect — update in place
        this.postEndpoint = url;
      }
      return;
    }

    // ── message event: JSON-RPC from server ───────────────────────────────
    if (type === 'message' || type === '') {
      try {
        const msg = JSON.parse(data);
        this.handleMessage(msg);
      } catch {
        this.handleError(new Error(`MCPSSETransport: JSON parse error — ${data}`));
      }
    }
    // Other custom event types are silently ignored for forward-compatibility.
  }
}
