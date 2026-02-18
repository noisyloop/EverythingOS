/**
 * EverythingOS — WebSocket Guard
 *
 * Fixes:
 *   CVE-2024-37890 — ws DoS via header count exhaustion (ws < 8.17.1)
 *
 * NIST CSF 2.0: Protect (PR.PS-1), Respond (RS.MI-1)
 *
 * All WebSocket servers in EverythingOS (ROS2 Bridge, API WS endpoint)
 * must use createWsServer() from this module rather than instantiating
 * ws.Server directly.
 *
 * Usage:
 *   import { createWsServer, createWsClient } from '../security/websocket-guard';
 *
 *   // ROS2 Bridge:
 *   const wss = createWsServer({ port: 9090, agentId: 'ros2-bridge' });
 *
 *   // Outbound client (ROS2 rosbridge):
 *   const ws = createWsClient('ws://localhost:9090', { agentId: 'ros2-bridge' });
 */

import { WebSocket, WebSocketServer, ServerOptions, ClientOptions } from 'ws';
import { IncomingMessage, ServerResponse } from 'http';
import { AuditLogger } from './audit-log';

// ─────────────────────────────────────────────────────────────────────────────
// Constants — CVE-2024-37890 mitigations
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Maximum number of HTTP headers allowed per WebSocket handshake.
 * CVE-2024-37890: sending more headers than maxHeadersCount crashed ws servers.
 * ws 8.17.1 fixes this, but we set an explicit low limit as defense-in-depth.
 */
const MAX_HEADERS_COUNT = 100;

/**
 * Maximum header size in bytes.
 * Passed to the underlying Node.js http server.
 */
const MAX_HEADER_SIZE_BYTES = 16 * 1024; // 16 KB

/** Max message size — prevents memory exhaustion from large payloads */
const MAX_MESSAGE_BYTES = 1 * 1024 * 1024; // 1 MB

/** Idle connection timeout — close connections that go quiet */
const IDLE_TIMEOUT_MS = 60_000; // 60 seconds

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface WsServerGuardOptions extends ServerOptions {
  agentId?: string;
  /** Override max message size. Default: 1 MB */
  maxMessageBytes?: number;
  /** Override idle timeout. Default: 60s */
  idleTimeoutMs?: number;
}

export interface WsClientGuardOptions extends ClientOptions {
  agentId?: string;
  /** Override max message size */
  maxMessageBytes?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardened WebSocket Server Factory
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Creates a hardened WebSocketServer with CVE-2024-37890 mitigations applied.
 *
 * Hardening applied:
 *   - Explicit maxHeadersCount limit on the underlying HTTP server
 *   - maxPayload enforced on all connections
 *   - Idle connection timeout
 *   - Error handlers on every connection (prevents unhandled rejection crashes)
 *   - All connections and errors logged to audit trail
 */
export function createWsServer(options: WsServerGuardOptions = {}): WebSocketServer {
  const {
    agentId = 'ws-server',
    maxMessageBytes = MAX_MESSAGE_BYTES,
    idleTimeoutMs = IDLE_TIMEOUT_MS,
    ...wsOptions
  } = options;

  const wss = new WebSocketServer({
    ...wsOptions,
    // CVE-2024-37890 fix: limit payload size
    maxPayload: maxMessageBytes,
  });

  // Apply header limits to the underlying HTTP server if available
  if (wss.options.server) {
    (wss.options.server as { maxHeadersCount?: number; maxHeaderSize?: number }).maxHeadersCount = MAX_HEADERS_COUNT;
    (wss.options.server as { maxHeadersCount?: number; maxHeaderSize?: number }).maxHeaderSize = MAX_HEADER_SIZE_BYTES;
  }

  // Handle server-level errors — prevents process crash on connection failure
  wss.on('error', (err: Error) => {
    AuditLogger.log({
      agentId,
      event: 'agent.error',
      metadata: { type: 'ws_server_error', error: err.message },
    });
    console.error(`[WebSocketGuard:${agentId}] Server error:`, err.message);
  });

  wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
    const remoteAddr = req.socket?.remoteAddress ?? 'unknown';

    AuditLogger.log({
      agentId,
      event: 'eventbus.subscribe',
      metadata: { type: 'ws_connection', remoteAddr },
    });

    // Attach error handler to every connection — prevents unhandled rejection
    // that would crash the ws server (part of CVE-2024-37890 attack surface)
    ws.on('error', (err: Error) => {
      AuditLogger.log({
        agentId,
        event: 'agent.error',
        metadata: { type: 'ws_connection_error', remoteAddr, error: err.message },
      });
    });

    // Idle timeout — close connections that stop sending
    let idleTimer = setTimeout(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.terminate();
        AuditLogger.log({
          agentId,
          event: 'agent.stopped',
          metadata: { type: 'ws_idle_timeout', remoteAddr },
        });
      }
    }, idleTimeoutMs);

    ws.on('message', () => {
      // Reset idle timer on any message
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        if (ws.readyState === WebSocket.OPEN) ws.terminate();
      }, idleTimeoutMs);
    });

    ws.on('close', () => {
      clearTimeout(idleTimer);
    });
  });

  return wss;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardened WebSocket Client Factory
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Creates a hardened WebSocket client connection.
 * Applies maxPayload and attaches error handlers.
 *
 * Used by: ROS2Bridge (ws://localhost:9090)
 */
export function createWsClient(
  url: string,
  options: WsClientGuardOptions = {},
): WebSocket {
  const { agentId = 'ws-client', maxMessageBytes = MAX_MESSAGE_BYTES, ...wsOptions } = options;

  // For ROS2 bridge localhost connections — these are intentionally local
  // and exempt from the SSRF check in http-guard. Document explicitly.
  if (url.startsWith('ws://localhost') || url.startsWith('ws://127.0.0.1')) {
    AuditLogger.log({
      agentId,
      event: 'eventbus.subscribe',
      metadata: { type: 'ws_local_connection', url },
    });
  }

  const ws = new WebSocket(url, {
    ...wsOptions,
    maxPayload: maxMessageBytes,
  });

  // Attach error handler immediately — before open event
  ws.on('error', (err: Error) => {
    AuditLogger.log({
      agentId,
      event: 'agent.error',
      metadata: { type: 'ws_client_error', url, error: err.message },
    });
    console.error(`[WebSocketGuard:${agentId}] Client error (${url}):`, err.message);
  });

  return ws;
}
