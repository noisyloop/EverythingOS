// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - MCP Stdio Transport
// Spawns an MCP server as a child process and communicates over
// stdin/stdout using newline-delimited JSON (ndjson).
// ═══════════════════════════════════════════════════════════════════════════════

import { spawn, ChildProcess } from 'child_process';
import { eventBus } from '../../../core/event-bus/EventBus';
import { MCPTransportBase } from './MCPTransportBase';
import { JSONRPCRequest, JSONRPCNotification } from '../MCPTypes';

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

export interface MCPStdioConfig {
  /** Executable to run, e.g. 'python', 'node', '/usr/local/bin/mcp-server' */
  command: string;
  /** Command-line arguments */
  args?: string[];
  /** Extra environment variables merged on top of process.env */
  env?: Record<string, string>;
  /** Working directory for the child process */
  cwd?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stdio Transport
// ─────────────────────────────────────────────────────────────────────────────

export class MCPStdioTransport extends MCPTransportBase {
  private config: MCPStdioConfig;
  private process: ChildProcess | null = null;
  /** Accumulated stdout bytes not yet newline-terminated */
  private lineBuffer = '';

  constructor(clientId: string, config: MCPStdioConfig) {
    super(clientId);
    this.config = config;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  async connect(): Promise<void> {
    if (this.status === 'connected') return;
    this.status = 'connecting';

    return new Promise<void>((resolve, reject) => {
      const proc = spawn(this.config.command, this.config.args ?? [], {
        env: { ...process.env, ...(this.config.env ?? {}) },
        cwd:  this.config.cwd,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      // ── stdout: parse newline-delimited JSON ─────────────────────────────
      proc.stdout!.on('data', (chunk: Buffer) => {
        this.lineBuffer += chunk.toString('utf8');
        let newlineIdx: number;
        while ((newlineIdx = this.lineBuffer.indexOf('\n')) !== -1) {
          const line = this.lineBuffer.slice(0, newlineIdx).trim();
          this.lineBuffer = this.lineBuffer.slice(newlineIdx + 1);
          if (!line) continue;
          try {
            const msg = JSON.parse(line);
            this.handleMessage(msg);
          } catch {
            this.handleError(new Error(`MCP stdio: JSON parse error — ${line}`));
          }
        }
      });

      // ── stderr: forward as debug events (servers use it for logs) ───────
      proc.stderr!.on('data', (chunk: Buffer) => {
        eventBus.emit(`mcp:${this.clientId}:stderr`, {
          text: chunk.toString('utf8'),
        });
      });

      // ── process events ───────────────────────────────────────────────────
      proc.on('spawn', () => {
        this.process = proc;
        this.status = 'connected';
        resolve();
      });

      proc.on('error', (err) => {
        if (this.status === 'connecting') {
          this.status = 'error';
          reject(err);
        } else {
          this.handleError(err);
        }
      });

      proc.on('exit', (code, signal) => {
        this.process = null;
        if (this.status === 'connecting') {
          reject(new Error(`MCP process exited before connecting (${signal ?? `code ${code}`})`));
        } else {
          this.handleClose();
        }
      });
    });
  }

  async disconnect(): Promise<void> {
    if (!this.process) return;

    // Close stdin so the server can shut down gracefully, then SIGTERM
    try { this.process.stdin?.end(); } catch { /* ignore */ }

    // Remove listeners before kill so the 'exit' handler won't call handleClose
    // — we're calling it manually right after.
    this.process.stdout?.removeAllListeners();
    this.process.stderr?.removeAllListeners();
    this.process.removeAllListeners();
    this.process.kill('SIGTERM');
    this.process = null;

    this.handleClose();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Sending
  // ─────────────────────────────────────────────────────────────────────────

  async send(message: JSONRPCRequest | JSONRPCNotification): Promise<void> {
    if (!this.process?.stdin) {
      throw new Error('MCPStdioTransport: not connected (stdin unavailable)');
    }

    const line = JSON.stringify(message) + '\n';
    await new Promise<void>((resolve, reject) => {
      this.process!.stdin!.write(line, 'utf8', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}
