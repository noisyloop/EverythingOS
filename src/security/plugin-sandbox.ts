/**
 * Plugin Sandbox — Worker Thread Isolation
 *
 * NIST AI RMF 1.0 — MANAGE (MG-2.4), GOVERN (GV-2)
 *
 * Runs plugins in a worker_threads Worker so a buggy or malicious plugin
 * cannot monkey-patch the security layer, read in-process secrets (token
 * registry, credential vault contents), or call process.exit().
 *
 * Communication is message-based — structured postMessage only.
 * A hard resource ceiling (maxOldGenerationSizeMb, maxExecutionTimeMs on
 * each call) prevents a plugin from exhausting system memory or hanging.
 *
 * Usage:
 *   const sandbox = new PluginSandbox('./plugins/my-plugin.js', { apiKey: '...' });
 *   await sandbox.start();
 *   const result = await sandbox.invoke('doWork', { input: '...' });
 *   await sandbox.stop();
 *
 * Plugin file requirements:
 *   The plugin module must call registerPluginHandlers(handlers) to expose methods:
 *
 *   import { registerPluginHandlers } from '../../security/plugin-sandbox-runtime';
 *   registerPluginHandlers({
 *     doWork: async (args) => { ... return result; },
 *   });
 */

import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { resolve } from 'path';
import { AuditLogger } from './audit-log';

// ─────────────────────────────────────────────────────────────────────────────
// Config validation — reject credential-shaped values (STRIDE I-4)
// Prevents plugins from being used as exfiltration vectors via their config.
// ─────────────────────────────────────────────────────────────────────────────

const CREDENTIAL_KEY_RE = /^(api[_-]?key|api[_-]?secret|secret[_-]?key|password|passwd|private[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|credentials?)$/i;
const CREDENTIAL_VAL_RE = /^(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}|[0-9a-f]{40,}|eyJ[A-Za-z0-9+/]{20,}={0,2})$/;

function validateConfig(obj: Record<string, unknown>, path = 'config'): void {
  for (const [key, val] of Object.entries(obj)) {
    const fullPath = `${path}.${key}`;
    if (typeof val === 'string') {
      if (CREDENTIAL_KEY_RE.test(key) && val.length > 8) {
        throw new Error(
          `[PluginSandbox] Config rejected: "${fullPath}" appears to hold a credential. ` +
          `Inject secrets via SecretsProvider at runtime, not plugin config.`
        );
      }
      if (CREDENTIAL_VAL_RE.test(val)) {
        throw new Error(
          `[PluginSandbox] Config rejected: value at "${fullPath}" matches a known credential pattern. ` +
          `Inject secrets via SecretsProvider at runtime, not plugin config.`
        );
      }
    } else if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
      validateConfig(val as Record<string, unknown>, fullPath);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Message protocol
// ─────────────────────────────────────────────────────────────────────────────

interface InvokeMessage {
  type: 'invoke';
  callId: string;
  method: string;
  args: unknown;
}

interface ResultMessage {
  type: 'result';
  callId: string;
  result: unknown;
}

interface ErrorMessage {
  type: 'error';
  callId: string;
  error: string;
}

interface ReadyMessage {
  type: 'ready';
}

type SandboxMessage = InvokeMessage | ResultMessage | ErrorMessage | ReadyMessage;

// ─────────────────────────────────────────────────────────────────────────────
// PluginSandbox — main-thread side
// ─────────────────────────────────────────────────────────────────────────────

export interface PluginSandboxOptions {
  /** Max heap size for the worker in MB. Default: 128 */
  maxHeapMb?: number;
  /** Per-call timeout in ms before the worker is killed. Default: 30s */
  callTimeoutMs?: number;
  /** Opaque config passed to the plugin as workerData.config */
  config?: Record<string, unknown>;
  /** Agent ID for audit logging */
  agentId?: string;
}

export class PluginSandbox {
  private worker: Worker | null = null;
  private pendingCalls = new Map<string, {
    resolve: (v: unknown) => void;
    reject: (e: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }>();
  private callCounter = 0;
  private readonly pluginPath: string;
  private readonly options: Required<PluginSandboxOptions>;

  constructor(pluginPath: string, opts: PluginSandboxOptions = {}) {
    this.pluginPath = resolve(pluginPath);
    const config = opts.config ?? {};
    validateConfig(config);
    this.options = {
      maxHeapMb:     opts.maxHeapMb    ?? 128,
      callTimeoutMs: opts.callTimeoutMs ?? 30_000,
      config,
      agentId:       opts.agentId       ?? 'plugin-sandbox',
    };
  }

  /** Start the sandboxed worker. Resolves when the plugin signals ready. */
  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const readyTimer = setTimeout(() => {
        reject(new Error(`[PluginSandbox] Plugin did not signal ready within 10s: ${this.pluginPath}`));
      }, 10_000);

      this.worker = new Worker(this.pluginPath, {
        workerData: { config: this.options.config },
        resourceLimits: {
          maxOldGenerationSizeMb: this.options.maxHeapMb,
          maxYoungGenerationSizeMb: Math.floor(this.options.maxHeapMb / 4),
        },
      });

      this.worker.on('message', (msg: SandboxMessage) => {
        if (msg.type === 'ready') {
          clearTimeout(readyTimer);
          AuditLogger.log({
            agentId: this.options.agentId,
            event: 'agent.started',
            metadata: { action: 'plugin_sandbox_ready', path: this.pluginPath },
          });
          resolve();
          return;
        }

        if (msg.type === 'result' || msg.type === 'error') {
          const pending = this.pendingCalls.get(msg.callId);
          if (!pending) return;
          clearTimeout(pending.timer);
          this.pendingCalls.delete(msg.callId);

          if (msg.type === 'result') {
            pending.resolve(msg.result);
          } else {
            pending.reject(new Error(msg.error));
          }
        }
      });

      this.worker.on('error', (err) => {
        AuditLogger.log({
          agentId: this.options.agentId,
          event: 'agent.error',
          metadata: { action: 'plugin_sandbox_error', path: this.pluginPath, error: String(err) },
        });
        this.rejectAllPending(err);
      });

      this.worker.on('exit', (code) => {
        AuditLogger.log({
          agentId: this.options.agentId,
          event: 'agent.stopped',
          metadata: { action: 'plugin_sandbox_exit', path: this.pluginPath, exitCode: code },
        });
        if (code !== 0) {
          this.rejectAllPending(new Error(`Plugin worker exited with code ${code}`));
        }
        this.worker = null;
      });
    });
  }

  /**
   * Invoke a method on the sandboxed plugin.
   * Throws if the plugin doesn't respond within callTimeoutMs.
   */
  invoke<T = unknown>(method: string, args?: unknown): Promise<T> {
    if (!this.worker) {
      return Promise.reject(new Error('[PluginSandbox] Worker is not running. Call start() first.'));
    }

    return new Promise<T>((resolve, reject) => {
      const callId = `call_${++this.callCounter}_${Date.now()}`;

      const timer = setTimeout(() => {
        this.pendingCalls.delete(callId);
        // Kill the worker on timeout — it's unresponsive and must be replaced
        this.worker?.terminate();
        AuditLogger.log({
          agentId: this.options.agentId,
          event: 'agent.error',
          metadata: { action: 'plugin_call_timeout', method, callId },
        });
        reject(new Error(`[PluginSandbox] Call "${method}" timed out after ${this.options.callTimeoutMs}ms`));
      }, this.options.callTimeoutMs);

      this.pendingCalls.set(callId, {
        resolve: (v) => resolve(v as T),
        reject,
        timer,
      });

      const msg: InvokeMessage = { type: 'invoke', callId, method, args };
      this.worker!.postMessage(msg);
    });
  }

  /** Gracefully stop the worker. */
  async stop(): Promise<void> {
    if (!this.worker) return;
    this.rejectAllPending(new Error('[PluginSandbox] Sandbox stopped'));
    await this.worker.terminate();
    this.worker = null;
    AuditLogger.log({
      agentId: this.options.agentId,
      event: 'agent.stopped',
      metadata: { action: 'plugin_sandbox_stopped', path: this.pluginPath },
    });
  }

  get isRunning(): boolean {
    return this.worker !== null;
  }

  private rejectAllPending(err: Error): void {
    for (const [, pending] of this.pendingCalls) {
      clearTimeout(pending.timer);
      pending.reject(err);
    }
    this.pendingCalls.clear();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin runtime helpers — import these INSIDE the worker file
// ─────────────────────────────────────────────────────────────────────────────

export type PluginHandlers = Record<string, (args: unknown) => Promise<unknown> | unknown>;

/**
 * Register method handlers in the worker thread.
 * Call this once in your plugin file — it wires up the message loop
 * and signals the sandbox host that the plugin is ready.
 *
 * Example plugin file:
 *   import { registerPluginHandlers } from '../security/plugin-sandbox';
 *   registerPluginHandlers({
 *     greet: async ({ name }) => `Hello, ${name}!`,
 *   });
 */
export function registerPluginHandlers(handlers: PluginHandlers): void {
  if (isMainThread) {
    throw new Error('[PluginSandbox] registerPluginHandlers() must be called from a worker thread, not the main thread.');
  }

  if (!parentPort) {
    throw new Error('[PluginSandbox] parentPort is not available.');
  }

  parentPort.on('message', async (msg: SandboxMessage) => {
    if (msg.type !== 'invoke') return;

    const handler = handlers[msg.method];
    if (!handler) {
      const errMsg: ErrorMessage = {
        type: 'error',
        callId: msg.callId,
        error: `Unknown method: ${msg.method}`,
      };
      parentPort!.postMessage(errMsg);
      return;
    }

    try {
      const result = await handler(msg.args);
      const resultMsg: ResultMessage = { type: 'result', callId: msg.callId, result };
      parentPort!.postMessage(resultMsg);
    } catch (err) {
      const errMsg: ErrorMessage = {
        type: 'error',
        callId: msg.callId,
        error: err instanceof Error ? err.message : String(err),
      };
      parentPort!.postMessage(errMsg);
    }
  });

  // Signal to the host that we are ready to receive calls
  const readyMsg: ReadyMessage = { type: 'ready' };
  parentPort.postMessage(readyMsg);
}
