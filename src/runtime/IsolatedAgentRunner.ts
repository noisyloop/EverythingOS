/**
 * Isolated Agent Runner
 *
 * NIST AI RMF 1.0 — MANAGE (MG-2.2), GOVERN (GV-2)
 * STRIDE E-2: Runs HIGH-tier agents in a dedicated worker_thread so they
 * cannot access the main thread's V8 heap — token registry, credential vault,
 * and secrets are invisible to the isolated agent.
 *
 * The runner bridges the two EventBus instances:
 *   main → worker: all events are forwarded via postMessage
 *   worker → main: emit() proxied through postMessage, re-emitted on main bus
 *
 * Usage:
 *   const runner = new IsolatedAgentRunner();
 *   await runner.start({
 *     agentModulePath: require.resolve('./agents/MyHighTierAgent'),
 *     agentConfig: { id: 'high-agent', ... },
 *   });
 *   // later...
 *   await runner.stop();
 */

import { Worker } from 'worker_threads';
import { resolve } from 'path';
import { eventBus } from '../core/event-bus/EventBus';

export interface IsolatedAgentOptions {
  /** Absolute path to the agent module. Must export a class as default or named export. */
  agentModulePath: string;
  /** Serializable config object passed to the agent constructor inside the worker. */
  agentConfig?: unknown;
  /** Start timeout in ms (default: 30 000). */
  startTimeoutMs?: number;
}

export class IsolatedAgentRunner {
  private worker: Worker | null = null;
  private busUnsubscribe: (() => void) | null = null;

  async start(options: IsolatedAgentOptions): Promise<void> {
    if (this.worker) throw new Error('[IsolatedAgentRunner] Already started. Call stop() first.');

    const workerScript = resolve(__dirname, './isolated-agent-worker-runtime.js');

    this.worker = new Worker(workerScript, {
      workerData: {
        agentModulePath: resolve(options.agentModulePath),
        agentConfig: options.agentConfig ?? {},
      },
    });

    this.worker.on('error', (err) => {
      console.error('[IsolatedAgentRunner] Worker error:', err);
      eventBus.emit('agent:error', { error: String(err), source: 'isolated-worker' });
    });

    // Forward worker EventBus emissions to the main EventBus
    this.worker.on('message', (msg: { type: string; eventType?: string; payload?: unknown; options?: Record<string, unknown>; error?: string }) => {
      if (msg.type === 'eventbus:emit' && msg.eventType) {
        try {
          eventBus.emit(msg.eventType, msg.payload, { ...(msg.options ?? {}), source: 'isolated-worker' });
        } catch {
          // Swallow — worker may emit to channels the main bus rate-limits
        }
      }
    });

    // Forward all main EventBus events down to the worker
    const unsub = eventBus.on('*', (event) => {
      if (this.worker) {
        this.worker.postMessage({
          type: 'eventbus:deliver',
          eventType: event.type,
          payload: event.payload,
        });
      }
    });
    this.busUnsubscribe = unsub;

    // Signal the worker to start its agent and wait for confirmation
    const startTimeout = options.startTimeoutMs ?? 30_000;
    await new Promise<void>((res, rej) => {
      const timer = setTimeout(
        () => rej(new Error(`[IsolatedAgentRunner] Agent start timed out after ${startTimeout}ms`)),
        startTimeout,
      );

      const onMsg = (msg: { type: string; error?: string }) => {
        if (msg.type === 'agent:started') {
          clearTimeout(timer);
          this.worker!.off('message', onMsg);
          res();
        } else if (msg.type === 'agent:error') {
          clearTimeout(timer);
          this.worker!.off('message', onMsg);
          rej(new Error(`[IsolatedAgentRunner] Worker agent failed to start: ${msg.error ?? 'unknown'}`));
        }
      };

      this.worker!.on('message', onMsg);
      this.worker!.postMessage({ type: 'agent:start' });
    });
  }

  async stop(): Promise<void> {
    if (this.busUnsubscribe) {
      this.busUnsubscribe();
      this.busUnsubscribe = null;
    }

    if (this.worker) {
      this.worker.postMessage({ type: 'agent:stop' });

      await new Promise<void>((res) => {
        const forceKill = setTimeout(() => {
          this.worker?.terminate();
          res();
        }, 5_000);

        this.worker!.once('exit', () => {
          clearTimeout(forceKill);
          res();
        });
      });

      this.worker = null;
    }
  }

  isRunning(): boolean {
    return this.worker !== null;
  }
}
