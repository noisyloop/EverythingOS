/**
 * Isolated Agent Worker Runtime
 *
 * NIST AI RMF 1.0 — MANAGE (MG-2.2), GOVERN (GV-2)
 * STRIDE E-2: HIGH-tier agents run in a separate V8 heap so they cannot
 * directly access the main thread's token registry, secrets, or credential vault.
 *
 * This module runs inside a worker_thread. It:
 *   1. Patches EventBus.emit() to proxy events UP to the main thread via postMessage
 *   2. Receives forwarded events from the main thread and delivers them to the local bus
 *   3. Dynamically imports and starts the agent class specified in workerData
 *
 * The agent code runs normally — it doesn't know it's in a worker.
 * The main thread bridges the EventBus boundary.
 */

import { parentPort, workerData } from 'worker_threads';
import { eventBus } from '../core/event-bus/EventBus';

interface WorkerMessage {
  type: 'eventbus:deliver' | 'agent:start' | 'agent:stop';
  eventType?: string;
  payload?: unknown;
  options?: Record<string, unknown>;
}

// Keep a reference to the original emit before patching
const _originalEmit = eventBus.emit.bind(eventBus) as typeof eventBus.emit;

// Patch emit — proxy to main thread instead of local dispatch
(eventBus as unknown as { emit: typeof eventBus.emit }).emit = <T>(
  type: string,
  payload: T,
  options: Partial<Parameters<typeof eventBus.emit>[2]> = {},
) => {
  parentPort?.postMessage({ type: 'eventbus:emit', eventType: type, payload, options });
  return '';
};

// Receive events forwarded from the main thread and deliver them locally
parentPort?.on('message', async (msg: WorkerMessage) => {
  switch (msg.type) {
    case 'eventbus:deliver':
      if (msg.eventType !== undefined) {
        _originalEmit(msg.eventType, msg.payload, msg.options ?? {});
      }
      break;

    case 'agent:start': {
      try {
        const { agentModulePath, agentConfig } = workerData as {
          agentModulePath: string;
          agentConfig?: unknown;
        };

        const mod = await import(agentModulePath) as Record<string, unknown>;

        // Find the exported agent class — prefer default export, then first function export
        const AgentClass = (mod.default ?? Object.values(mod).find((v) => typeof v === 'function')) as (new (cfg: unknown) => { start(): Promise<void>; stop(): Promise<void> }) | undefined;
        if (!AgentClass) {
          throw new Error(`[IsolatedWorker] No exported class found in ${agentModulePath}`);
        }

        const agent = new AgentClass(agentConfig);
        await agent.start();

        parentPort?.postMessage({ type: 'agent:started' });
      } catch (err) {
        parentPort?.postMessage({ type: 'agent:error', error: String(err) });
        process.exit(1);
      }
      break;
    }

    case 'agent:stop':
      process.exit(0);
      break;
  }
});
