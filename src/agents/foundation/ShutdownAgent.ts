// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Shutdown Agent
// Graceful shutdown coordination for the entire system
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent, AgentConfig } from '../../runtime/Agent';
import { AgentRiskTier } from '../../types/agent-risk';
import { agentRegistry } from '../../core/registry/AgentRegistry';
import { snapshotManager } from '../../core/state/SnapshotManager';

export interface ShutdownConfig {
  timeout: number;
  createSnapshot: boolean;
  stopOrder?: string[];
  skipAgents?: string[];
}

export interface ShutdownProgress {
  phase: ShutdownPhase;
  agentsStopped: number;
  agentsTotal: number;
  currentAgent?: string;
  errors: string[];
  startTime: number;
  elapsed: number;
}

export type ShutdownPhase =
  | 'idle'
  | 'initiated'
  | 'snapshot'
  | 'stopping_agents'
  | 'cleanup'
  | 'complete'
  | 'forced';

export class ShutdownAgent extends Agent {
  private shutdownConfig: ShutdownConfig;
  private phase: ShutdownPhase = 'idle';
  private shutdownPromise?: Promise<void>;
  private shutdownResolve?: () => void;
  private progress: ShutdownProgress;
  private signalHandlersInstalled = false;

  constructor(agentConfig?: Partial<AgentConfig>, shutdownConfig?: Partial<ShutdownConfig>) {
    super({
      id: 'shutdown',
      name: 'Shutdown Agent',
      type: 'foundation',
      description: 'Coordinates graceful system shutdown',
      tickRate: 0,
      riskConfig: {
        tier: AgentRiskTier.LOW,
        riskJustification: 'Foundation shutdown coordinator — orchestrates clean exit',
        allowedPublishChannels: [
          'shutdown:initiated', 'shutdown:snapshot', 'shutdown:agent:stopped',
          'shutdown:agent:error', 'shutdown:cleanup', 'shutdown:complete',
          'shutdown:forced', 'shutdown:progress',
        ],
        allowedSubscribeChannels: ['system:shutdown'],
      },
      ...agentConfig,
    });

    this.shutdownConfig = {
      timeout: 30000,
      createSnapshot: true,
      stopOrder: [],
      skipAgents: ['shutdown'],
      ...shutdownConfig,
    };

    this.progress = this.createInitialProgress();
  }

  protected async onStart(): Promise<void> {
    this.subscribe('system:shutdown', async (event) => {
      const { force, reason } = event.payload as { force?: boolean; reason?: string };
      await this.initiateShutdown(force, reason);
    });

    this.installSignalHandlers();
    this.log('info', 'Shutdown agent started');
  }

  protected async onStop(): Promise<void> {
    this.removeSignalHandlers();
    this.log('info', 'Shutdown agent stopped');
  }

  protected async onTick(): Promise<void> {}

  private installSignalHandlers(): void {
    if (this.signalHandlersInstalled) return;

    const handleSignal = (signal: string) => {
      this.log('info', `Received ${signal} signal`);
      this.initiateShutdown(false, `Signal: ${signal}`);
    };

    process.on('SIGINT', () => handleSignal('SIGINT'));
    process.on('SIGTERM', () => handleSignal('SIGTERM'));

    process.on('uncaughtException', (error) => {
      this.log('error', `Uncaught exception: ${error.message}`);
      this.initiateShutdown(true, `Uncaught exception: ${error.message}`);
    });

    process.on('unhandledRejection', (reason) => {
      this.log('error', `Unhandled rejection: ${reason}`);
    });

    this.signalHandlersInstalled = true;
  }

  private removeSignalHandlers(): void {
    this.signalHandlersInstalled = false;
  }

  async initiateShutdown(force = false, reason?: string): Promise<void> {
    if (this.phase !== 'idle') {
      this.log('warn', 'Shutdown already in progress');
      return this.shutdownPromise;
    }

    this.phase = 'initiated';
    this.progress = this.createInitialProgress();
    this.progress.phase = 'initiated';

    this.log('info', `Shutdown initiated${reason ? `: ${reason}` : ''}`);
    this.emit('shutdown:initiated', { reason, force });

    this.shutdownPromise = new Promise<void>((resolve) => {
      this.shutdownResolve = resolve;
    });

    const timeoutId = setTimeout(() => {
      if (this.phase !== 'complete') {
        this.log('warn', 'Shutdown timeout reached, forcing shutdown');
        this.forceShutdown();
      }
    }, this.shutdownConfig.timeout);

    try {
      if (force) {
        await this.forceShutdown();
      } else {
        await this.gracefulShutdown();
      }
    } finally {
      clearTimeout(timeoutId);
    }

    return this.shutdownPromise;
  }

  private async gracefulShutdown(): Promise<void> {
    const startTime = Date.now();

    if (this.shutdownConfig.createSnapshot) {
      this.updatePhase('snapshot');
      try {
        const snapshot = snapshotManager.takeSnapshot('pre-shutdown');
        this.log('info', `Snapshot created: ${snapshot.id}`);
        this.emit('shutdown:snapshot', { snapshotId: snapshot.id });
      } catch (error) {
        this.log('warn', `Snapshot failed: ${error}`);
        this.progress.errors.push(`Snapshot: ${error}`);
      }
    }

    this.updatePhase('stopping_agents');
    await this.stopAllAgents();

    this.updatePhase('cleanup');
    await this.cleanup();

    this.updatePhase('complete');
    this.progress.elapsed = Date.now() - startTime;

    this.log('info', `Graceful shutdown complete (${this.progress.elapsed}ms)`);
    this.emit('shutdown:complete', { elapsed: this.progress.elapsed, errors: this.progress.errors });

    this.shutdownResolve?.();
  }

  private async forceShutdown(): Promise<void> {
    this.updatePhase('forced');
    this.log('warn', 'Forcing immediate shutdown');
    this.emit('shutdown:forced', {});

    const agents = agentRegistry.getAll();
    await Promise.allSettled(
      agents.map(agent => agent.stop().catch(() => {}))
    );

    this.updatePhase('complete');
    this.shutdownResolve?.();
  }

  private async stopAllAgents(): Promise<void> {
    const allAgents = agentRegistry.getAll();
    const skipSet = new Set(this.shutdownConfig.skipAgents);

    const orderedIds = [...(this.shutdownConfig.stopOrder ?? [])];
    const remainingAgents = allAgents.filter(
      a => !skipSet.has(a.getId()) && !orderedIds.includes(a.getId())
    );

    for (const agent of remainingAgents.reverse()) {
      orderedIds.push(agent.getId());
    }

    this.progress.agentsTotal = orderedIds.length;

    for (const agentId of orderedIds) {
      if (skipSet.has(agentId)) continue;

      const agent = agentRegistry.get(agentId);
      if (!agent) continue;

      this.progress.currentAgent = agentId;
      this.emitProgress();

      try {
        this.log('debug', `Stopping agent: ${agentId}`);
        await agent.stop();
        this.progress.agentsStopped++;
        this.emit('shutdown:agent:stopped', { agentId });
      } catch (error) {
        const errorMsg = `Failed to stop ${agentId}: ${error}`;
        this.log('error', errorMsg);
        this.progress.errors.push(errorMsg);
        this.emit('shutdown:agent:error', { agentId, error: String(error) });
      }
    }

    this.progress.currentAgent = undefined;
  }

  private async cleanup(): Promise<void> {
    this.emit('shutdown:cleanup', {});
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  private createInitialProgress(): ShutdownProgress {
    return {
      phase: 'idle',
      agentsStopped: 0,
      agentsTotal: 0,
      errors: [],
      startTime: Date.now(),
      elapsed: 0,
    };
  }

  private updatePhase(phase: ShutdownPhase): void {
    this.phase = phase;
    this.progress.phase = phase;
    this.progress.elapsed = Date.now() - this.progress.startTime;
    this.emitProgress();
  }

  private emitProgress(): void {
    this.emit('shutdown:progress', { ...this.progress });
  }

  getPhase(): ShutdownPhase { return this.phase; }
  getProgress(): ShutdownProgress { return { ...this.progress }; }
  isShuttingDown(): boolean { return this.phase !== 'idle' && this.phase !== 'complete'; }
  setShutdownConfig(config: Partial<ShutdownConfig>): void { Object.assign(this.shutdownConfig, config); }

  async shutdown(options?: { force?: boolean; reason?: string }): Promise<void> {
    return this.initiateShutdown(options?.force, options?.reason);
  }
}
