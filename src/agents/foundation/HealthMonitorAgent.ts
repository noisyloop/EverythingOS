// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Health Monitor Agent
// System health monitoring: CPU, memory, disk, agent health, event throughput
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent, AgentConfig, AgentStatus } from '../../runtime/Agent';
import { AgentRiskTier } from '../../types/agent-risk';
import { eventBus } from '../../core/event-bus/EventBus';
import { agentRegistry } from '../../core/registry/AgentRegistry';
import { metrics } from '../../observability/MetricsCollector';

export interface SystemHealth {
  timestamp: number;
  cpu: CPUHealth;
  memory: MemoryHealth;
  disk: DiskHealth;
  process: ProcessHealth;
  agents: AgentHealthStats;
  events: EventHealth;
}

export interface CPUHealth {
  usage: number;
  loadAvg: number[];
}

export interface MemoryHealth {
  total: number;
  used: number;
  free: number;
  usagePercent: number;
  heapUsed: number;
  heapTotal: number;
}

export interface DiskHealth {
  total: number;
  used: number;
  free: number;
  usagePercent: number;
}

export interface ProcessHealth {
  pid: number;
  uptime: number;
  memoryUsage: number;
}

export interface AgentHealthStats {
  total: number;
  running: number;
  stopped: number;
  error: number;
  unhealthy: string[];
}

export interface EventHealth {
  throughput: number;
  queueSize: number;
  deadLetterCount: number;
}

export interface HealthThresholds {
  cpuWarning: number;
  cpuCritical: number;
  memoryWarning: number;
  memoryCritical: number;
  diskWarning: number;
  diskCritical: number;
}

export type SystemHealthStatus = 'healthy' | 'degraded' | 'unhealthy' | 'critical';

export class HealthMonitorAgent extends Agent {
  private thresholds: HealthThresholds;
  private lastHealth?: SystemHealth;
  private eventCount = 0;
  private lastEventCountTime = Date.now();
  private healthHistory: SystemHealth[] = [];
  private maxHistorySize = 60;

  constructor(config?: Partial<AgentConfig> & { thresholds?: Partial<HealthThresholds> }) {
    super({
      id: 'health-monitor',
      name: 'Health Monitor Agent',
      type: 'foundation',
      description: 'Monitors system health and emits alerts',
      tickRate: 10000,
      riskConfig: {
        tier: AgentRiskTier.LOW,
        riskJustification: 'Foundation health monitor — read-only system observation',
        allowedPublishChannels: ['health:started', 'health:report', 'health:alert', 'health:thresholds:updated'],
        allowedSubscribeChannels: [],
      },
      ...config,
    });

    this.thresholds = {
      cpuWarning: 70,
      cpuCritical: 90,
      memoryWarning: 75,
      memoryCritical: 90,
      diskWarning: 80,
      diskCritical: 95,
      ...config?.thresholds,
    };
  }

  protected async onStart(): Promise<void> {
    eventBus.on('*', () => { this.eventCount++; });
    this.log('info', 'Health monitor started');
    this.emit('health:started', { thresholds: this.thresholds });
  }

  protected async onStop(): Promise<void> {
    this.log('info', 'Health monitor stopped');
  }

  protected async onTick(): Promise<void> {
    const health = await this.collectHealth();
    this.lastHealth = health;

    this.healthHistory.push(health);
    if (this.healthHistory.length > this.maxHistorySize) {
      this.healthHistory.shift();
    }

    this.updateMetrics(health);

    const status = this.determineStatus(health);
    this.emit('health:report', { health, status });
    this.checkAndEmitAlerts(health, status);
  }

  async collectHealth(): Promise<SystemHealth> {
    const now = Date.now();
    const elapsed = (now - this.lastEventCountTime) / 1000;
    const throughput = this.eventCount / elapsed;
    this.eventCount = 0;
    this.lastEventCountTime = now;

    return {
      timestamp: now,
      cpu: await this.collectCPU(),
      memory: this.collectMemory(),
      disk: await this.collectDisk(),
      process: this.collectProcess(),
      agents: this.collectAgentHealthStats(),
      events: { throughput, queueSize: 0, deadLetterCount: 0 },
    };
  }

  private async collectCPU(): Promise<CPUHealth> {
    try {
      const os = await import('os');
      const cpus = os.cpus();
      const loadAvg = os.loadavg();

      let totalIdle = 0;
      let totalTick = 0;
      for (const cpu of cpus) {
        for (const type in cpu.times) {
          totalTick += cpu.times[type as keyof typeof cpu.times];
        }
        totalIdle += cpu.times.idle;
      }
      const usage = 100 - (totalIdle / totalTick * 100);
      return { usage: Math.round(usage * 10) / 10, loadAvg };
    } catch {
      return { usage: 0, loadAvg: [0, 0, 0] };
    }
  }

  private collectMemory(): MemoryHealth {
    try {
      const os = require('os');
      const total = os.totalmem();
      const free = os.freemem();
      const used = total - free;
      const { heapUsed, heapTotal } = process.memoryUsage();
      return {
        total, used, free,
        usagePercent: Math.round((used / total) * 1000) / 10,
        heapUsed, heapTotal,
      };
    } catch {
      return { total: 0, used: 0, free: 0, usagePercent: 0, heapUsed: 0, heapTotal: 0 };
    }
  }

  private async collectDisk(): Promise<DiskHealth> {
    return { total: 0, used: 0, free: 0, usagePercent: 0 };
  }

  private collectProcess(): ProcessHealth {
    return { pid: process.pid, uptime: process.uptime(), memoryUsage: process.memoryUsage().rss };
  }

  private collectAgentHealthStats(): AgentHealthStats {
    const agents = agentRegistry.getAll();
    const unhealthy: string[] = [];
    let running = 0, stopped = 0, error = 0;

    for (const agent of agents) {
      const status: AgentStatus = agent.getStatus();
      switch (status) {
        case 'running': running++; break;
        case 'stopped':
        case 'idle': stopped++; break;
        case 'error':
          error++;
          unhealthy.push(agent.getId());
          break;
      }
    }

    return { total: agents.length, running, stopped, error, unhealthy };
  }

  private determineStatus(health: SystemHealth): SystemHealthStatus {
    if (health.cpu.usage >= this.thresholds.cpuCritical) return 'critical';
    if (health.memory.usagePercent >= this.thresholds.memoryCritical) return 'critical';
    if (health.disk.usagePercent >= this.thresholds.diskCritical) return 'critical';
    if (health.agents.error > 0) return 'unhealthy';
    if (health.cpu.usage >= this.thresholds.cpuWarning) return 'degraded';
    if (health.memory.usagePercent >= this.thresholds.memoryWarning) return 'degraded';
    if (health.disk.usagePercent >= this.thresholds.diskWarning) return 'degraded';
    return 'healthy';
  }

  private checkAndEmitAlerts(health: SystemHealth, status: SystemHealthStatus): void {
    if (status === 'critical') {
      this.emit('health:alert', {
        level: 'critical', status, health,
        message: this.buildAlertMessage(health, 'critical'),
      }, { priority: 'critical' });
    } else if (status === 'unhealthy' || status === 'degraded') {
      this.emit('health:alert', {
        level: 'warning', status, health,
        message: this.buildAlertMessage(health, 'warning'),
      }, { priority: 'high' });
    }
  }

  private buildAlertMessage(health: SystemHealth, level: string): string {
    const issues: string[] = [];
    if (health.cpu.usage >= this.thresholds.cpuCritical) issues.push(`CPU critical: ${health.cpu.usage}%`);
    else if (health.cpu.usage >= this.thresholds.cpuWarning) issues.push(`CPU high: ${health.cpu.usage}%`);
    if (health.memory.usagePercent >= this.thresholds.memoryCritical) issues.push(`Memory critical: ${health.memory.usagePercent}%`);
    else if (health.memory.usagePercent >= this.thresholds.memoryWarning) issues.push(`Memory high: ${health.memory.usagePercent}%`);
    if (health.agents.error > 0) issues.push(`${health.agents.error} agent(s) in error state`);
    return issues.join('; ');
  }

  private updateMetrics(health: SystemHealth): void {
    metrics.set('everythingos_cpu_usage_percent', health.cpu.usage);
    metrics.set('everythingos_memory_usage_percent', health.memory.usagePercent);
    metrics.set('everythingos_memory_heap_bytes', health.memory.heapUsed);
    metrics.set('everythingos_agents_active', health.agents.running);
    metrics.set('everythingos_agents_error', health.agents.error);
    metrics.set('everythingos_event_throughput', health.events.throughput);
    metrics.set('everythingos_process_uptime_seconds', health.process.uptime);
  }

  getLastHealth(): SystemHealth | undefined { return this.lastHealth; }
  getHealthHistory(): SystemHealth[] { return [...this.healthHistory]; }

  getHealthStatus(): SystemHealthStatus {
    if (!this.lastHealth) return 'healthy';
    return this.determineStatus(this.lastHealth);
  }

  setThresholds(thresholds: Partial<HealthThresholds>): void {
    Object.assign(this.thresholds, thresholds);
    this.emit('health:thresholds:updated', { thresholds: this.thresholds });
  }

  getThresholds(): HealthThresholds { return { ...this.thresholds }; }
}
