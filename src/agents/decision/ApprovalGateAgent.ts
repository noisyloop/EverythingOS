// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Approval Gate Agent
// Human-in-the-loop for sensitive decisions
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent, AgentConfig } from '../../runtime/Agent';
import { AgentRiskTier } from '../../types/agent-risk';
import { eventBus } from '../../core/event-bus/EventBus';
import { toolRegistry } from '../../services/tools';
import { intentManager, Intent } from '../../runtime/IntentContract';
import { ToolApprovalRequest } from '../../services/tools/ToolTypes';

export type ApprovalChannel = 'cli' | 'webhook' | 'discord' | 'slack' | 'email';

export interface PendingApproval {
  id: string;
  type: 'tool' | 'intent';
  request: ToolApprovalRequest | Intent;
  summary: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  createdAt: number;
  expiresAt: number;
  notifiedChannels: ApprovalChannel[];
}

export interface ApprovalDecision {
  approvalId: string;
  approved: boolean;
  approvedBy: string;
  reason?: string;
  timestamp: number;
}

export interface ApprovalGateConfig {
  channels: ApprovalChannel[];
  defaultTimeout: number;
  webhookUrl?: string;
  discordChannelId?: string;
  slackChannelId?: string;
  emailTo?: string;
  autoApprove?: {
    lowRisk?: boolean;
    trustedAgents?: string[];
  };
}

export class ApprovalGateAgent extends Agent {
  private pending: Map<string, PendingApproval> = new Map();
  private history: ApprovalDecision[] = [];
  private gateConfig: ApprovalGateConfig;

  constructor(config?: Partial<ApprovalGateConfig>) {
    const agentConfig: AgentConfig = {
      id: 'approval-gate',
      name: 'Approval Gate',
      type: 'decision',
      description: 'Human-in-the-loop approval for sensitive actions',
      tickRate: 5000,
      riskConfig: {
        tier: AgentRiskTier.MEDIUM,
        riskJustification: 'Routes approval requests — no autonomous actions',
        allowedPublishChannels: [
          'approval:pending', 'approval:approved', 'approval:denied',
          'discord:send_message', 'slack:send_message', 'email:send',
        ],
        allowedSubscribeChannels: [
          'tools:approval:request', 'intent:approval:required', 'approval:decision',
        ],
      },
    };

    super(agentConfig);

    this.gateConfig = {
      channels: config?.channels ?? ['cli'],
      defaultTimeout: config?.defaultTimeout ?? 300000,
      webhookUrl: config?.webhookUrl,
      discordChannelId: config?.discordChannelId,
      slackChannelId: config?.slackChannelId,
      emailTo: config?.emailTo,
      autoApprove: config?.autoApprove,
    };
  }

  protected async onStart(): Promise<void> {
    this.subscribe('tools:approval:request', (event) => {
      this.handleToolApproval(event.payload as ToolApprovalRequest);
    });

    this.subscribe('intent:approval:required', (event) => {
      this.handleIntentApproval((event.payload as { intent: Intent }).intent);
    });

    this.subscribe('approval:decision', (event) => {
      this.processDecision(event.payload as ApprovalDecision);
    });

    this.log('info', `Approval Gate started with channels: ${this.gateConfig.channels.join(', ')}`);
  }

  protected async onStop(): Promise<void> {
    for (const [id] of this.pending) {
      this.deny(id, 'system', 'Agent shutdown');
    }
    this.pending.clear();
  }

  protected async onTick(): Promise<void> {
    const now = Date.now();
    for (const [id, pending] of this.pending) {
      if (now > pending.expiresAt) {
        this.log('warn', `Approval ${id} expired`);
        this.deny(id, 'timeout', 'Approval request timed out');
      }
    }
  }

  private handleToolApproval(request: ToolApprovalRequest): void {
    const risk = this.assessToolRisk(request);

    if (this.shouldAutoApprove(request.agentId, risk)) {
      this.log('info', `Auto-approving tool ${request.tool} for ${request.agentId}`);
      toolRegistry.approve(request.callId, 'approval-gate:auto');
      return;
    }

    const pending: PendingApproval = {
      id: request.callId,
      type: 'tool',
      request,
      summary: this.summarizeToolRequest(request),
      risk,
      createdAt: Date.now(),
      expiresAt: Date.now() + this.gateConfig.defaultTimeout,
      notifiedChannels: [],
    };

    this.pending.set(request.callId, pending);
    this.notifyChannels(pending);
    this.emit('approval:pending', { approval: pending });
  }

  private handleIntentApproval(intent: Intent): void {
    const risk = this.assessIntentRisk(intent);

    if (this.shouldAutoApprove(intent.agentId, risk)) {
      this.log('info', `Auto-approving intent ${intent.type}:${intent.action} for ${intent.agentId}`);
      intentManager.approve(intent.id, 'approval-gate:auto');
      return;
    }

    const pending: PendingApproval = {
      id: intent.id,
      type: 'intent',
      request: intent,
      summary: this.summarizeIntent(intent),
      risk,
      createdAt: Date.now(),
      expiresAt: Date.now() + this.gateConfig.defaultTimeout,
      notifiedChannels: [],
    };

    this.pending.set(intent.id, pending);
    this.notifyChannels(pending);
    this.emit('approval:pending', { approval: pending });
  }

  private assessToolRisk(request: ToolApprovalRequest): PendingApproval['risk'] {
    switch (request.trustLevel) {
      case 'dangerous': return 'critical';
      case 'sensitive': return 'high';
      case 'moderate': return 'medium';
      default: return 'low';
    }
  }

  private assessIntentRisk(intent: Intent): PendingApproval['risk'] {
    const typeRisk: Record<string, PendingApproval['risk']> = {
      'execute': 'high', 'communicate': 'medium', 'store': 'low',
      'query': 'low', 'delegate': 'medium', 'escalate': 'low', 'schedule': 'medium',
    };

    let risk = typeRisk[intent.type] ?? 'medium';

    if (intent.confidence < 0.5) {
      if (risk === 'low') risk = 'medium';
      else if (risk === 'medium') risk = 'high';
    }

    if (intent.priority === 'critical') {
      if (risk === 'medium') risk = 'high';
      else if (risk === 'high') risk = 'critical';
    }

    return risk;
  }

  private shouldAutoApprove(agentId: string, risk: PendingApproval['risk']): boolean {
    if (!this.gateConfig.autoApprove) return false;
    if (risk === 'low' && this.gateConfig.autoApprove.lowRisk) return true;
    if (this.gateConfig.autoApprove.trustedAgents?.includes(agentId)) return true;
    return false;
  }

  private async notifyChannels(pending: PendingApproval): Promise<void> {
    for (const channel of this.gateConfig.channels) {
      try {
        await this.notifyChannel(channel, pending);
        pending.notifiedChannels.push(channel);
      } catch (error) {
        this.log('error', `Failed to notify ${channel}: ${error}`);
      }
    }
  }

  private async notifyChannel(channel: ApprovalChannel, pending: PendingApproval): Promise<void> {
    const message = this.formatApprovalMessage(pending);
    switch (channel) {
      case 'cli': this.notifyCLI(pending, message); break;
      case 'webhook': await this.notifyWebhook(pending, message); break;
      case 'discord': await this.notifyDiscord(pending, message); break;
      case 'slack': await this.notifySlack(pending, message); break;
      case 'email': await this.notifyEmail(pending, message); break;
    }
  }

  private formatApprovalMessage(pending: PendingApproval): string {
    const riskEmoji = { low: '🟢', medium: '🟡', high: '🟠', critical: '🔴' };
    return [
      `${riskEmoji[pending.risk]} APPROVAL REQUIRED [${pending.risk.toUpperCase()}]`,
      ``, `ID: ${pending.id}`, `Type: ${pending.type}`, ``,
      pending.summary, ``,
      `Expires: ${new Date(pending.expiresAt).toISOString()}`, ``,
      `To approve: POST /api/approvals/${pending.id}/approve`,
      `To deny: POST /api/approvals/${pending.id}/deny`,
    ].join('\n');
  }

  private notifyCLI(pending: PendingApproval, message: string): void {
    console.log('\n' + '═'.repeat(60));
    console.log(message);
    console.log('═'.repeat(60) + '\n');
  }

  private async notifyWebhook(pending: PendingApproval, message: string): Promise<void> {
    if (!this.gateConfig.webhookUrl) return;
    await fetch(this.gateConfig.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'approval_required', approval: pending, message }),
    });
  }

  private async notifyDiscord(pending: PendingApproval, message: string): Promise<void> {
    if (!this.gateConfig.discordChannelId) return;
    this.emit('discord:send_message', {
      channelId: this.gateConfig.discordChannelId,
      content: '```\n' + message + '\n```',
    });
  }

  private async notifySlack(pending: PendingApproval, message: string): Promise<void> {
    if (!this.gateConfig.slackChannelId) return;
    this.emit('slack:send_message', { channel: this.gateConfig.slackChannelId, text: message });
  }

  private async notifyEmail(pending: PendingApproval, message: string): Promise<void> {
    if (!this.gateConfig.emailTo) return;
    this.emit('email:send', {
      to: this.gateConfig.emailTo,
      subject: `[EverythingOS] Approval Required: ${pending.type} - ${pending.risk.toUpperCase()}`,
      body: message,
    });
  }

  private summarizeToolRequest(request: ToolApprovalRequest): string {
    return [
      `Tool: ${request.tool}`, `Agent: ${request.agentId}`,
      `Trust Level: ${request.trustLevel}`,
      `Input: ${JSON.stringify(request.input, null, 2)}`,
      `Reason: ${request.reason}`,
    ].join('\n');
  }

  private summarizeIntent(intent: Intent): string {
    return [
      `Intent: ${intent.type}:${intent.action}`, `Agent: ${intent.agentId}`,
      `Target: ${intent.target ?? 'none'}`,
      `Confidence: ${(intent.confidence * 100).toFixed(0)}%`,
      `Reasoning: ${intent.reasoning}`,
      `Payload: ${JSON.stringify(intent.payload, null, 2)}`,
    ].join('\n');
  }

  private processDecision(decision: ApprovalDecision): void {
    const pending = this.pending.get(decision.approvalId);
    if (!pending) {
      this.log('warn', `No pending approval found for ${decision.approvalId}`);
      return;
    }
    if (decision.approved) {
      this.approve(decision.approvalId, decision.approvedBy, decision.reason);
    } else {
      this.deny(decision.approvalId, decision.approvedBy, decision.reason ?? 'Denied by user');
    }
  }

  approve(approvalId: string, approvedBy: string, reason?: string): boolean {
    const pending = this.pending.get(approvalId);
    if (!pending) return false;

    this.log('info', `Approved ${pending.type} ${approvalId} by ${approvedBy}`);
    this.history.push({ approvalId, approved: true, approvedBy, reason, timestamp: Date.now() });

    if (pending.type === 'tool') {
      toolRegistry.approve(approvalId, approvedBy);
    } else {
      intentManager.approve(approvalId, approvedBy);
    }

    this.pending.delete(approvalId);
    this.emit('approval:approved', { approvalId, approvedBy, reason });
    return true;
  }

  deny(approvalId: string, deniedBy: string, reason: string): boolean {
    const pending = this.pending.get(approvalId);
    if (!pending) return false;

    this.log('info', `Denied ${pending.type} ${approvalId} by ${deniedBy}: ${reason}`);
    this.history.push({ approvalId, approved: false, approvedBy: deniedBy, reason, timestamp: Date.now() });

    if (pending.type === 'tool') {
      toolRegistry.deny(approvalId, deniedBy, reason);
    } else {
      intentManager.deny(approvalId, deniedBy, reason);
    }

    this.pending.delete(approvalId);
    this.emit('approval:denied', { approvalId, deniedBy, reason });
    return true;
  }

  getPending(): PendingApproval[] { return Array.from(this.pending.values()); }
  getPendingByRisk(risk: PendingApproval['risk']): PendingApproval[] { return this.getPending().filter(p => p.risk === risk); }
  getHistory(limit = 100): ApprovalDecision[] { return this.history.slice(-limit); }

  getStats() {
    const approved = this.history.filter(h => h.approved).length;
    const denied = this.history.filter(h => !h.approved).length;
    const byRisk: Record<string, number> = {};
    for (const p of this.pending.values()) {
      byRisk[p.risk] = (byRisk[p.risk] || 0) + 1;
    }
    return { pending: this.pending.size, approved, denied, byRisk };
  }
}

export function createApprovalGate(config?: Partial<ApprovalGateConfig>): ApprovalGateAgent {
  return new ApprovalGateAgent(config);
}
