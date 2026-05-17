// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Approval Gate Agent
// Human-in-the-loop for sensitive decisions
//
// Security model: approval decisions arrive via HMAC-signed submitDecision()
// calls, NOT via the EventBus. Any agent can emit EventBus events — removing
// approval:decision from the bus prevents a compromised agent from self-approving
// its own HIGH-tier actions (STRIDE finding E-1/S-2).
// ═══════════════════════════════════════════════════════════════════════════════

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { Agent, AgentConfig } from '../../runtime/Agent';
import { AgentRiskTier } from '../../types/agent-risk';
import { toolRegistry } from '../../services/tools';
import { intentManager, Intent } from '../../runtime/IntentContract';
import { ToolApprovalRequest } from '../../services/tools/ToolTypes';
import { AuditLogger } from '../../security/audit-log';
import { createHttpClient } from '../../security/http-guard';

// ─────────────────────────────────────────────────────────────────────────────
// Approval HMAC secret — separate from EOS_AGENT_SECRET
// ─────────────────────────────────────────────────────────────────────────────

const APPROVAL_GATE_SECRET: string = (() => {
  const key = process.env.APPROVAL_GATE_SECRET;
  if (!key) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        '[ApprovalGate] APPROVAL_GATE_SECRET is required in production. ' +
        'Generate: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
      );
    }
    const dev = randomBytes(32).toString('hex');
    console.warn('[ApprovalGate] WARNING: APPROVAL_GATE_SECRET not set. Using ephemeral key. Set in .env for stability.');
    return dev;
  }
  return key;
})();

// Token format: <hmac>:<minuteTimestamp>
// HMAC = HMAC-SHA256("${approvalId}:${approved}:${approvedBy}:${minuteTs}", APPROVAL_GATE_SECRET)
// Tokens are valid for ±5 minutes from generation time.

function generateApprovalToken(approvalId: string, approved: boolean, approvedBy: string): string {
  const minuteTs = Math.floor(Date.now() / 60_000);
  const payload = `${approvalId}:${approved ? '1' : '0'}:${approvedBy}:${minuteTs}`;
  const hmac = createHmac('sha256', APPROVAL_GATE_SECRET).update(payload).digest('hex');
  return `${hmac}:${minuteTs}`;
}

function verifyApprovalToken(approvalId: string, approved: boolean, approvedBy: string, token: string): boolean {
  const colonIdx = token.lastIndexOf(':');
  if (colonIdx === -1) return false;
  const hmac = token.slice(0, colonIdx);
  const minuteTsStr = token.slice(colonIdx + 1);
  const minuteTs = parseInt(minuteTsStr, 10);
  if (isNaN(minuteTs) || hmac.length !== 64) return false;

  const currentMinute = Math.floor(Date.now() / 60_000);
  if (Math.abs(currentMinute - minuteTs) > 5) return false;

  const payload = `${approvalId}:${approved ? '1' : '0'}:${approvedBy}:${minuteTs}`;
  const expected = createHmac('sha256', APPROVAL_GATE_SECRET).update(payload).digest('hex');
  if (expected.length !== 64) return false;
  return timingSafeEqual(Buffer.from(hmac, 'hex'), Buffer.from(expected, 'hex'));
}

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// ApprovalGateAgent
// ─────────────────────────────────────────────────────────────────────────────

export class ApprovalGateAgent extends Agent {
  private pending: Map<string, PendingApproval> = new Map();
  private history: ApprovalDecision[] = [];
  private gateConfig: ApprovalGateConfig;
  private readonly webhookClient = createHttpClient({ agentId: 'approval-gate:webhook' });

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
        // approval:decision intentionally absent — decisions arrive via submitDecision(),
        // not the EventBus, to prevent any agent from self-approving its own actions.
        allowedSubscribeChannels: [
          'tools:approval:request', 'intent:approval:required',
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

  // ─────────────────────────────────────────────────────────────────────────────
  // Authenticated approval intake — replaces EventBus approval:decision channel
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Submit an approval decision with an HMAC-signed token.
   *
   * Generate the token with ApprovalGateAgent.generateToken() or:
   *   node -e "
   *     const { createHmac } = require('crypto');
   *     const secret = process.env.APPROVAL_GATE_SECRET;
   *     const minuteTs = Math.floor(Date.now() / 60000);
   *     const payload = \`{approvalId}:{1|0}:{approvedBy}:\${minuteTs}\`;
   *     console.log(createHmac('sha256', secret).update(payload).digest('hex') + ':' + minuteTs);
   *   "
   *
   * Tokens are valid for ±5 minutes from generation time.
   */
  submitDecision(approvalId: string, approved: boolean, approvedBy: string, token: string): boolean {
    if (!verifyApprovalToken(approvalId, approved, approvedBy, token)) {
      this.log('warn', `Approval decision rejected — invalid HMAC token for ${approvalId}`);
      AuditLogger.log({
        agentId: this.id,
        event: 'auth.token_rejected',
        metadata: { reason: 'invalid_approval_token', approvalId, approvedBy },
      });
      return false;
    }

    const pending = this.pending.get(approvalId);
    if (!pending) {
      this.log('warn', `No pending approval found for ${approvalId}`);
      return false;
    }

    if (approved) {
      this.approve(approvalId, approvedBy);
    } else {
      this.deny(approvalId, approvedBy, 'Denied by approver');
    }
    return true;
  }

  /**
   * Generate an HMAC token for use with submitDecision().
   * Call this from a trusted context (CLI tool, webhook receiver) — not from agent code.
   */
  static generateToken(approvalId: string, approved: boolean, approvedBy: string): string {
    return generateApprovalToken(approvalId, approved, approvedBy);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Internal handlers
  // ─────────────────────────────────────────────────────────────────────────────

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
    const riskLabel = { low: 'LOW', medium: 'MEDIUM', high: 'HIGH', critical: 'CRITICAL' };
    const approveToken = generateApprovalToken(pending.id, true, 'approver');
    const denyToken = generateApprovalToken(pending.id, false, 'approver');
    return [
      `APPROVAL REQUIRED [${riskLabel[pending.risk]}]`,
      ``,
      `ID: ${pending.id}`,
      `Type: ${pending.type}`,
      ``,
      pending.summary,
      ``,
      `Expires: ${new Date(pending.expiresAt).toISOString()}`,
      ``,
      `To approve or deny, call submitDecision() with a signed token:`,
      `  approvalGate.submitDecision("${pending.id}", true, "approver", "${approveToken}")`,
      `  approvalGate.submitDecision("${pending.id}", false, "approver", "${denyToken}")`,
      ``,
      `Tokens expire in ~5 minutes. Regenerate with ApprovalGateAgent.generateToken().`,
    ].join('\n');
  }

  private notifyCLI(_pending: PendingApproval, message: string): void {
    console.log('\n' + '═'.repeat(60));
    console.log(message);
    console.log('═'.repeat(60) + '\n');
  }

  private async notifyWebhook(pending: PendingApproval, message: string): Promise<void> {
    if (!this.gateConfig.webhookUrl) return;
    // Uses http-guard client — blocks internal URLs to prevent SSRF
    await this.webhookClient.post(this.gateConfig.webhookUrl, {
      type: 'approval_required',
      approval: { id: pending.id, type: pending.type, risk: pending.risk, summary: pending.summary, expiresAt: pending.expiresAt },
      message,
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
