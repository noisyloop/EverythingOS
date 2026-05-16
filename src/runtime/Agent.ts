/**
 * EverythingOS — Hardened Base Agent Class
 *
 * NIST AI RMF 1.0 — MANAGE (MG-2.2), GOVERN (GV-1.2), MEASURE (MS-2.5)
 * NIST AI 600-1 — Prompt Injection, Data Privacy, Harmful Content
 */

import { randomBytes } from 'crypto';
import { AgentRiskConfig, AgentRiskTier, resolveRiskConfig, requiresSanitization } from '../types/agent-risk';
import { sanitizeInput, scrubPII, checkRateLimit, SanitizedInput } from '../security/sanitize';
import { filterOutput, FilterResult } from '../security/content-filter';
import { AuditLogger, hashContent } from '../security/audit-log';
import { AgentAuthManager, AgentToken, signCall } from '../security/agent-auth';
import { DecisionLedger } from '../security/decision-ledger';
import { eventBus } from '../core/event-bus/EventBus';
import { llmRouter } from '../runtime/LLMRouter';
import { worldState } from '../core/state/WorldState';

// ─────────────────────────────────────────────────────────────────────────────
// AgentConfig
// ─────────────────────────────────────────────────────────────────────────────

export type AgentStatus = 'idle' | 'running' | 'stopped' | 'error';

export interface AgentConfig {
  id: string;
  name: string;
  type: 'perception' | 'analysis' | 'decision' | 'execution' | 'learning' | 'orchestration' | 'foundation';
  description?: string;
  tickRate?: number;
  tags?: string[];

  /**
   * REQUIRED — every agent must declare a risk tier.
   * Omit only for foundation agents using the default below.
   */
  riskConfig?: AgentRiskConfig;

  llm?: {
    provider: 'claude' | 'openai' | 'gemini' | 'ollama';
    model: string;
    temperature?: number;
    maxTokens?: number;
  };
}

/** Default riskConfig for foundation/LOW-tier agents that don't declare one */
const FOUNDATION_RISK_CONFIG: AgentRiskConfig = {
  tier: AgentRiskTier.LOW,
  allowedPublishChannels: ['*'],
  allowedSubscribeChannels: ['*'],
  riskJustification: 'Foundation agent — system internal only',
};

// ─────────────────────────────────────────────────────────────────────────────
// LLM types
// ─────────────────────────────────────────────────────────────────────────────

interface LLMRequest {
  provider: string;
  model: string;
  messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>;
  temperature?: number;
  maxTokens?: number;
}

interface LLMResponse {
  content: string;
  usage?: { promptTokens: number; completionTokens: number; totalTokens: number };
  finishReason?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Think Options
// ─────────────────────────────────────────────────────────────────────────────

export interface ThinkOptions {
  systemPrompt?: string;
  temperature?: number;
  _unsafeSkipSanitization?: never;
}

// ─────────────────────────────────────────────────────────────────────────────
// Abstract Base Agent
// ─────────────────────────────────────────────────────────────────────────────

export abstract class Agent {
  readonly id: string;
  readonly name: string;
  readonly type: AgentConfig['type'];
  readonly description: string;
  readonly tags: string[];

  readonly risk: ReturnType<typeof resolveRiskConfig>;

  private _token: AgentToken | null = null;
  private _tickInterval: ReturnType<typeof setInterval> | null = null;
  private _subscriptions: Array<() => void> = [];
  private _running = false;
  private _status: AgentStatus = 'idle';

  constructor(protected readonly config: AgentConfig) {
    // Use provided riskConfig or fall back to foundation default
    if (!config.riskConfig) {
      config.riskConfig = FOUNDATION_RISK_CONFIG;
    }

    if (!config.riskConfig.allowedPublishChannels || !config.riskConfig.allowedSubscribeChannels) {
      throw new Error(
        `[Agent:${config.id}] riskConfig must declare allowedPublishChannels and allowedSubscribeChannels.`
      );
    }

    this.id = config.id;
    this.name = config.name;
    this.type = config.type;
    this.description = config.description ?? '';
    this.tags = config.tags ?? [];
    this.risk = resolveRiskConfig(config.riskConfig);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public accessors (needed by registry, server, health monitor)
  // ─────────────────────────────────────────────────────────────────────────

  getId(): string { return this.id; }
  getStatus(): AgentStatus { return this._status; }
  isRunning(): boolean { return this._running; }
  getRiskTier(): AgentRiskTier { return this.risk.tier; }
  getToken(): string | null { return this._token?.token ?? null; }
  getConfig(): AgentConfig { return this.config; }

  // ─────────────────────────────────────────────────────────────────────────
  // Public stop — callable by registry and other agents
  // ─────────────────────────────────────────────────────────────────────────

  async stop(): Promise<void> {
    return this._internalStop();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  async _internalStart(): Promise<void> {
    if (this._running) return;

    this._token = AgentAuthManager.issueToken(this.id, this.config.riskConfig!);
    this._status = 'running';

    AuditLogger.log({ agentId: this.id, event: 'agent.started', metadata: { tier: this.risk.tier, type: this.type } });

    await this.onStart();
    this._running = true;

    if (this.config.tickRate && this.config.tickRate > 0) {
      this._tickInterval = setInterval(async () => {
        try {
          await this.onTick();
        } catch (err) {
          this._status = 'error';
          this.log('error', 'Tick error', { error: String(err) });
          AuditLogger.log({ agentId: this.id, event: 'agent.error', metadata: { phase: 'tick', error: String(err) } });
        }
      }, this.config.tickRate);
    }
  }

  async _internalStop(): Promise<void> {
    if (!this._running) return;

    this._running = false;
    this._status = 'stopped';

    if (this._tickInterval) {
      clearInterval(this._tickInterval);
      this._tickInterval = null;
    }

    for (const unsub of this._subscriptions) unsub();
    this._subscriptions = [];

    await this.onStop();

    if (this._token) {
      AgentAuthManager.revokeToken(this.id, 'agent_stopped');
      this._token = null;
    }

    AuditLogger.log({ agentId: this.id, event: 'agent.stopped' });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Abstract lifecycle hooks
  // ─────────────────────────────────────────────────────────────────────────

  protected abstract onStart(): Promise<void>;
  protected abstract onStop(): Promise<void>;
  protected onTick(): Promise<void> { return Promise.resolve(); }

  // ─────────────────────────────────────────────────────────────────────────
  // LLM — think() with mandatory security pipeline
  // ─────────────────────────────────────────────────────────────────────────

  protected async think(prompt: string, options?: ThinkOptions): Promise<string> {
    if (!this.config.llm) {
      throw new Error(`[Agent:${this.id}] Cannot call think() — no LLM configured in AgentConfig.`);
    }

    if (!this._running) {
      throw new Error(`[Agent:${this.id}] Cannot call think() before agent is started.`);
    }

    if (!checkRateLimit(this.id, this.risk.llmRateLimit)) {
      AuditLogger.log({ agentId: this.id, event: 'llm.rate_limited', metadata: { limit: this.risk.llmRateLimit } });
      throw new Error(`[Agent:${this.id}] LLM rate limit exceeded (${this.risk.llmRateLimit} calls/min).`);
    }

    const inputHash = hashContent(prompt);
    if (this.risk.auditInputs) {
      AuditLogger.log({ agentId: this.id, event: 'llm.call', inputHash });
    }

    const ledgerContext = DecisionLedger.buildContext({
      modelId: this.config.llm.model,
      promptTemplate: prompt,
      parameters: {
        temperature: options?.temperature ?? this.config.llm.temperature ?? 0.7,
        maxTokens: this.config.llm.maxTokens ?? 1000,
      },
    });

    const response = await llmRouter.complete({
      provider: this.config.llm.provider,
      model: this.config.llm.model,
      messages: [
        ...(options?.systemPrompt ? [{ role: 'system' as const, content: options.systemPrompt }] : []),
        { role: 'user' as const, content: prompt },
      ],
      temperature: options?.temperature ?? this.config.llm.temperature,
      maxTokens: this.config.llm.maxTokens,
    });

    DecisionLedger.record({
      agentId: this.id,
      decisionType: 'llm.think',
      context: ledgerContext,
      inputHash,
      outputHash: hashContent(response.content),
      outcome: { provider: this.config.llm.provider, finishReason: response.finishReason },
    });

    const filtered = filterOutput(response.content, {
      agentId: this.id,
      context: this.type,
      strictMode: this.risk.tier === AgentRiskTier.HIGH,
    });

    if (filtered.blocked) {
      throw new Error(`[Agent:${this.id}] LLM output blocked by content filter: ${filtered.reasons.join(', ')}`);
    }

    if (this.risk.auditOutputs) {
      AuditLogger.log({ agentId: this.id, event: 'llm.response', outputHash: hashContent(filtered.filtered) });
    }

    return filtered.filtered;
  }

  protected async thinkWithUserInput(
    template: string,
    userContent: string,
    options?: ThinkOptions,
  ): Promise<{ response: string; sanitized: SanitizedInput }> {
    if (!requiresSanitization(this.config.riskConfig!)) {
      this.log('warn', 'LOW risk tier agent calling thinkWithUserInput — consider upgrading tier if handling user input.');
    }

    const sanitized = sanitizeInput(userContent, this.id);

    if (sanitized.injectionDetected) {
      AuditLogger.log({
        agentId: this.id,
        event: 'security.injection_detected',
        inputHash: sanitized.originalHash,
        metadata: { patterns: sanitized.detectedPatterns, truncated: sanitized.truncated },
      });
      this.log('warn', 'Prompt injection detected and stripped', { patterns: sanitized.detectedPatterns });
    }

    const piiResult = scrubPII(sanitized.sanitized);

    if (piiResult.piiInstancesFound > 0) {
      AuditLogger.log({
        agentId: this.id,
        event: 'security.pii_scrubbed',
        inputHash: sanitized.originalHash,
        metadata: { categories: piiResult.piiCategories, count: piiResult.piiInstancesFound },
      });
    }

    const cleanPrompt = template.replace('{userContent}', piiResult.scrubbed);
    const response = await this.think(cleanPrompt, options);

    return { response, sanitized };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // EventBus
  // ─────────────────────────────────────────────────────────────────────────

  protected emit(
    type: string,
    payload: unknown,
    options?: { priority?: 'critical' | 'high' | 'normal' | 'low' },
  ): void {
    if (!this._token) {
      AuditLogger.log({ agentId: this.id, event: 'eventbus.publish_blocked', metadata: { channel: type, reason: 'no_token' } });
      throw new Error(`[Agent:${this.id}] Cannot emit — agent has no auth token. Is the agent started?`);
    }

    const nonce = randomBytes(8).toString('hex');
    const ts = Date.now();
    const sig = signCall(this._token.callSigningKey, this.id, type, nonce, ts);
    const allowed = AgentAuthManager.canPublish(this.id, sig, type, nonce, ts);

    if (!allowed) {
      throw new Error(
        `[Agent:${this.id}] Publish to channel "${type}" blocked — not in allowedPublishChannels. ` +
        `Declared channels: ${this.risk.allowedPublishChannels.join(', ')}`
      );
    }

    if (this.risk.auditOutputs) {
      AuditLogger.log({
        agentId: this.id,
        event: 'eventbus.publish',
        metadata: { channel: type, priority: options?.priority },
      });
    }

    eventBus.emit(type, payload, { source: this.id, priority: options?.priority });
  }

  protected subscribe<T = unknown>(
    type: string,
    handler: (event: { type: string; payload: T }) => void,
  ): void {
    if (!this._token) {
      throw new Error(`[Agent:${this.id}] Cannot subscribe — agent has no auth token. Is the agent started?`);
    }

    const nonce = randomBytes(8).toString('hex');
    const ts = Date.now();
    const sig = signCall(this._token.callSigningKey, this.id, type, nonce, ts);
    const allowed = AgentAuthManager.canSubscribe(this.id, sig, type, nonce, ts);

    if (!allowed) {
      throw new Error(
        `[Agent:${this.id}] Subscribe to channel "${type}" blocked — not in allowedSubscribeChannels. ` +
        `Declared channels: ${this.risk.allowedSubscribeChannels.join(', ')}`
      );
    }

    AuditLogger.log({ agentId: this.id, event: 'eventbus.subscribe', metadata: { channel: type } });

    const unsub = eventBus.on(type, handler as (event: { type: string; payload: unknown }) => void);
    this._subscriptions.push(unsub);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // State
  // ─────────────────────────────────────────────────────────────────────────

  protected getState<T>(key: string): T | undefined {
    return worldState.getAgentState<T>(this.id, key);
  }

  protected setState<T>(key: string, value: T): void {
    worldState.setAgentState(this.id, key, value);
  }

  protected getGlobal<T>(key: string): T | undefined {
    return worldState.getGlobal<T>(key);
  }

  protected setGlobal<T>(key: string, value: T): void {
    worldState.setGlobal(key, value);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Logging
  // ─────────────────────────────────────────────────────────────────────────

  protected log(level: 'debug' | 'info' | 'warn' | 'error', message: string, data?: Record<string, unknown>): void {
    const prefix = `[${this.name}]`;
    const formatted = data ? `${message} ${JSON.stringify(data)}` : message;
    if (level === 'error') console.error(prefix, formatted);
    else if (level === 'warn') console.warn(prefix, formatted);
    else if (level === 'info') console.info(prefix, formatted);
    else console.debug(prefix, formatted);
  }
}
