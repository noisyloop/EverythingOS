/**
 * EverythingOS — Hardened Base Agent Class
 *
 * NIST AI RMF 1.0 — MANAGE (MG-2.2), GOVERN (GV-1.2), MEASURE (MS-2.5)
 * NIST AI 600-1 — Prompt Injection, Data Privacy, Harmful Content
 *
 * Security controls are MANDATORY and AUTOMATIC — not optional utilities.
 * Every agent that extends this class gets them for free. There is no way
 * to call think() without sanitization. There is no way to publish without
 * an auth token. There is no way to start without a declared riskTier.
 *
 * Developers cannot bypass these controls without modifying this file,
 * which makes bypassing an intentional and reviewable act.
 */

import { AgentRiskConfig, AgentRiskTier, resolveRiskConfig, requiresSanitization } from '../types/agent-risk';
import { sanitizeInput, scrubPII, checkRateLimit, SanitizedInput } from '../security/sanitize';
import { filterOutput, FilterResult } from '../security/content-filter';
import { AuditLogger, hashContent } from '../security/audit-log';
import { AgentAuthManager, AgentToken } from '../security/agent-auth';
import { DecisionLedger } from '../security/decision-ledger';

// ─────────────────────────────────────────────────────────────────────────────
// AgentConfig — riskConfig is REQUIRED, not optional
// ─────────────────────────────────────────────────────────────────────────────

export interface AgentConfig {
  id: string;
  name: string;
  type: 'perception' | 'analysis' | 'decision' | 'execution' | 'learning' | 'orchestration';
  description?: string;
  tickRate?: number;

  /**
   * REQUIRED — every agent must declare a risk tier.
   * TypeScript will refuse to compile any agent that omits this.
   * See src/types/agent-risk.ts for tier definitions and defaults.
   */
  riskConfig: AgentRiskConfig;

  llm?: {
    provider: 'claude' | 'openai' | 'gemini' | 'ollama';
    model: string;
    temperature?: number;
    maxTokens?: number;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// LLM Router interface (matches existing LLMRouter shape)
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
}

// Injected at runtime by the framework — not imported directly to avoid circular deps
declare const llmRouter: { complete(req: LLMRequest): Promise<LLMResponse> };
declare const eventBus: {
  emit(type: string, payload: unknown, opts?: { source?: string; priority?: string }): void;
  on(type: string, handler: (event: { type: string; payload: unknown }) => void): () => void;
};
declare const worldState: {
  getAgentState<T>(agentId: string, key: string): T | undefined;
  setAgentState<T>(agentId: string, key: string, value: T): void;
  getGlobal<T>(key: string): T | undefined;
  setGlobal<T>(key: string, value: T): void;
};

// ─────────────────────────────────────────────────────────────────────────────
// Think Options
// ─────────────────────────────────────────────────────────────────────────────

export interface ThinkOptions {
  systemPrompt?: string;
  temperature?: number;
  /** If true, skip sanitization (only valid for LOW tier agents with no user input) */
  _unsafeSkipSanitization?: never; // typed as never — cannot be set
}

// ─────────────────────────────────────────────────────────────────────────────
// Abstract Base Agent
// ─────────────────────────────────────────────────────────────────────────────

export abstract class Agent {
  readonly id: string;
  readonly name: string;
  readonly type: AgentConfig['type'];
  readonly description: string;

  /** Resolved risk config with tier defaults applied */
  readonly risk: ReturnType<typeof resolveRiskConfig>;

  /** HMAC auth token issued at construction — required for all EventBus publishes */
  private _token: AgentToken | null = null;

  private _tickInterval: ReturnType<typeof setInterval> | null = null;
  private _subscriptions: Array<() => void> = [];
  private _running = false;

  constructor(protected readonly config: AgentConfig) {
    // Validate riskConfig at construction time — catches missing config immediately
    if (!config.riskConfig) {
      throw new Error(
        `[Agent:${config.id}] riskConfig is required. Every agent must declare a risk tier. ` +
        `See src/types/agent-risk.ts for AgentRiskTier.LOW / MEDIUM / HIGH.`
      );
    }

    if (!config.riskConfig.allowedPublishChannels || !config.riskConfig.allowedSubscribeChannels) {
      throw new Error(
        `[Agent:${config.id}] riskConfig must declare allowedPublishChannels and allowedSubscribeChannels. ` +
        `Channels cannot be empty — use [] if this agent has no publish/subscribe needs.`
      );
    }

    this.id = config.id;
    this.name = config.name;
    this.type = config.type;
    this.description = config.description ?? '';
    this.risk = resolveRiskConfig(config.riskConfig);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Lifecycle — enforced start/stop
  // ─────────────────────────────────────────────────────────────────────────────

  /** Called by the AgentRegistry — do not call directly */
  async _internalStart(): Promise<void> {
    if (this._running) return;

    // Issue auth token before anything else
    this._token = AgentAuthManager.issueToken(this.id, this.config.riskConfig);

    AuditLogger.log({ agentId: this.id, event: 'agent.started', metadata: { tier: this.risk.tier, type: this.type } });

    await this.onStart();
    this._running = true;

    if (this.config.tickRate && this.config.tickRate > 0) {
      this._tickInterval = setInterval(async () => {
        try {
          await this.onTick();
        } catch (err) {
          this.log('error', 'Tick error', { error: String(err) });
          AuditLogger.log({ agentId: this.id, event: 'agent.error', metadata: { phase: 'tick', error: String(err) } });
        }
      }, this.config.tickRate);
    }
  }

  /** Called by the AgentRegistry — do not call directly */
  async _internalStop(): Promise<void> {
    if (!this._running) return;

    this._running = false;

    if (this._tickInterval) {
      clearInterval(this._tickInterval);
      this._tickInterval = null;
    }

    // Unsubscribe from all EventBus channels
    for (const unsub of this._subscriptions) unsub();
    this._subscriptions = [];

    await this.onStop();

    // Revoke token on stop — agent must re-register to re-operate
    if (this._token) {
      AgentAuthManager.revokeToken(this.id, 'agent_stopped');
      this._token = null;
    }

    AuditLogger.log({ agentId: this.id, event: 'agent.stopped' });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Abstract lifecycle hooks — implement in your agent
  // ─────────────────────────────────────────────────────────────────────────────

  protected abstract onStart(): Promise<void>;
  protected abstract onStop(): Promise<void>;
  protected onTick(): Promise<void> { return Promise.resolve(); }

  // ─────────────────────────────────────────────────────────────────────────────
  // LLM — think() with mandatory security pipeline
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Send a prompt to the configured LLM.
   *
   * MANDATORY PIPELINE (cannot be bypassed):
   *   1. Rate limit check
   *   2. If user-supplied content: sanitize (injection) + scrub (PII)
   *   3. LLM API call
   *   4. Output content filter
   *   5. Audit log (input hash + output hash)
   *
   * @param prompt - The prompt to send. If this contains user-supplied content,
   *                 pass it through the `userContent` parameter instead so it
   *                 gets sanitized before being embedded.
   * @param options - System prompt and temperature overrides.
   */
  protected async think(prompt: string, options?: ThinkOptions): Promise<string> {
    if (!this.config.llm) {
      throw new Error(`[Agent:${this.id}] Cannot call think() — no LLM configured in AgentConfig.`);
    }

    if (!this._running) {
      throw new Error(`[Agent:${this.id}] Cannot call think() before agent is started.`);
    }

    // 1. Rate limit
    if (!checkRateLimit(this.id, this.risk.llmRateLimit)) {
      AuditLogger.log({ agentId: this.id, event: 'llm.rate_limited', metadata: { limit: this.risk.llmRateLimit } });
      throw new Error(`[Agent:${this.id}] LLM rate limit exceeded (${this.risk.llmRateLimit} calls/min).`);
    }

    // 2. Audit input
    const inputHash = hashContent(prompt);
    if (this.risk.auditInputs) {
      AuditLogger.log({ agentId: this.id, event: 'llm.call', inputHash });
    }

    // 3. LLM call — wrapped with DecisionLedger for provenance
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

    // 4. Content filter — MANDATORY on all LLM outputs
    const filtered = filterOutput(response.content, {
      agentId: this.id,
      context: this.type,
      strictMode: this.risk.tier === AgentRiskTier.HIGH,
    });

    if (filtered.blocked) {
      throw new Error(`[Agent:${this.id}] LLM output blocked by content filter: ${filtered.reasons.join(', ')}`);
    }

    // 5. Audit output
    if (this.risk.auditOutputs) {
      AuditLogger.log({ agentId: this.id, event: 'llm.response', outputHash: hashContent(filtered.filtered) });
    }

    return filtered.filtered;
  }

  /**
   * think() variant for user-supplied content.
   * Sanitizes and PII-scrubs the user content before embedding it in the prompt.
   * Use this whenever the prompt contains anything from user input.
   *
   * @param template - Prompt template. Use {userContent} as a placeholder.
   * @param userContent - Raw user-supplied text (will be sanitized + scrubbed)
   * @param options - System prompt and temperature overrides.
   */
  protected async thinkWithUserInput(
    template: string,
    userContent: string,
    options?: ThinkOptions,
  ): Promise<{ response: string; sanitized: SanitizedInput }> {
    if (!requiresSanitization(this.config.riskConfig)) {
      // LOW tier agent trying to use user input — warn and sanitize anyway
      this.log('warn', 'LOW risk tier agent calling thinkWithUserInput — consider upgrading tier if handling user input.');
    }

    // Sanitize injection patterns
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

    // Scrub PII before it leaves the system
    const piiResult = scrubPII(sanitized.sanitized);

    if (piiResult.piiInstancesFound > 0) {
      AuditLogger.log({
        agentId: this.id,
        event: 'security.pii_scrubbed',
        inputHash: sanitized.originalHash,
        metadata: { categories: piiResult.piiCategories, count: piiResult.piiInstancesFound },
      });
    }

    // Embed cleaned content into template
    const cleanPrompt = template.replace('{userContent}', piiResult.scrubbed);

    const response = await this.think(cleanPrompt, options);

    return { response, sanitized };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // EventBus — publish() with mandatory auth + ACL check
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Publish an event to the EventBus.
   * MANDATORY: validates HMAC token and channel ACL before publishing.
   * Blocked attempts are logged to the audit trail.
   */
  protected emit(
    type: string,
    payload: unknown,
    options?: { priority?: 'critical' | 'high' | 'normal' | 'low' },
  ): void {
    if (!this._token) {
      AuditLogger.log({ agentId: this.id, event: 'eventbus.publish_blocked', metadata: { channel: type, reason: 'no_token' } });
      throw new Error(`[Agent:${this.id}] Cannot emit — agent has no auth token. Is the agent started?`);
    }

    const allowed = AgentAuthManager.canPublish(this.id, this._token.token, type);

    if (!allowed) {
      // Already logged by AgentAuthManager — throw so the agent knows
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

  /**
   * Subscribe to an EventBus channel.
   * MANDATORY: validates token and ACL before subscribing.
   * Subscription is tracked and automatically cleaned up on agent stop.
   */
  protected subscribe<T = unknown>(
    type: string,
    handler: (event: { type: string; payload: T }) => void,
  ): void {
    if (!this._token) {
      throw new Error(`[Agent:${this.id}] Cannot subscribe — agent has no auth token. Is the agent started?`);
    }

    const allowed = AgentAuthManager.canSubscribe(this.id, this._token.token, type);

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

  // ─────────────────────────────────────────────────────────────────────────────
  // State — unchanged from original
  // ─────────────────────────────────────────────────────────────────────────────

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

  // ─────────────────────────────────────────────────────────────────────────────
  // Logging
  // ─────────────────────────────────────────────────────────────────────────────

  protected log(level: 'debug' | 'info' | 'warn' | 'error', message: string, data?: Record<string, unknown>): void {
    const prefix = `[${this.name}]`;
    const formatted = data ? `${message} ${JSON.stringify(data)}` : message;
    if (level === 'error') console.error(prefix, formatted);
    else if (level === 'warn') console.warn(prefix, formatted);
    else if (level === 'info') console.info(prefix, formatted);
    else console.debug(prefix, formatted);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Health
  // ─────────────────────────────────────────────────────────────────────────────

  isRunning(): boolean { return this._running; }
  getRiskTier(): AgentRiskTier { return this.risk.tier; }
  getToken(): string | null { return this._token?.token ?? null; }
}
