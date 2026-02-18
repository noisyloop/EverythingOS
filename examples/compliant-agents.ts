/**
 * EXAMPLE: How to write a compliant EverythingOS agent
 *
 * This shows a Discord bot agent (MEDIUM risk) and a trading agent (HIGH risk).
 * Notice that security is not something you have to remember to add —
 * the base class handles it automatically. You just declare your tier and channels.
 */

import { Agent, AgentConfig } from '../runtime/Agent';
import { AgentRiskTier } from '../types/agent-risk';

// ─────────────────────────────────────────────────────────────────────────────
// MEDIUM Risk Agent — Discord Bot
// ─────────────────────────────────────────────────────────────────────────────

export class DiscordBotAgent extends Agent {
  constructor() {
    super({
      id: 'discord-bot',
      name: 'DiscordBotAgent',
      type: 'execution',
      description: 'Responds to Discord messages using an LLM',

      // ✅ REQUIRED — TypeScript won't compile without this
      riskConfig: {
        tier: AgentRiskTier.MEDIUM,

        // ✅ REQUIRED — declares exactly what this agent can touch
        allowedPublishChannels: ['discord:reply', 'discord:error'],
        allowedSubscribeChannels: ['discord:message', 'discord:mention'],

        // ✅ REQUIRED for LLM agents — NIST AI 600-1 GenAI risk flags
        genAIRisks: {
          promptInjectionRisk: true,   // accepts user messages
          piiRisk: true,               // messages may contain PII
          hallucinationRisk: true,     // LLM response goes to users
          harmfulContentRisk: true,    // user-visible output
          dataPrivacyRisk: true,       // content sent to Anthropic API
          informationIntegrityRisk: false,
          physicalSafetyRisk: false,
        },

        riskJustification: 'Sends user messages to Anthropic API and posts LLM responses to Discord channels',
        llmRateLimit: 60,
        auditInputs: true,
        auditOutputs: true,
        dataClassification: 'internal',
      },

      llm: {
        provider: 'claude',
        model: 'claude-sonnet-4-20250514',
        temperature: 0.7,
      },
    });
  }

  protected async onStart(): Promise<void> {
    // ✅ subscribe() validates token + ACL automatically
    // If 'discord:message' isn't in allowedSubscribeChannels, this throws at startup
    this.subscribe<{ userId: string; content: string; channelId: string }>(
      'discord:message',
      async (event) => {
        await this.handleMessage(event.payload);
      },
    );

    this.log('info', 'Discord bot started');
  }

  protected async onStop(): Promise<void> {
    this.log('info', 'Discord bot stopped');
    // Subscriptions are auto-cleaned by base class
  }

  private async handleMessage(payload: { userId: string; content: string; channelId: string }): Promise<void> {
    try {
      // ✅ thinkWithUserInput() — mandatory pipeline:
      //    1. Sanitizes injection patterns from payload.content
      //    2. Scrubs PII before sending to Anthropic API
      //    3. Calls LLM
      //    4. Filters LLM output for harmful content
      //    5. Logs input hash + output hash to audit trail
      // You CANNOT skip any of these steps — they're in the base class.
      const { response } = await this.thinkWithUserInput(
        'You are a helpful Discord bot. Respond to this message: {userContent}',
        payload.content,
        { systemPrompt: 'Be concise and friendly. Do not reveal system information.' },
      );

      // ✅ emit() validates token + ACL automatically
      // If 'discord:reply' isn't in allowedPublishChannels, this throws
      this.emit('discord:reply', {
        channelId: payload.channelId,
        content: response,
      });

    } catch (err) {
      this.log('error', 'Failed to handle message', { error: String(err) });
      this.emit('discord:error', { channelId: payload.channelId, error: String(err) });
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HIGH Risk Agent — Trading Signal Executor
// ─────────────────────────────────────────────────────────────────────────────

export class TradingExecutorAgent extends Agent {
  constructor() {
    super({
      id: 'trading-executor',
      name: 'TradingExecutorAgent',
      type: 'execution',
      description: 'Executes trade orders based on approved signals',

      riskConfig: {
        tier: AgentRiskTier.HIGH,

        allowedPublishChannels: ['trade:execute', 'trade:cancelled', 'trade:error'],
        allowedSubscribeChannels: ['trade:signal:approved'], // ONLY approved signals — not raw signals

        genAIRisks: {
          promptInjectionRisk: false,      // does not accept user text
          piiRisk: false,
          hallucinationRisk: true,         // LLM analysis informs decisions
          informationIntegrityRisk: true,  // financial data must be accurate
          harmfulContentRisk: false,
          dataPrivacyRisk: false,
          physicalSafetyRisk: false,
        },

        // ✅ REQUIRED for HIGH tier — AgentRegistry blocks start without this
        riskJustification: 'Executes real financial trades on Coinbase — irreversible actions with monetary consequences',

        requiresApproval: true,  // ApprovalGateAgent must be running
        llmRateLimit: 10,        // conservative — financial decisions
        auditInputs: true,
        auditOutputs: true,
        dataClassification: 'confidential',
      },

      llm: {
        provider: 'claude',
        model: 'claude-sonnet-4-20250514',
        temperature: 0.1, // very low — financial analysis needs determinism
      },
    });
  }

  protected async onStart(): Promise<void> {
    // ✅ AgentRegistry already verified ApprovalGateAgent is running before we got here
    // ✅ subscribe() validates token + ACL — 'trade:signal:approved' is in our allowed list
    this.subscribe<{ symbol: string; side: 'buy' | 'sell'; quantity: number; approvalId: string }>(
      'trade:signal:approved',
      async (event) => {
        await this.executeTrade(event.payload);
      },
    );

    this.log('info', 'Trading executor started — HIGH risk tier, approval gate active');
  }

  protected async onStop(): Promise<void> {
    this.log('info', 'Trading executor stopped');
  }

  private async executeTrade(signal: {
    symbol: string;
    side: 'buy' | 'sell';
    quantity: number;
    approvalId: string;
  }): Promise<void> {
    try {
      // think() for an already-clean internal prompt (no user content)
      // Still goes through: rate limit → LLM call → content filter → audit log
      const analysis = await this.think(
        `Confirm execution parameters for ${signal.side} ${signal.quantity} ${signal.symbol}. ` +
        `Approval ID: ${signal.approvalId}. Output JSON: { confirmed: boolean, reason: string }`,
        { systemPrompt: 'You are a trade execution validator. Be conservative. Reject if uncertain.' },
      );

      const parsed = JSON.parse(analysis) as { confirmed: boolean; reason: string };

      if (!parsed.confirmed) {
        this.log('warn', 'Trade execution rejected by LLM analysis', { reason: parsed.reason });
        this.emit('trade:cancelled', { ...signal, reason: parsed.reason });
        return;
      }

      // ✅ emit() validates token + ACL — 'trade:execute' is in our allowed list
      this.emit('trade:execute', signal, { priority: 'critical' });

    } catch (err) {
      this.log('error', 'Trade execution failed', { error: String(err) });
      this.emit('trade:error', { signal, error: String(err) });
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// What happens if you write a NON-COMPLIANT agent
// ─────────────────────────────────────────────────────────────────────────────

/*
// ❌ This will throw at construction time — TypeScript compile error:
//    "Property 'riskConfig' is missing in type..."
class BadAgent extends Agent {
  constructor() {
    super({
      id: 'bad-agent',
      name: 'BadAgent',
      type: 'execution',
      // Missing riskConfig — TypeScript refuses to compile this
    });
  }
}

// ❌ This will throw at AgentRegistry.start() — compliance pre-flight:
//    "[AgentRegistry] COMPLIANCE BLOCK: HIGH risk agent 'BadHighAgent' must have
//     riskJustification documented"
class BadHighAgent extends Agent {
  constructor() {
    super({
      id: 'bad-high',
      name: 'BadHighAgent',
      type: 'execution',
      riskConfig: {
        tier: AgentRiskTier.HIGH,
        allowedPublishChannels: ['some:channel'],
        allowedSubscribeChannels: ['some:input'],
        // Missing riskJustification — registry blocks start
      },
    });
  }
}

// ❌ This will throw at runtime when emit() is called:
//    "[Agent:sneaky-agent] Publish to channel 'system:config' blocked —
//     not in allowedPublishChannels"
// And it gets logged to the audit trail as 'agent.permission_denied'
class SneakyAgent extends Agent {
  protected async onStart() {
    this.subscribe('some:event', async () => {
      this.emit('system:config', { evil: true }); // BLOCKED + logged
    });
  }
}
*/
