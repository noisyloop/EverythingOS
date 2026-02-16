// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Secure Discord Bot
// Production-ready Discord integration with defense-in-depth security
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../core/event-bus/EventBus';
import {
  DiscordSecurityLayer,
  SecurityConfig,
  MessageContext,
  DEFAULT_SECURITY_CONFIG,
} from './DiscordSecurityLayer';
import {
  buildSystemPrompt,
  wrapUserMessage,
  sanitizeResponse,
  AgentPersonality,
  PRESET_PERSONALITIES,
} from './HardenedPrompts';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface DiscordBotConfig {
  // Bot token (from environment, never hardcoded)
  token?: string;  // Will use process.env.DISCORD_BOT_TOKEN if not provided
  
  // LLM settings
  llm: {
    provider: 'anthropic' | 'openai' | 'google' | 'ollama';
    model?: string;
    apiKey?: string;  // Will use environment variable if not provided
  };
  
  // Agent personality
  personality: AgentPersonality;
  
  // Security config (uses secure defaults if not provided)
  security?: Partial<SecurityConfig>;
  
  // Behavior
  triggerPrefix?: string;  // e.g., "!" or "@BotName" - if set, only responds to prefix
  respondToMentions: boolean;
  respondInThreads: boolean;
  typingIndicator: boolean;
  
  // Logging
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

export interface DiscordMessage {
  id: string;
  content: string;
  author: {
    id: string;
    username: string;
    bot: boolean;
  };
  channel: {
    id: string;
    name?: string;
    type: 'text' | 'dm' | 'thread';
  };
  guild?: {
    id: string;
    name: string;
  };
  mentions: {
    users: string[];
    roles: string[];
  };
  member?: {
    roles: string[];
  };
  timestamp: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Default Config
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_BOT_CONFIG: Partial<DiscordBotConfig> = {
  respondToMentions: true,
  respondInThreads: true,
  typingIndicator: true,
  logLevel: 'info',
};

// ─────────────────────────────────────────────────────────────────────────────
// Discord Bot Class
// ─────────────────────────────────────────────────────────────────────────────

export class DiscordBot {
  private config: DiscordBotConfig;
  private security: DiscordSecurityLayer;
  private systemPrompt: string;
  private client: any = null;  // discord.js Client (type any for now, actual type when discord.js is installed)
  private isRunning = false;
  private messageCount = 0;
  private startTime = 0;

  constructor(config: DiscordBotConfig) {
    // Merge with defaults
    this.config = { ...DEFAULT_BOT_CONFIG, ...config } as DiscordBotConfig;
    
    // Initialize security layer with merged config
    this.security = new DiscordSecurityLayer(config.security);
    
    // Build hardened system prompt
    this.systemPrompt = buildSystemPrompt(this.config.personality);
    
    // Log initialization (without sensitive data)
    this.log('info', `Discord bot initialized: ${this.config.personality.name}`);
    this.log('debug', `LLM provider: ${this.config.llm.provider}`);
    this.log('debug', `Security: DMs ${this.security.getConfig().allowDMs ? 'enabled' : 'disabled'}`);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  async start(): Promise<void> {
    if (this.isRunning) {
      this.log('warn', 'Bot is already running');
      return;
    }

    const token = this.config.token || process.env.DISCORD_BOT_TOKEN;
    if (!token) {
      throw new Error('Discord bot token not provided. Set DISCORD_BOT_TOKEN environment variable.');
    }

    // Validate token format (basic check)
    if (!this.validateTokenFormat(token)) {
      throw new Error('Invalid Discord bot token format');
    }

    try {
      // Dynamic import discord.js (only when starting)
      const { Client, GatewayIntentBits, Events } = await import('discord.js');
      
      this.client = new Client({
        intents: [
          GatewayIntentBits.Guilds,
          GatewayIntentBits.GuildMessages,
          GatewayIntentBits.MessageContent,
          GatewayIntentBits.DirectMessages,
        ],
      });

      // Set up event handlers
      this.client.once(Events.ClientReady, () => {
        this.onReady();
      });

      this.client.on(Events.MessageCreate, (message: any) => {
        this.onMessage(message).catch(err => {
          this.log('error', `Message handler error: ${err.message}`);
        });
      });

      // Login
      await this.client.login(token);
      
    } catch (error: any) {
      // Don't expose token in error messages
      const safeError = error.message.replace(/[\w-]{59}\.[\w-]{6}\.[\w-]{38}/g, '[TOKEN]');
      this.log('error', `Failed to start bot: ${safeError}`);
      throw new Error('Failed to connect to Discord. Check your bot token.');
    }
  }

  async stop(): Promise<void> {
    if (!this.isRunning) return;

    this.log('info', 'Stopping Discord bot...');
    
    if (this.client) {
      await this.client.destroy();
      this.client = null;
    }
    
    this.isRunning = false;
    eventBus.emit('discord:stopped', { uptime: Date.now() - this.startTime });
    this.log('info', 'Discord bot stopped');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Event Handlers
  // ─────────────────────────────────────────────────────────────────────────

  private onReady(): void {
    this.isRunning = true;
    this.startTime = Date.now();
    
    const username = this.client?.user?.tag || 'Unknown';
    this.log('info', `Discord bot ready: ${username}`);
    
    eventBus.emit('discord:ready', {
      username,
      personality: this.config.personality.name,
    });
  }

  private async onMessage(discordMessage: any): Promise<void> {
    // Ignore bot messages (including our own)
    if (discordMessage.author.bot) return;

    // Convert to our message format
    const message = this.convertMessage(discordMessage);

    // Check if we should respond
    if (!this.shouldRespond(message, discordMessage)) return;

    // Extract the actual content (remove mention/prefix)
    const content = this.extractContent(message.content, discordMessage);
    if (!content.trim()) return;

    // Build security context
    const ctx: MessageContext = {
      messageId: message.id,
      userId: message.author.id,
      username: message.author.username,
      channelId: message.channel.id,
      serverId: message.guild?.id || null,
      content,
      timestamp: message.timestamp,
      isDM: message.channel.type === 'dm',
      userRoles: message.member?.roles || [],
    };

    // Run through security layer
    const securityResult = await this.security.validateMessage(ctx);

    if (!securityResult.allowed) {
      this.log('info', `Message blocked: ${securityResult.reason}`);
      
      // Optionally respond with rate limit message
      if (securityResult.reason === 'rate_limited') {
        await this.safeReply(discordMessage, this.security.getConfig().rateLimitMessage);
      }
      
      eventBus.emit('discord:message:blocked', {
        userId: ctx.userId,
        reason: securityResult.reason,
        threatLevel: securityResult.threatLevel,
      });
      return;
    }

    // Log high threat level even if allowed
    if (securityResult.threatLevel !== 'none') {
      this.log('warn', `Suspicious message from ${message.author.username}: ${securityResult.flags.join(', ')}`);
    }

    // Show typing indicator
    if (this.config.typingIndicator) {
      discordMessage.channel.sendTyping().catch(() => {});
    }

    // Generate response
    try {
      this.messageCount++;
      
      const response = await this.generateResponse(
        securityResult.sanitizedContent || content,
        message.author.username,
        message.channel.name
      );

      // Validate and sanitize output
      const outputResult = this.security.validateOutput(response);
      
      if (outputResult.flags.length > 0) {
        this.log('warn', `Output flags: ${outputResult.flags.join(', ')}`);
      }

      // Send response
      await this.safeReply(discordMessage, outputResult.sanitized);
      
      eventBus.emit('discord:message:handled', {
        messageId: message.id,
        responseLength: outputResult.sanitized.length,
      });
      
    } catch (error: any) {
      this.log('error', `Response generation failed: ${error.message}`);
      await this.safeReply(discordMessage, this.security.getConfig().errorMessage);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Response Generation
  // ─────────────────────────────────────────────────────────────────────────

  private async generateResponse(
    content: string,
    username: string,
    channelName?: string
  ): Promise<string> {
    // Wrap user message with context
    const wrappedMessage = wrapUserMessage(content, username, channelName);

    // Call LLM
    const response = await this.callLLM(wrappedMessage);

    // Sanitize response
    return sanitizeResponse(response);
  }

  private async callLLM(userMessage: string): Promise<string> {
    const provider = this.config.llm.provider;
    
    switch (provider) {
      case 'anthropic':
        return this.callAnthropic(userMessage);
      case 'openai':
        return this.callOpenAI(userMessage);
      case 'google':
        return this.callGoogle(userMessage);
      case 'ollama':
        return this.callOllama(userMessage);
      default:
        throw new Error(`Unknown LLM provider: ${provider}`);
    }
  }

  private async callAnthropic(userMessage: string): Promise<string> {
    const apiKey = this.config.llm.apiKey || process.env.ANTHROPIC_API_KEY;
    if (!apiKey) throw new Error('ANTHROPIC_API_KEY not set');

    const model = this.config.llm.model || 'claude-sonnet-4-20250514';
    
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model,
        max_tokens: 1024,
        system: this.systemPrompt,
        messages: [{ role: 'user', content: userMessage }],
      }),
    });

    if (!response.ok) {
      throw new Error(`Anthropic API error: ${response.status}`);
    }

    const data = await response.json();
    return data.content[0]?.text || 'I could not generate a response.';
  }

  private async callOpenAI(userMessage: string): Promise<string> {
    const apiKey = this.config.llm.apiKey || process.env.OPENAI_API_KEY;
    if (!apiKey) throw new Error('OPENAI_API_KEY not set');

    const model = this.config.llm.model || 'gpt-4o';

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        max_tokens: 1024,
        messages: [
          { role: 'system', content: this.systemPrompt },
          { role: 'user', content: userMessage },
        ],
      }),
    });

    if (!response.ok) {
      throw new Error(`OpenAI API error: ${response.status}`);
    }

    const data = await response.json();
    return data.choices[0]?.message?.content || 'I could not generate a response.';
  }

  private async callGoogle(userMessage: string): Promise<string> {
    const apiKey = this.config.llm.apiKey || process.env.GOOGLE_API_KEY;
    if (!apiKey) throw new Error('GOOGLE_API_KEY not set');

    const model = this.config.llm.model || 'gemini-pro';
    
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1/models/${model}:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{
            parts: [{ text: `${this.systemPrompt}\n\n${userMessage}` }],
          }],
          generationConfig: { maxOutputTokens: 1024 },
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Google API error: ${response.status}`);
    }

    const data = await response.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || 'I could not generate a response.';
  }

  private async callOllama(userMessage: string): Promise<string> {
    const model = this.config.llm.model || 'llama2';
    const baseUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';

    const response = await fetch(`${baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: this.systemPrompt },
          { role: 'user', content: userMessage },
        ],
        stream: false,
      }),
    });

    if (!response.ok) {
      throw new Error(`Ollama API error: ${response.status}`);
    }

    const data = await response.json();
    return data.message?.content || 'I could not generate a response.';
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Helpers
  // ─────────────────────────────────────────────────────────────────────────

  private convertMessage(discordMessage: any): DiscordMessage {
    return {
      id: discordMessage.id,
      content: discordMessage.content,
      author: {
        id: discordMessage.author.id,
        username: discordMessage.author.username,
        bot: discordMessage.author.bot,
      },
      channel: {
        id: discordMessage.channel.id,
        name: discordMessage.channel.name,
        type: discordMessage.channel.isDMBased() ? 'dm' : 
              discordMessage.channel.isThread() ? 'thread' : 'text',
      },
      guild: discordMessage.guild ? {
        id: discordMessage.guild.id,
        name: discordMessage.guild.name,
      } : undefined,
      mentions: {
        users: discordMessage.mentions.users.map((u: any) => u.id),
        roles: discordMessage.mentions.roles.map((r: any) => r.id),
      },
      member: discordMessage.member ? {
        roles: discordMessage.member.roles.cache.map((r: any) => r.id),
      } : undefined,
      timestamp: discordMessage.createdTimestamp,
    };
  }

  private shouldRespond(message: DiscordMessage, discordMessage: any): boolean {
    // Always respond in DMs (if enabled by security)
    if (message.channel.type === 'dm') return true;

    // Check if we should respond in threads
    if (message.channel.type === 'thread' && !this.config.respondInThreads) {
      return false;
    }

    // Check for prefix
    if (this.config.triggerPrefix) {
      return message.content.startsWith(this.config.triggerPrefix);
    }

    // Check for mention
    if (this.config.respondToMentions && this.client?.user) {
      return message.mentions.users.includes(this.client.user.id);
    }

    return false;
  }

  private extractContent(content: string, discordMessage: any): string {
    let extracted = content;

    // Remove prefix
    if (this.config.triggerPrefix && extracted.startsWith(this.config.triggerPrefix)) {
      extracted = extracted.slice(this.config.triggerPrefix.length);
    }

    // Remove bot mention
    if (this.client?.user) {
      extracted = extracted.replace(new RegExp(`<@!?${this.client.user.id}>`, 'g'), '');
    }

    return extracted.trim();
  }

  private async safeReply(discordMessage: any, content: string): Promise<void> {
    try {
      // Split long messages
      const chunks = this.splitMessage(content, 2000);
      
      for (const chunk of chunks) {
        await discordMessage.reply({
          content: chunk,
          allowedMentions: { repliedUser: false },  // Don't ping the user
        });
      }
    } catch (error: any) {
      this.log('error', `Failed to send reply: ${error.message}`);
    }
  }

  private splitMessage(content: string, maxLength: number): string[] {
    if (content.length <= maxLength) return [content];

    const chunks: string[] = [];
    let remaining = content;

    while (remaining.length > 0) {
      if (remaining.length <= maxLength) {
        chunks.push(remaining);
        break;
      }

      // Try to split at a newline
      let splitIndex = remaining.lastIndexOf('\n', maxLength);
      if (splitIndex === -1 || splitIndex < maxLength / 2) {
        // Try to split at a space
        splitIndex = remaining.lastIndexOf(' ', maxLength);
      }
      if (splitIndex === -1 || splitIndex < maxLength / 2) {
        // Force split at max length
        splitIndex = maxLength;
      }

      chunks.push(remaining.slice(0, splitIndex));
      remaining = remaining.slice(splitIndex).trim();
    }

    return chunks;
  }

  private validateTokenFormat(token: string): boolean {
    // Discord tokens have a specific format: BASE64.BASE64.BASE64
    // This is a basic check, not a full validation
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    if (token.length < 50 || token.length > 100) return false;
    return true;
  }

  private log(level: DiscordBotConfig['logLevel'], message: string): void {
    const levels = ['debug', 'info', 'warn', 'error'];
    const configLevel = levels.indexOf(this.config.logLevel);
    const msgLevel = levels.indexOf(level);

    if (msgLevel >= configLevel) {
      const timestamp = new Date().toISOString();
      const prefix = `[${timestamp}] [Discord] [${level.toUpperCase()}]`;
      console.log(`${prefix} ${message}`);
    }

    eventBus.emit('discord:log', { level, message, timestamp: Date.now() });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public Methods
  // ─────────────────────────────────────────────────────────────────────────

  getStats(): {
    isRunning: boolean;
    uptime: number;
    messageCount: number;
    securityStats: ReturnType<DiscordSecurityLayer['getStats']>;
  } {
    return {
      isRunning: this.isRunning,
      uptime: this.isRunning ? Date.now() - this.startTime : 0,
      messageCount: this.messageCount,
      securityStats: this.security.getStats(),
    };
  }

  getSecurity(): DiscordSecurityLayer {
    return this.security;
  }

  updatePersonality(personality: AgentPersonality): void {
    this.config.personality = personality;
    this.systemPrompt = buildSystemPrompt(personality);
    this.log('info', `Personality updated to: ${personality.name}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory Function
// ─────────────────────────────────────────────────────────────────────────────

export function createDiscordBot(config: Partial<DiscordBotConfig> = {}): DiscordBot {
  const fullConfig: DiscordBotConfig = {
    llm: config.llm || { provider: 'anthropic' },
    personality: config.personality || PRESET_PERSONALITIES.default,
    respondToMentions: config.respondToMentions ?? true,
    respondInThreads: config.respondInThreads ?? true,
    typingIndicator: config.typingIndicator ?? true,
    logLevel: config.logLevel || 'info',
    ...config,
  };

  return new DiscordBot(fullConfig);
}
