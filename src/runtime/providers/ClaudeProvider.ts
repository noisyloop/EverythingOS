// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Claude Provider
// ═══════════════════════════════════════════════════════════════════════════════

import type { LLMProvider, LLMRequest, LLMResponse, LLMMessage } from '../LLMRouter';
import { getSecret } from '../../security/secrets-provider';

export class ClaudeProvider implements LLMProvider {
  readonly name = 'claude';
  private apiKey: string | undefined;
  private baseUrl = 'https://api.anthropic.com/v1';

  constructor(apiKey?: string) {
    this.apiKey = apiKey || getSecret('ANTHROPIC_API_KEY');
  }

  async complete(request: Omit<LLMRequest, 'provider'>): Promise<LLMResponse> {
    if (!this.apiKey) {
      throw new Error('Anthropic API key not configured');
    }

    const systemMessage = request.messages.find(m => m.role === 'system');
    const otherMessages = request.messages.filter(m => m.role !== 'system');

    const response = await fetch(`${this.baseUrl}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: request.model || 'claude-sonnet-4-20250514',
        max_tokens: request.maxTokens || 4096,
        system: systemMessage?.content,
        messages: otherMessages.map(m => ({
          role: m.role === 'assistant' ? 'assistant' : 'user',
          content: m.content,
        })),
        temperature: request.temperature ?? 0.7,
        stop_sequences: request.stopSequences,
        tools: request.tools?.map(t => ({
          name: t.name,
          description: t.description,
          input_schema: t.parameters,
        })),
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Claude API error: ${response.status} - ${error}`);
    }

    const data = await response.json();

    let content = '';
    const toolCalls: LLMResponse['toolCalls'] = [];

    for (const block of data.content) {
      if (block.type === 'text') {
        content += block.text;
      } else if (block.type === 'tool_use') {
        toolCalls.push({
          id: block.id,
          name: block.name,
          arguments: block.input,
        });
      }
    }

    return {
      content,
      finishReason: this.mapStopReason(data.stop_reason),
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      usage: data.usage ? {
        promptTokens: data.usage.input_tokens,
        completionTokens: data.usage.output_tokens,
        totalTokens: data.usage.input_tokens + data.usage.output_tokens,
      } : undefined,
    };
  }

  async *stream(request: Omit<LLMRequest, 'provider'>): AsyncIterable<string> {
    if (!this.apiKey) {
      throw new Error('Anthropic API key not configured');
    }

    const systemMessage = request.messages.find(m => m.role === 'system');
    const otherMessages = request.messages.filter(m => m.role !== 'system');

    const response = await fetch(`${this.baseUrl}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: request.model || 'claude-sonnet-4-20250514',
        max_tokens: request.maxTokens || 4096,
        system: systemMessage?.content,
        messages: otherMessages.map(m => ({
          role: m.role === 'assistant' ? 'assistant' : 'user',
          content: m.content,
        })),
        temperature: request.temperature ?? 0.7,
        stream: true,
      }),
    });

    if (!response.ok) {
      throw new Error(`Claude API error: ${response.status}`);
    }

    const reader = response.body?.getReader();
    if (!reader) throw new Error('No response body');

    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const data = JSON.parse(line.slice(6));
            if (data.type === 'content_block_delta' && data.delta?.text) {
              yield data.delta.text;
            }
          } catch {}
        }
      }
    }
  }

  private mapStopReason(reason: string): LLMResponse['finishReason'] {
    switch (reason) {
      case 'end_turn': return 'stop';
      case 'max_tokens': return 'length';
      case 'tool_use': return 'tool_call';
      default: return 'stop';
    }
  }
}
