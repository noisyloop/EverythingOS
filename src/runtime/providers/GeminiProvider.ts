// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Gemini Provider
// ═══════════════════════════════════════════════════════════════════════════════

import type { LLMProvider, LLMRequest, LLMResponse } from '../LLMRouter';
import { getSecret } from '../../security/secrets-provider';

export class GeminiProvider implements LLMProvider {
  readonly name = 'gemini';
  private apiKey: string | undefined;
  private baseUrl = 'https://generativelanguage.googleapis.com/v1beta';

  constructor(apiKey?: string) {
    this.apiKey = apiKey || getSecret('GOOGLE_API_KEY');
  }

  async complete(request: Omit<LLMRequest, 'provider'>): Promise<LLMResponse> {
    if (!this.apiKey) {
      throw new Error('Google API key not configured');
    }

    const model = request.model || 'gemini-pro';
    const systemInstruction = request.messages.find(m => m.role === 'system')?.content;
    const contents = request.messages
      .filter(m => m.role !== 'system')
      .map(m => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }],
      }));

    const response = await fetch(
      `${this.baseUrl}/models/${model}:generateContent?key=${this.apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents,
          systemInstruction: systemInstruction ? { parts: [{ text: systemInstruction }] } : undefined,
          generationConfig: {
            temperature: request.temperature ?? 0.7,
            maxOutputTokens: request.maxTokens,
            stopSequences: request.stopSequences,
          },
          tools: request.tools?.length ? [{
            functionDeclarations: request.tools.map(t => ({
              name: t.name,
              description: t.description,
              parameters: t.parameters,
            })),
          }] : undefined,
        }),
      }
    );

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Gemini API error: ${response.status} - ${error}`);
    }

    const data = await response.json();
    const candidate = data.candidates?.[0];

    if (!candidate) {
      throw new Error('No response from Gemini');
    }

    let content = '';
    const toolCalls: LLMResponse['toolCalls'] = [];

    for (const part of candidate.content?.parts || []) {
      if (part.text) {
        content += part.text;
      } else if (part.functionCall) {
        toolCalls.push({
          id: `fc_${Date.now()}`,
          name: part.functionCall.name,
          arguments: part.functionCall.args,
        });
      }
    }

    return {
      content,
      finishReason: this.mapFinishReason(candidate.finishReason),
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      usage: data.usageMetadata ? {
        promptTokens: data.usageMetadata.promptTokenCount,
        completionTokens: data.usageMetadata.candidatesTokenCount,
        totalTokens: data.usageMetadata.totalTokenCount,
      } : undefined,
    };
  }

  async *stream(request: Omit<LLMRequest, 'provider'>): AsyncIterable<string> {
    if (!this.apiKey) {
      throw new Error('Google API key not configured');
    }

    const model = request.model || 'gemini-pro';
    const contents = request.messages
      .filter(m => m.role !== 'system')
      .map(m => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }],
      }));

    const response = await fetch(
      `${this.baseUrl}/models/${model}:streamGenerateContent?key=${this.apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents,
          generationConfig: {
            temperature: request.temperature ?? 0.7,
            maxOutputTokens: request.maxTokens,
          },
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Gemini API error: ${response.status}`);
    }

    const reader = response.body?.getReader();
    if (!reader) throw new Error('No response body');

    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      
      // Gemini streams JSON objects
      try {
        const chunks = buffer.split('\n').filter(l => l.trim());
        for (const chunk of chunks) {
          const data = JSON.parse(chunk);
          const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) yield text;
        }
        buffer = '';
      } catch {
        // Incomplete JSON, keep buffering
      }
    }
  }

  private mapFinishReason(reason: string): LLMResponse['finishReason'] {
    switch (reason) {
      case 'STOP': return 'stop';
      case 'MAX_TOKENS': return 'length';
      case 'SAFETY': return 'error';
      default: return 'stop';
    }
  }
}
