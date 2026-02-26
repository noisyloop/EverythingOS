// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - MCP Tool Adapter
// Bridges MCP server tools into the EverythingOS ToolRegistry so they appear
// as native tools, fully subject to existing trust/permission/approval gates.
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../core/event-bus/EventBus';
import { toolRegistry } from '../../services/tools/ToolRegistry';
import { Tool, ToolTrustLevel } from '../../services/tools/ToolTypes';
import { MCPClient } from './MCPClient';
import { MCPTool } from './MCPTypes';

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

export interface MCPToolAdapterConfig {
  /** Must match MCPClientConfig.serverName — used to namespace tool names. */
  serverName: string;
  /**
   * Trust level applied to every tool from this server.
   * Defaults to 'sensitive' (approval required per ToolRegistry policy).
   */
  trustLevel?: ToolTrustLevel;
  /**
   * Whether every call requires explicit supervisor approval.
   * Defaults to true — all remote tool calls are gated on first use.
   */
  requiresApproval?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP Tool Adapter
// ─────────────────────────────────────────────────────────────────────────────

export class MCPToolAdapter {
  private client: MCPClient;
  private config: Required<MCPToolAdapterConfig>;
  private registeredTools: string[] = [];

  constructor(client: MCPClient, config: MCPToolAdapterConfig) {
    this.client = client;
    this.config = {
      trustLevel:       'sensitive',
      requiresApproval: true,
      ...config,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Registration
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Fetch the tool list from the connected MCP server and register every tool
   * in the ToolRegistry under the namespace `mcp:<serverName>:<toolName>`.
   * Safe to call again after a reconnect — already-registered versions are
   * silently skipped.
   */
  async registerTools(): Promise<void> {
    const mcpTools = await this.client.listTools();

    for (const mcpTool of mcpTools) {
      this.registerOneTool(mcpTool);
    }

    eventBus.emit('mcp:tools:registered', {
      serverName: this.config.serverName,
      count:      mcpTools.length,
      tools:      [...this.registeredTools],
    });
  }

  /**
   * Remove all tools registered by this adapter from the ToolRegistry.
   * Call on disconnect / server removal.
   */
  unregisterTools(): void {
    for (const toolName of this.registeredTools) {
      toolRegistry.unregister(toolName);
    }
    this.registeredTools = [];

    eventBus.emit('mcp:tools:unregistered', { serverName: this.config.serverName });
  }

  getRegisteredToolNames(): string[] {
    return [...this.registeredTools];
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Security Mapping
  // ─────────────────────────────────────────────────────────────────────────
  //
  //  MCP tool action              │ EverythingOS gate
  //  ─────────────────────────────┼──────────────────────────────────────────
  //  Any tool call                │ Permission check via ToolRegistry
  //  trustLevel = 'sensitive'     │ requiresApproval → supervisor gate
  //  Network-bound calls          │ Rate limited via plugin trust levels
  //  All calls                    │ Audit logged via ToolRegistry execution log

  private registerOneTool(mcpTool: MCPTool): void {
    const toolName = `mcp:${this.config.serverName}:${mcpTool.name}`;

    const tool: Tool = {
      name:             toolName,
      version:          '1.0.0',
      description:      mcpTool.description,
      category:         'network',
      trustLevel:       this.config.trustLevel,
      requiresApproval: this.config.requiresApproval,
      tags:             ['mcp', this.config.serverName],

      // MCP already delivers JSON Schema — map it straight through.
      inputSchema: {
        type:        'object',
        properties:  mcpTool.inputSchema.properties as Tool['inputSchema']['properties'],
        required:    mcpTool.inputSchema.required,
        description: mcpTool.inputSchema.description,
      },

      handler: async (args) => {
        const result = await this.client.callTool(
          mcpTool.name,
          args as Record<string, unknown>,
        );

        // Flatten MCP content array to a single text payload when possible.
        const textParts = result.content
          .filter((c) => c.type === 'text' && c.text !== undefined)
          .map((c)    => c.text!);

        const text = textParts.join('\n');

        return {
          success: !result.isError,
          data:    text || result.content,
          error:   result.isError ? (text || 'MCP tool returned an error') : undefined,
        };
      },
    };

    try {
      toolRegistry.register(tool);
      this.registeredTools.push(toolName);

      eventBus.emit('mcp:tool:discovered', {
        serverName: this.config.serverName,
        toolName,
        mcpName:    mcpTool.name,
      });
    } catch (err) {
      // Already registered at the same version — skip silently on reconnects.
      const alreadyExists = err instanceof Error && err.message.includes('already registered');
      if (!alreadyExists) {
        eventBus.emit('mcp:error', {
          serverName: this.config.serverName,
          error: `Failed to register tool ${toolName}: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }
  }
}
