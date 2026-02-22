// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Capability Discovery
// Agents ask "What can the system do right now?"
// Enables dynamic planning and graceful degradation
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../core/event-bus/EventBus';
import { agentRegistry } from '../../core/registry/AgentRegistry';
import { pluginRegistry } from '../../core/registry/PluginRegistry';
import { toolRegistry } from '../tools';
import { workflowRegistry } from '../../core/workflow/WorkflowRegistry';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type CapabilityType = 'tool' | 'plugin' | 'agent' | 'workflow' | 'action';

export type CapabilityStatus = 
  | 'available'      // Ready to use
  | 'unavailable'    // Not available (missing config, etc)
  | 'degraded'       // Working but with limitations
  | 'permission'     // Needs permission
  | 'approval';      // Needs approval each use

export interface Capability {
  type: CapabilityType;
  name: string;
  description?: string;
  status: CapabilityStatus;
  reason?: string;           // Why unavailable/degraded
  metadata?: Record<string, unknown>;
}

export interface CapabilityCheck {
  available: boolean;
  status: CapabilityStatus;
  reason?: string;
  alternatives?: string[];   // Alternative capabilities if this one unavailable
}

export interface SystemCapabilities {
  tools: Capability[];
  plugins: Capability[];
  agents: Capability[];
  workflows: Capability[];
  summary: {
    totalTools: number;
    availableTools: number;
    totalPlugins: number;
    availablePlugins: number;
    totalAgents: number;
    runningAgents: number;
    totalWorkflows: number;
    activeWorkflows: number;
  };
}

export interface AgentCapabilities {
  agentId: string;
  tools: Capability[];
  plugins: Capability[];
  canDelegate: string[];     // Agent IDs this agent can delegate to
  canEscalate: boolean;      // Can escalate to human
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability Discovery Service
// ─────────────────────────────────────────────────────────────────────────────

export class CapabilityDiscovery {
  // ─────────────────────────────────────────────────────────────────────────
  // Full System Discovery
  // ─────────────────────────────────────────────────────────────────────────

  discover(): SystemCapabilities {
    const tools = this.discoverTools();
    const plugins = this.discoverPlugins();
    const agents = this.discoverAgents();
    const workflows = this.discoverWorkflows();

    return {
      tools,
      plugins,
      agents,
      workflows,
      summary: {
        totalTools: tools.length,
        availableTools: tools.filter(t => t.status === 'available').length,
        totalPlugins: plugins.length,
        availablePlugins: plugins.filter(p => p.status === 'available').length,
        totalAgents: agents.length,
        runningAgents: agents.filter(a => a.status === 'available').length,
        totalWorkflows: workflows.length,
        activeWorkflows: workflows.filter(w => w.status === 'available').length,
      },
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Agent-Specific Discovery
  // ─────────────────────────────────────────────────────────────────────────

  discoverForAgent(agentId: string): AgentCapabilities {
    // Get tools this agent can use
    const agentTools = toolRegistry.getAgentTools(agentId);
    const tools: Capability[] = agentTools.map(tool => ({
      type: 'tool',
      name: tool.name,
      description: tool.description,
      status: tool.requiresApproval ? 'approval' : 'available',
      metadata: {
        category: tool.category,
        trustLevel: tool.trustLevel,
      },
    }));

    // Get plugins
    const plugins = this.discoverPlugins();

    // Get agents this agent can delegate to (all other running agents)
    const canDelegate = agentRegistry.getAll()
      .filter(a => a.id !== agentId && a.getStatus() === 'running')
      .map(a => a.id);

    return {
      agentId,
      tools,
      plugins,
      canDelegate,
      canEscalate: true, // TODO: Make configurable
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Individual Capability Checks
  // ─────────────────────────────────────────────────────────────────────────

  can(type: CapabilityType, name: string, agentId?: string): CapabilityCheck {
    switch (type) {
      case 'tool':
        return this.canUseTool(name, agentId);
      case 'plugin':
        return this.canUsePlugin(name);
      case 'agent':
        return this.canUseAgent(name);
      case 'workflow':
        return this.canUseWorkflow(name);
      case 'action':
        return this.canUseAction(name);
      default:
        return { available: false, status: 'unavailable', reason: `Unknown capability type: ${type}` };
    }
  }

  private canUseTool(name: string, agentId?: string): CapabilityCheck {
    const tool = toolRegistry.get(name);
    
    if (!tool) {
      // Check for alternatives
      const alternatives = this.findAlternativeTools(name);
      return {
        available: false,
        status: 'unavailable',
        reason: `Tool not found: ${name}`,
        alternatives,
      };
    }

    if (tool.deprecated) {
      return {
        available: true,
        status: 'degraded',
        reason: tool.deprecationMessage || 'Tool is deprecated',
      };
    }

    if (agentId && !toolRegistry.hasPermission(agentId, name)) {
      return {
        available: false,
        status: 'permission',
        reason: `Agent ${agentId} lacks permission for tool ${name}`,
      };
    }

    if (tool.requiresApproval) {
      return {
        available: true,
        status: 'approval',
        reason: 'Tool requires approval for each use',
      };
    }

    return { available: true, status: 'available' };
  }

  private canUsePlugin(name: string): CapabilityCheck {
    const plugin = pluginRegistry.get(name);
    
    if (!plugin) {
      return {
        available: false,
        status: 'unavailable',
        reason: `Plugin not found: ${name}`,
      };
    }

    // TODO: Check if plugin is properly configured (has required API keys, etc)
    return { available: true, status: 'available' };
  }

  private canUseAgent(agentId: string): CapabilityCheck {
    const agent = agentRegistry.get(agentId);
    
    if (!agent) {
      return {
        available: false,
        status: 'unavailable',
        reason: `Agent not found: ${agentId}`,
      };
    }

    if (agent.getStatus() !== 'running') {
      return {
        available: false,
        status: 'unavailable',
        reason: `Agent not running (status: ${agent.getStatus()})`,
      };
    }

    return { available: true, status: 'available' };
  }

  private canUseWorkflow(workflowId: string): CapabilityCheck {
    const workflow = workflowRegistry.get(workflowId);
    
    if (!workflow) {
      return {
        available: false,
        status: 'unavailable',
        reason: `Workflow not found: ${workflowId}`,
      };
    }

    if (workflow.status !== 'active') {
      return {
        available: false,
        status: 'unavailable',
        reason: `Workflow not active (status: ${workflow.status})`,
      };
    }

    return { available: true, status: 'available' };
  }

  private canUseAction(action: string): CapabilityCheck {
    // Action format: "plugin:action"
    const [pluginId, actionName] = action.split(':');
    
    if (!pluginId || !actionName) {
      return {
        available: false,
        status: 'unavailable',
        reason: `Invalid action format: ${action}. Expected "plugin:action"`,
      };
    }

    const pluginAction = pluginRegistry.getAction(pluginId, actionName);
    
    if (!pluginAction) {
      return {
        available: false,
        status: 'unavailable',
        reason: `Action not found: ${action}`,
      };
    }

    return { available: true, status: 'available' };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Discovery Helpers
  // ─────────────────────────────────────────────────────────────────────────

  private discoverTools(): Capability[] {
    return toolRegistry.list().map(tool => ({
      type: 'tool' as const,
      name: tool.name,
      description: tool.description,
      status: this.getToolStatus(tool),
      reason: tool.deprecated ? tool.deprecationMessage : undefined,
      metadata: {
        category: tool.category,
        trustLevel: tool.trustLevel,
        version: tool.version,
      },
    }));
  }

  private getToolStatus(tool: { deprecated?: boolean; requiresApproval?: boolean }): CapabilityStatus {
    if (tool.deprecated) return 'degraded';
    if (tool.requiresApproval) return 'approval';
    return 'available';
  }

  private discoverPlugins(): Capability[] {
    return pluginRegistry.getAll().map(plugin => ({
      type: 'plugin' as const,
      name: plugin.id,
      description: plugin.description,
      status: 'available' as const, // TODO: Check config status
      metadata: {
        version: plugin.version,
        actions: plugin.actions.map(a => a.name),
      },
    }));
  }

  private discoverAgents(): Capability[] {
    return agentRegistry.getAll().map(agent => ({
      type: 'agent' as const,
      name: agent.id,
      description: agent.getConfig().description,
      status: agent.getStatus() === 'running' ? 'available' as const : 'unavailable' as const,
      reason: agent.getStatus() !== 'running' ? `Agent status: ${agent.getStatus()}` : undefined,
      metadata: {
        type: agent.getConfig().type,
        tags: agent.getConfig().tags,
      },
    }));
  }

  private discoverWorkflows(): Capability[] {
    return workflowRegistry.list().map(workflow => ({
      type: 'workflow' as const,
      name: workflow.id,
      description: workflow.description,
      status: workflow.status === 'active' ? 'available' as const : 'unavailable' as const,
      reason: workflow.status !== 'active' ? `Workflow status: ${workflow.status}` : undefined,
      metadata: {
        version: workflow.version,
        triggers: workflow.triggers?.map(t => t.type),
      },
    }));
  }

  private findAlternativeTools(name: string): string[] {
    // Simple alternative finding based on category
    const allTools = toolRegistry.list();
    
    // Find tools with similar names or in same category
    const nameParts = name.toLowerCase().split(/[_-]/);
    
    return allTools
      .filter(t => {
        const toolParts = t.name.toLowerCase().split(/[_-]/);
        return nameParts.some(p => toolParts.includes(p));
      })
      .map(t => t.name)
      .slice(0, 3);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Prompt Generation
  // ─────────────────────────────────────────────────────────────────────────

  generateCapabilityPrompt(agentId: string): string {
    const caps = this.discoverForAgent(agentId);
    const lines: string[] = ['# Available Capabilities', ''];

    // Tools
    if (caps.tools.length > 0) {
      lines.push('## Tools');
      for (const tool of caps.tools) {
        const status = tool.status === 'available' ? '✓' : 
                      tool.status === 'approval' ? '⚠️ requires approval' : '✗';
        lines.push(`- ${tool.name} ${status}`);
        if (tool.description) lines.push(`  ${tool.description}`);
      }
      lines.push('');
    }

    // Delegation
    if (caps.canDelegate.length > 0) {
      lines.push('## Can Delegate To');
      for (const agentId of caps.canDelegate) {
        lines.push(`- ${agentId}`);
      }
      lines.push('');
    }

    // Escalation
    if (caps.canEscalate) {
      lines.push('## Escalation');
      lines.push('- Can escalate to human when needed');
      lines.push('');
    }

    return lines.join('\n');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Requirement Checking
  // ─────────────────────────────────────────────────────────────────────────

  checkRequirements(requirements: CapabilityRequirement[], agentId?: string): RequirementCheckResult {
    const results: RequirementCheckResult['checks'] = [];
    let allMet = true;

    for (const req of requirements) {
      const check = this.can(req.type, req.name, agentId);
      const met = req.required ? check.available : true;
      
      if (req.required && !check.available) {
        allMet = false;
      }

      results.push({
        requirement: req,
        met,
        check,
      });
    }

    return { allMet, checks: results };
  }
}

export interface CapabilityRequirement {
  type: CapabilityType;
  name: string;
  required: boolean;
  reason?: string;
}

export interface RequirementCheckResult {
  allMet: boolean;
  checks: Array<{
    requirement: CapabilityRequirement;
    met: boolean;
    check: CapabilityCheck;
  }>;
}

// Singleton export
export const capabilityDiscovery = new CapabilityDiscovery();
