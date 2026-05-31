// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Workflow Engine
// Executes workflow definitions
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../event-bus/EventBus';
import {
  WorkflowDefinition,
  WorkflowExecution,
  WorkflowNode,
  WorkflowData,
  NodeHandler,
  NodeContext,
  NodeResult,
  ExecutionLog,
  ExecutionStatus,
} from './WorkflowTypes';

export class WorkflowEngine {
  private handlers: Map<string, NodeHandler> = new Map();
  private executions: Map<string, WorkflowExecution> = new Map();

  constructor() {
    this.registerBuiltInHandlers();
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Handler Registration
  // ─────────────────────────────────────────────────────────────────────────────

  registerHandler(type: string, handler: NodeHandler): void {
    this.handlers.set(type, handler);
  }

  registerPluginHandler(plugin: string, action: string, handler: NodeHandler): void {
    this.handlers.set(`${plugin}:${action}`, handler);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Execution
  // ─────────────────────────────────────────────────────────────────────────────

  async execute(
    workflow: WorkflowDefinition,
    input: Record<string, unknown> = {},
    triggeredBy?: WorkflowExecution['triggeredBy']
  ): Promise<WorkflowExecution> {
    const execution = this.createExecution(workflow, input, triggeredBy);
    this.executions.set(execution.id, execution);

    eventBus.emit('workflow:started', { executionId: execution.id, workflowId: workflow.id });

    try {
      const triggerNodes = workflow.nodes.filter(n => n.type === 'trigger');
      if (triggerNodes.length === 0) {
        throw new Error('Workflow has no trigger nodes');
      }

      for (const trigger of triggerNodes) {
        await this.executeNode(workflow, execution, trigger.id);
      }

      execution.status = 'completed';
      execution.completedAt = Date.now();
      eventBus.emit('workflow:completed', { executionId: execution.id });

    } catch (error) {
      execution.status = 'failed';
      execution.error = error instanceof Error ? error.message : String(error);
      execution.completedAt = Date.now();
      eventBus.emit('workflow:failed', { executionId: execution.id, error: execution.error });
    }

    return execution;
  }

  private async executeNode(
    workflow: WorkflowDefinition,
    execution: WorkflowExecution,
    nodeId: string
  ): Promise<void> {
    const node = workflow.nodes.find(n => n.id === nodeId);
    if (!node) return;

    execution.currentNodes = [nodeId];
    const nodeOutput = execution.data.nodes[nodeId] || { status: 'pending' };
    nodeOutput.status = 'running';
    nodeOutput.startedAt = Date.now();
    execution.data.nodes[nodeId] = nodeOutput;

    const context = this.createNodeContext(execution, node);
    context.log('info', `Executing node: ${node.name}`);

    try {
      const handler = this.getHandler(node);
      if (!handler || typeof handler !== 'function') {
        throw new Error(`No valid handler for node type: ${node.type}`);
      }

      const result = await this.executeWithTimeout(handler, node, context, node.timeout);

      nodeOutput.status = 'completed';
      nodeOutput.output = result.output;
      nodeOutput.completedAt = Date.now();

      eventBus.emit('workflow:node:completed', {
        executionId: execution.id,
        nodeId,
        output: result.output,
      });

      // Determine next nodes
      const nextNodes = result.next
        ? (Array.isArray(result.next) ? result.next : [result.next])
        : this.getNextNodes(workflow, node, result);

      for (const nextId of nextNodes) {
        await this.executeNode(workflow, execution, nextId);
      }

    } catch (error) {
      nodeOutput.status = 'failed';
      nodeOutput.error = error instanceof Error ? error.message : String(error);
      nodeOutput.completedAt = Date.now();

      context.log('error', `Node failed: ${nodeOutput.error}`);

      if (node.onError === 'continue') {
        const nextNodes = this.getNextNodes(workflow, node, {});
        for (const nextId of nextNodes) {
          await this.executeNode(workflow, execution, nextId);
        }
      } else if (node.onError && node.onError !== 'fail' && node.onError !== 'retry') {
        await this.executeNode(workflow, execution, node.onError);
      } else {
        throw error;
      }
    }
  }

  private async executeWithTimeout(
    handler: NodeHandler,
    node: WorkflowNode,
    context: NodeContext,
    timeout?: number
  ): Promise<NodeResult> {
    // Normalize and bound the timeout to prevent resource exhaustion from untrusted values
    const MAX_NODE_TIMEOUT_MS = 60_000; // 60 seconds hard limit for node timeouts
    const numericTimeout = typeof timeout === 'number' ? timeout : Number(timeout);
    const safeTimeout =
      Number.isFinite(numericTimeout) && numericTimeout > 0
        ? Math.min(Math.floor(numericTimeout), MAX_NODE_TIMEOUT_MS)
        : 0;

    // If there is no effective timeout, run the handler directly
    if (!safeTimeout) {
      return handler(node, context);
    }

    return Promise.race([
      handler(node, context),
      new Promise<NodeResult>((_, reject) =>
        setTimeout(
          () => reject(new Error(`Node timeout: ${safeTimeout}ms`)),
          safeTimeout
        )
      ),
    ]);
  }

  private getHandler(node: WorkflowNode): NodeHandler | undefined {
    let handler: NodeHandler | undefined;

    if (node.plugin && node.action) {
      handler = this.handlers.get(`${node.plugin}:${node.action}`);
    } else {
      handler = this.handlers.get(node.type);
    }

    // Extra runtime safety: ensure the retrieved value is actually a function
    if (handler && typeof handler !== 'function') {
      return undefined;
    }

    return handler;
  }

  private getNextNodes(
    workflow: WorkflowDefinition,
    node: WorkflowNode,
    result: NodeResult
  ): string[] {
    const edges = workflow.edges.filter(e => e.from === node.id);
    
    if (node.type === 'condition') {
      const branch = result.output as boolean;
      const edge = edges.find(e =>
        (branch && e.condition === 'true') ||
        (!branch && e.condition === 'false')
      );
      return edge ? [edge.to] : [];
    }

    return edges.filter(e => !e.condition).map(e => e.to);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Context & Execution Creation
  // ─────────────────────────────────────────────────────────────────────────────

  private createExecution(
    workflow: WorkflowDefinition,
    input: Record<string, unknown>,
    triggeredBy?: WorkflowExecution['triggeredBy']
  ): WorkflowExecution {
    return {
      id: this.generateId(),
      workflowId: workflow.id,
      workflowVersion: workflow.version,
      status: 'running',
      startedAt: Date.now(),
      currentNodes: [],
      data: {
        input,
        output: {},
        nodes: {},
        variables: { ...workflow.variables },
      },
      logs: [],
      triggeredBy,
    };
  }

  private createNodeContext(execution: WorkflowExecution, node: WorkflowNode): NodeContext {
    return {
      execution,
      input: this.resolveNodeInput(execution, node),
      variables: execution.data.variables,
      emit: (type, payload) => eventBus.emit(type, payload, { source: `workflow:${execution.workflowId}` }),
      log: (level, message, data) => {
        const log: ExecutionLog = { timestamp: Date.now(), nodeId: node.id, level, message, data };
        execution.logs.push(log);
      },
      getNodeOutput: (nodeId) => execution.data.nodes[nodeId],
    };
  }

  private resolveNodeInput(execution: WorkflowExecution, node: WorkflowNode): unknown {
    // TODO: Implement input resolution from previous nodes, variables, config
    return execution.data.input;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Built-in Handlers
  // ─────────────────────────────────────────────────────────────────────────────

  private registerBuiltInHandlers(): void {
    this.registerHandler('trigger', async () => ({}));

    this.registerHandler('delay', async (node) => {
      const ms = (node.config.seconds as number || 0) * 1000;
      await new Promise(r => setTimeout(r, ms));
      return {};
    });

    this.registerHandler('condition', async (node, ctx) => {
      const { field, operator, value } = node.config as { field: string; operator: string; value: unknown };
      const fieldValue = this.getNestedValue(ctx.input, field);
      const result = this.evaluateCondition(fieldValue, operator, value);
      return { output: result };
    });

    this.registerHandler('transform', async (node, ctx) => {
      const { mapping } = node.config as { mapping: Record<string, string> };
      const output: Record<string, unknown> = {};
      for (const [key, path] of Object.entries(mapping || {})) {
        output[key] = this.getNestedValue(ctx.input, path);
      }
      return { output };
    });

    this.registerHandler('parallel', async (node, ctx) => {
      // Handled by engine - returns multiple next nodes
      return { next: node.config.branches as string[] };
    });

    this.registerHandler('merge', async (node, ctx) => {
      // Collect outputs from previous parallel branches
      const inputs = (node.config.from as string[] || []).map(id => ctx.getNodeOutput(id)?.output);
      return { output: inputs };
    });
  }

  private getNestedValue(obj: unknown, path: string): unknown {
    if (!path) return obj;
    const parts = path.split('.');
    let current = obj;
    for (const part of parts) {
      if (current && typeof current === 'object' && part in current) {
        current = (current as Record<string, unknown>)[part];
      } else {
        return undefined;
      }
    }
    return current;
  }

  private evaluateCondition(value: unknown, operator: string, target: unknown): boolean {
    switch (operator) {
      case 'eq': case 'equals': return value === target;
      case 'ne': case 'not_equals': return value !== target;
      case 'gt': return typeof value === 'number' && value > (target as number);
      case 'gte': return typeof value === 'number' && value >= (target as number);
      case 'lt': return typeof value === 'number' && value < (target as number);
      case 'lte': return typeof value === 'number' && value <= (target as number);
      case 'contains': return typeof value === 'string' && value.includes(target as string);
      case 'matches': return typeof value === 'string' && new RegExp(target as string).test(value);
      case 'exists': return value !== undefined && value !== null;
      case 'empty': return !value || (Array.isArray(value) && value.length === 0);
      default: return false;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Execution Management
  // ─────────────────────────────────────────────────────────────────────────────

  getExecution(id: string): WorkflowExecution | undefined {
    return this.executions.get(id);
  }

  getExecutions(filter?: { workflowId?: string; status?: ExecutionStatus }): WorkflowExecution[] {
    let results = Array.from(this.executions.values());
    if (filter?.workflowId) results = results.filter(e => e.workflowId === filter.workflowId);
    if (filter?.status) results = results.filter(e => e.status === filter.status);
    return results;
  }

  cancelExecution(id: string): boolean {
    const execution = this.executions.get(id);
    if (execution && execution.status === 'running') {
      execution.status = 'cancelled';
      execution.completedAt = Date.now();
      eventBus.emit('workflow:cancelled', { executionId: id });
      return true;
    }
    return false;
  }

  private generateId(): string {
    return `${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 9)}`;
  }
}

export const workflowEngine = new WorkflowEngine();
