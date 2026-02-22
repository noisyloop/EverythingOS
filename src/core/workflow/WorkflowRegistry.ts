// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Workflow Registry
// Store and manage workflow definitions
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../event-bus/EventBus';
import { WorkflowDefinition, WorkflowStatus, WorkflowTrigger } from './WorkflowTypes';
import { workflowEngine } from './WorkflowEngine';

export class WorkflowRegistry {
  private workflows: Map<string, WorkflowDefinition> = new Map();
  private triggerSubscriptions: Map<string, () => void> = new Map();

  // ─────────────────────────────────────────────────────────────────────────────
  // Registration
  // ─────────────────────────────────────────────────────────────────────────────

  register(workflow: WorkflowDefinition): void {
    const existing = this.workflows.get(workflow.id);
    
    if (existing) {
      workflow.version = existing.version + 1;
      workflow.metadata = {
        ...workflow.metadata,
        updatedAt: Date.now(),
        createdAt: existing.metadata?.createdAt || Date.now(),
      };
    } else {
      workflow.metadata = {
        ...workflow.metadata,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
    }

    this.workflows.set(workflow.id, workflow);
    
    if (workflow.status === 'active') {
      this.activateTriggers(workflow);
    }

    eventBus.emit('workflow:registered', { workflowId: workflow.id, version: workflow.version });
  }

  unregister(workflowId: string): boolean {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) return false;

    this.deactivateTriggers(workflowId);
    this.workflows.delete(workflowId);
    eventBus.emit('workflow:unregistered', { workflowId });
    return true;
  }

  get(workflowId: string): WorkflowDefinition | undefined {
    return this.workflows.get(workflowId);
  }

  list(filter?: { status?: WorkflowStatus; tags?: string[] }): WorkflowDefinition[] {
    let results = Array.from(this.workflows.values());
    if (filter?.status) results = results.filter(w => w.status === filter.status);
    if (filter?.tags) {
      results = results.filter(w =>
        filter.tags!.some(tag => w.metadata?.tags?.includes(tag))
      );
    }
    return results;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Status Management
  // ─────────────────────────────────────────────────────────────────────────────

  activate(workflowId: string): boolean {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) return false;

    workflow.status = 'active';
    workflow.metadata = { createdAt: workflow.metadata?.createdAt ?? Date.now(), ...workflow.metadata, updatedAt: Date.now() };
    this.activateTriggers(workflow);
    eventBus.emit('workflow:activated', { workflowId });
    return true;
  }

  pause(workflowId: string): boolean {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) return false;

    workflow.status = 'paused';
    workflow.metadata = { createdAt: workflow.metadata?.createdAt ?? Date.now(), ...workflow.metadata, updatedAt: Date.now() };
    this.deactivateTriggers(workflowId);
    eventBus.emit('workflow:paused', { workflowId });
    return true;
  }

  archive(workflowId: string): boolean {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) return false;

    workflow.status = 'archived';
    workflow.metadata = { createdAt: workflow.metadata?.createdAt ?? Date.now(), ...workflow.metadata, updatedAt: Date.now() };
    this.deactivateTriggers(workflowId);
    eventBus.emit('workflow:archived', { workflowId });
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Triggers
  // ─────────────────────────────────────────────────────────────────────────────

  private activateTriggers(workflow: WorkflowDefinition): void {
    if (!workflow.triggers) return;

    for (const trigger of workflow.triggers) {
      if (!trigger.enabled) continue;
      this.activateTrigger(workflow.id, trigger);
    }
  }

  private activateTrigger(workflowId: string, trigger: WorkflowTrigger): void {
    const key = `${workflowId}:${trigger.id}`;

    switch (trigger.type) {
      case 'event': {
        const pattern = trigger.config.pattern as string;
        const unsub = eventBus.on(pattern, async (event) => {
          const workflow = this.workflows.get(workflowId);
          if (workflow && workflow.status === 'active') {
            await workflowEngine.execute(workflow, event.payload as Record<string, unknown>, {
              type: 'event',
              id: event.id,
              data: event,
            });
          }
        });
        this.triggerSubscriptions.set(key, unsub);
        break;
      }

      case 'schedule': {
        // TODO: Implement cron/interval scheduling
        break;
      }

      case 'webhook': {
        // Webhooks handled by API server
        break;
      }
    }
  }

  private deactivateTriggers(workflowId: string): void {
    for (const [key, unsub] of this.triggerSubscriptions) {
      if (key.startsWith(`${workflowId}:`)) {
        unsub();
        this.triggerSubscriptions.delete(key);
      }
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Manual Execution
  // ─────────────────────────────────────────────────────────────────────────────

  async execute(workflowId: string, input: Record<string, unknown> = {}) {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) throw new Error(`Workflow not found: ${workflowId}`);

    return workflowEngine.execute(workflow, input, { type: 'manual' });
  }
}

export const workflowRegistry = new WorkflowRegistry();
