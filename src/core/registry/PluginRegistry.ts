// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Plugin Registry
// Plugin management and action registration
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../event-bus/EventBus';
import { workflowEngine } from '../workflow/WorkflowEngine';
import { pluginTrustManager } from '../../services/trust';

export interface PluginAction {
  name: string;
  description?: string;
  schema?: Record<string, unknown>;  // JSON Schema for validation
  handler: (input: unknown, context: PluginContext) => Promise<unknown>;
  requiredPermissions?: Array<'network' | 'filesystem' | 'state:write' | 'secrets' | 'hardware'>;
}

export interface PluginConfig {
  id: string;
  name: string;
  version: string;
  description?: string;
  author?: string;
  actions: PluginAction[];
  initialize?: (context: PluginContext) => Promise<void>;
  shutdown?: () => Promise<void>;
}

export interface PluginContext {
  emit: (type: string, payload: unknown) => void;
  getConfig: <T>(key: string) => T | undefined;
  setConfig: <T>(key: string, value: T) => void;
}

export class PluginRegistry {
  private plugins: Map<string, PluginConfig> = new Map();
  private configs: Map<string, Map<string, unknown>> = new Map();

  // ─────────────────────────────────────────────────────────────────────────────
  // Registration
  // ─────────────────────────────────────────────────────────────────────────────

  async register(plugin: PluginConfig): Promise<void> {
    if (this.plugins.has(plugin.id)) {
      throw new Error(`Plugin already registered: ${plugin.id}`);
    }

    // Initialize config store
    this.configs.set(plugin.id, new Map());

    // Create context
    const context = this.createContext(plugin.id);

    // Initialize plugin
    if (plugin.initialize) {
      await plugin.initialize(context);
    }

    // Register actions with workflow engine
    for (const action of plugin.actions) {
      workflowEngine.registerPluginHandler(plugin.id, action.name, async (node, nodeContext) => {
        const result = await action.handler(nodeContext.input, context);
        return { output: result };
      });
    }

    this.plugins.set(plugin.id, plugin);
    eventBus.emit('plugin:registered', { pluginId: plugin.id, version: plugin.version });
  }

  async unregister(pluginId: string): Promise<boolean> {
    const plugin = this.plugins.get(pluginId);
    if (!plugin) return false;

    if (plugin.shutdown) {
      await plugin.shutdown();
    }

    this.plugins.delete(pluginId);
    this.configs.delete(pluginId);
    eventBus.emit('plugin:unregistered', { pluginId });
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Query
  // ─────────────────────────────────────────────────────────────────────────────

  get(pluginId: string): PluginConfig | undefined {
    return this.plugins.get(pluginId);
  }

  getAll(): PluginConfig[] {
    return Array.from(this.plugins.values());
  }

  getAction(pluginId: string, actionName: string): PluginAction | undefined {
    const plugin = this.plugins.get(pluginId);
    return plugin?.actions.find(a => a.name === actionName);
  }

  getAllActions(): Array<{ plugin: string; action: PluginAction }> {
    const actions: Array<{ plugin: string; action: PluginAction }> = [];
    for (const [pluginId, plugin] of this.plugins) {
      for (const action of plugin.actions) {
        actions.push({ plugin: pluginId, action });
      }
    }
    return actions;
  }

  has(pluginId: string): boolean {
    return this.plugins.has(pluginId);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Execute Action
  // ─────────────────────────────────────────────────────────────────────────────

  async execute(pluginId: string, actionName: string, input: unknown): Promise<unknown> {
    const action = this.getAction(pluginId, actionName);
    if (!action) {
      throw new Error(`Action not found: ${pluginId}:${actionName}`);
    }

    // Check trust/permissions
    if (action.requiredPermissions) {
      for (const permission of action.requiredPermissions) {
        if (!pluginTrustManager.checkPermission(pluginId, permission, actionName)) {
          throw new Error(`Permission denied: ${pluginId} requires '${permission}' for action '${actionName}'`);
        }
      }
    }

    // Check general plugin:invoke permission (always required)
    if (!pluginTrustManager.checkPermission(pluginId, 'plugins:invoke', actionName)) {
      throw new Error(`Plugin ${pluginId} is not allowed to invoke actions`);
    }

    // Validate input against schema if defined
    if (action.schema) {
      if (input !== null && typeof input === 'object') {
        const inputObj = input as Record<string, unknown>;
        const required = (action.schema.required as string[]) ?? [];
        for (const key of required) {
          if (!(key in inputObj)) {
            throw new Error(`Missing required input field '${key}' for action '${actionName}'`);
          }
        }
      }
    }

    // Get timeout from trust config
    const timeout = pluginTrustManager.getTimeout(pluginId);

    const context = this.createContext(pluginId);

    // Execute with timeout
    const result = await Promise.race([
      action.handler(input, context),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Plugin action timeout: ${timeout}ms`)), timeout)
      ),
    ]);

    return result;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Context
  // ─────────────────────────────────────────────────────────────────────────────

  private createContext(pluginId: string): PluginContext {
    const configStore = this.configs.get(pluginId)!;
    
    return {
      emit: (type, payload) => eventBus.emit(`plugin:${pluginId}:${type}`, payload),
      getConfig: <T>(key: string) => configStore.get(key) as T | undefined,
      setConfig: <T>(key: string, value: T) => configStore.set(key, value),
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Plugin Config
  // ─────────────────────────────────────────────────────────────────────────────

  setPluginConfig<T>(pluginId: string, key: string, value: T): void {
    const store = this.configs.get(pluginId);
    if (store) store.set(key, value);
  }

  getPluginConfig<T>(pluginId: string, key: string): T | undefined {
    return this.configs.get(pluginId)?.get(key) as T | undefined;
  }
}

export const pluginRegistry = new PluginRegistry();
