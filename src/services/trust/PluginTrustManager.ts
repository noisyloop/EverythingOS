// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Plugin Trust System
// Trust levels: trusted, restricted, sandboxed
// Controls what plugins can do at runtime
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../../core/event-bus/EventBus';
import { PluginConfig } from '../../core/registry/PluginRegistry';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type TrustLevel = 'trusted' | 'restricted' | 'sandboxed';

export interface PluginPermission {
  type: PermissionType;
  scope?: string;        // Optional scope (e.g., specific API, file path pattern)
  granted: boolean;
  grantedBy?: string;
  grantedAt?: number;
}

export type PermissionType =
  | 'network'            // Make HTTP requests
  | 'network:internal'   // Access internal APIs only
  | 'network:external'   // Access external APIs
  | 'filesystem'         // Read/write files
  | 'filesystem:read'    // Read files only
  | 'filesystem:write'   // Write files
  | 'state:read'         // Read world state
  | 'state:write'        // Modify world state
  | 'events:emit'        // Emit events
  | 'events:listen'      // Listen to events
  | 'agents:invoke'      // Invoke other agents
  | 'plugins:invoke'     // Invoke other plugins
  | 'secrets'            // Access secrets/credentials
  | 'system'             // System-level operations
  | 'hardware';          // Hardware access (future)

export interface TrustPolicy {
  level: TrustLevel;
  permissions: PermissionType[];
  restrictions?: TrustRestriction[];
}

export interface TrustRestriction {
  type: 'rate_limit' | 'timeout' | 'memory' | 'cpu' | 'pattern_block';
  value: number | string;
}

export interface PluginTrustConfig {
  pluginId: string;
  level: TrustLevel;
  permissions: PluginPermission[];
  restrictions: TrustRestriction[];
  audit: boolean;
  approvedBy?: string;
  approvedAt?: number;
  expiresAt?: number;
}

export interface TrustViolation {
  pluginId: string;
  permission: PermissionType;
  action: string;
  timestamp: number;
  blocked: boolean;
  details?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Default Policies
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_POLICIES: Record<TrustLevel, TrustPolicy> = {
  trusted: {
    level: 'trusted',
    permissions: [
      'network', 'network:internal', 'network:external',
      'filesystem', 'filesystem:read', 'filesystem:write',
      'state:read', 'state:write',
      'events:emit', 'events:listen',
      'agents:invoke', 'plugins:invoke',
      'secrets',
    ],
    restrictions: [],
  },
  
  restricted: {
    level: 'restricted',
    permissions: [
      'network:internal',
      'filesystem:read',
      'state:read',
      'events:emit', 'events:listen',
      'agents:invoke',
    ],
    restrictions: [
      { type: 'rate_limit', value: 100 },    // 100 calls/minute
      { type: 'timeout', value: 30000 },     // 30s max execution
    ],
  },
  
  sandboxed: {
    level: 'sandboxed',
    permissions: [
      'state:read',
      'events:listen',
    ],
    restrictions: [
      { type: 'rate_limit', value: 10 },     // 10 calls/minute
      { type: 'timeout', value: 5000 },      // 5s max execution
      { type: 'memory', value: 50 },         // 50MB max
    ],
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Plugin Trust Manager
// ─────────────────────────────────────────────────────────────────────────────

export class PluginTrustManager {
  private configs: Map<string, PluginTrustConfig> = new Map();
  private violations: TrustViolation[] = [];
  private callCounts: Map<string, { count: number; windowStart: number }> = new Map();

  constructor() {
    this.setupListeners();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Configuration
  // ─────────────────────────────────────────────────────────────────────────

  setTrustLevel(
    pluginId: string, 
    level: TrustLevel, 
    options?: { 
      approvedBy?: string; 
      expiresAt?: number;
      additionalPermissions?: PermissionType[];
      additionalRestrictions?: TrustRestriction[];
    }
  ): void {
    const policy = DEFAULT_POLICIES[level];
    
    const permissions: PluginPermission[] = policy.permissions.map(type => ({
      type,
      granted: true,
      grantedBy: options?.approvedBy ?? 'system',
      grantedAt: Date.now(),
    }));

    // Add additional permissions if specified
    if (options?.additionalPermissions) {
      for (const type of options.additionalPermissions) {
        if (!permissions.find(p => p.type === type)) {
          permissions.push({
            type,
            granted: true,
            grantedBy: options.approvedBy ?? 'system',
            grantedAt: Date.now(),
          });
        }
      }
    }

    const config: PluginTrustConfig = {
      pluginId,
      level,
      permissions,
      restrictions: [
        ...(policy.restrictions ?? []),
        ...(options?.additionalRestrictions ?? []),
      ],
      audit: level !== 'trusted', // Audit non-trusted plugins
      approvedBy: options?.approvedBy,
      approvedAt: Date.now(),
      expiresAt: options?.expiresAt,
    };

    this.configs.set(pluginId, config);
    eventBus.emit('trust:level:set', { pluginId, level });
  }

  getTrustConfig(pluginId: string): PluginTrustConfig | undefined {
    return this.configs.get(pluginId);
  }

  getTrustLevel(pluginId: string): TrustLevel {
    return this.configs.get(pluginId)?.level ?? 'sandboxed'; // Default to most restrictive
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Permission Management
  // ─────────────────────────────────────────────────────────────────────────

  grantPermission(
    pluginId: string, 
    permission: PermissionType, 
    options?: { scope?: string; grantedBy?: string; expiresAt?: number }
  ): boolean {
    const config = this.configs.get(pluginId);
    if (!config) {
      // Create sandboxed config if none exists
      this.setTrustLevel(pluginId, 'sandboxed');
      return this.grantPermission(pluginId, permission, options);
    }

    const existing = config.permissions.find(p => p.type === permission && p.scope === options?.scope);
    if (existing) {
      existing.granted = true;
      existing.grantedBy = options?.grantedBy ?? 'system';
      existing.grantedAt = Date.now();
    } else {
      config.permissions.push({
        type: permission,
        scope: options?.scope,
        granted: true,
        grantedBy: options?.grantedBy ?? 'system',
        grantedAt: Date.now(),
      });
    }

    eventBus.emit('trust:permission:granted', { pluginId, permission });
    return true;
  }

  revokePermission(pluginId: string, permission: PermissionType, scope?: string): boolean {
    const config = this.configs.get(pluginId);
    if (!config) return false;

    const perm = config.permissions.find(p => p.type === permission && p.scope === scope);
    if (perm) {
      perm.granted = false;
      eventBus.emit('trust:permission:revoked', { pluginId, permission });
      return true;
    }
    return false;
  }

  hasPermission(pluginId: string, permission: PermissionType, scope?: string): boolean {
    const config = this.configs.get(pluginId);
    if (!config) return false;

    // Check expiration
    if (config.expiresAt && Date.now() > config.expiresAt) {
      return false;
    }

    // Check for exact permission
    const exact = config.permissions.find(p => 
      p.type === permission && 
      p.granted && 
      (!scope || !p.scope || p.scope === scope || scope.startsWith(p.scope))
    );
    if (exact) return true;

    // Check for parent permission (e.g., 'network' grants 'network:internal')
    const parent = permission.split(':')[0];
    if (parent !== permission) {
      const parentPerm = config.permissions.find(p => p.type === parent && p.granted);
      if (parentPerm) return true;
    }

    return false;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Enforcement
  // ─────────────────────────────────────────────────────────────────────────

  checkPermission(pluginId: string, permission: PermissionType, action: string, scope?: string): boolean {
    const allowed = this.hasPermission(pluginId, permission, scope);
    const config = this.configs.get(pluginId);

    if (!allowed) {
      this.recordViolation(pluginId, permission, action, true);
      return false;
    }

    // Check rate limit
    if (config && !this.checkRateLimit(pluginId, config)) {
      this.recordViolation(pluginId, permission, action, true, 'Rate limit exceeded');
      return false;
    }

    // Audit if required
    if (config?.audit) {
      eventBus.emit('trust:action:audited', { pluginId, permission, action, scope });
    }

    return true;
  }

  private checkRateLimit(pluginId: string, config: PluginTrustConfig): boolean {
    const rateLimit = config.restrictions.find(r => r.type === 'rate_limit');
    if (!rateLimit) return true;

    const limit = rateLimit.value as number;
    const now = Date.now();
    const windowMs = 60000; // 1 minute window

    let record = this.callCounts.get(pluginId);
    
    if (!record || now - record.windowStart > windowMs) {
      record = { count: 0, windowStart: now };
      this.callCounts.set(pluginId, record);
    }

    record.count++;
    return record.count <= limit;
  }

  getTimeout(pluginId: string): number {
    const config = this.configs.get(pluginId);
    const timeout = config?.restrictions.find(r => r.type === 'timeout');
    return (timeout?.value as number) ?? 30000; // Default 30s
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Violations
  // ─────────────────────────────────────────────────────────────────────────

  private recordViolation(
    pluginId: string, 
    permission: PermissionType, 
    action: string, 
    blocked: boolean,
    details?: string
  ): void {
    const violation: TrustViolation = {
      pluginId,
      permission,
      action,
      timestamp: Date.now(),
      blocked,
      details,
    };

    this.violations.push(violation);
    
    // Keep last 1000 violations
    if (this.violations.length > 1000) {
      this.violations = this.violations.slice(-500);
    }

    eventBus.emit('trust:violation', violation);
  }

  getViolations(filter?: { pluginId?: string; since?: number; limit?: number }): TrustViolation[] {
    let results = [...this.violations];

    if (filter?.pluginId) {
      results = results.filter(v => v.pluginId === filter.pluginId);
    }
    if (filter?.since) {
      results = results.filter(v => v.timestamp >= filter.since!);
    }
    if (filter?.limit) {
      results = results.slice(-filter.limit);
    }

    return results;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Event Listeners
  // ─────────────────────────────────────────────────────────────────────────

  private setupListeners(): void {
    // Auto-configure new plugins as sandboxed
    eventBus.on('plugin:registered', (event) => {
      const plugin = event.payload as PluginConfig;
      if (!this.configs.has(plugin.id)) {
        this.setTrustLevel(plugin.id, 'sandboxed');
      }
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Helpers
  // ─────────────────────────────────────────────────────────────────────────

  listConfigs(): PluginTrustConfig[] {
    return Array.from(this.configs.values());
  }

  listByLevel(level: TrustLevel): string[] {
    return Array.from(this.configs.entries())
      .filter(([_, config]) => config.level === level)
      .map(([id]) => id);
  }

  stats(): {
    total: number;
    byLevel: Record<TrustLevel, number>;
    violations: number;
    recentViolations: number;
  } {
    const byLevel = { trusted: 0, restricted: 0, sandboxed: 0 };
    
    for (const config of this.configs.values()) {
      byLevel[config.level]++;
    }

    const hourAgo = Date.now() - 3600000;
    const recentViolations = this.violations.filter(v => v.timestamp > hourAgo).length;

    return {
      total: this.configs.size,
      byLevel,
      violations: this.violations.length,
      recentViolations,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Bulk Operations
  // ─────────────────────────────────────────────────────────────────────────

  trustAll(pluginIds: string[], level: TrustLevel, approvedBy: string): void {
    for (const id of pluginIds) {
      this.setTrustLevel(id, level, { approvedBy });
    }
  }

  revokeAll(pluginId: string): void {
    const config = this.configs.get(pluginId);
    if (config) {
      for (const perm of config.permissions) {
        perm.granted = false;
      }
      eventBus.emit('trust:revoked:all', { pluginId });
    }
  }

  reset(pluginId: string): void {
    this.configs.delete(pluginId);
    this.setTrustLevel(pluginId, 'sandboxed');
  }
}

// Singleton export
export const pluginTrustManager = new PluginTrustManager();
