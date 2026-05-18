// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Policy Engine
// Rule-based policy evaluation for agent actions
// ═══════════════════════════════════════════════════════════════════════════════

export type PolicyAction = 'allow' | 'deny' | 'restart' | 'stop' | 'alert' | 'escalate';

export interface Policy {
  id: string;
  name: string;
  description?: string;
  priority: number;           // Lower = higher priority
  enabled: boolean;
  conditions: PolicyCondition[];
  action: PolicyAction;
  reason?: string;
}

export interface PolicyCondition {
  field: string;              // Dot notation path
  operator: PolicyOperator;
  value: unknown;
}

export type PolicyOperator =
  | 'eq' | 'ne'
  | 'gt' | 'gte' | 'lt' | 'lte'
  | 'contains' | 'not_contains'
  | 'matches'
  | 'in' | 'not_in'
  | 'exists' | 'not_exists';

export interface PolicyDecision {
  allowed: boolean;
  action: PolicyAction;
  policy?: Policy;
  reason?: string;
}

export interface PolicyContext {
  agentId: string;
  action: string;
  timestamp: number;
  [key: string]: unknown;
}

export class PolicyEngine {
  private policies: Map<string, Policy> = new Map();
  private locked = false;

  // ─────────────────────────────────────────────────────────────────────────────
  // Policy Management
  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Lock the policy store. Call once at startup after all policies are loaded.
   * Prevents runtime policy injection by compromised in-process agents.
   */
  lock(): void {
    this.locked = true;
  }

  addPolicy(policy: Policy): void {
    if (this.locked) {
      throw new Error(`[PolicyEngine] Policy store is locked. addPolicy() must be called at startup, before lock().`);
    }
    this.policies.set(policy.id, policy);
  }

  removePolicy(policyId: string): boolean {
    if (this.locked) {
      throw new Error(`[PolicyEngine] Policy store is locked. removePolicy() must be called at startup, before lock().`);
    }
    return this.policies.delete(policyId);
  }

  getPolicy(policyId: string): Policy | undefined {
    return this.policies.get(policyId);
  }

  getAllPolicies(): Policy[] {
    return Array.from(this.policies.values());
  }

  enablePolicy(policyId: string): void {
    const policy = this.policies.get(policyId);
    if (policy) policy.enabled = true;
  }

  disablePolicy(policyId: string): void {
    const policy = this.policies.get(policyId);
    if (policy) policy.enabled = false;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Evaluation
  // ─────────────────────────────────────────────────────────────────────────────

  async evaluate(agentId: string, action: string, context: Record<string, unknown> = {}): Promise<PolicyDecision> {
    const fullContext: PolicyContext = {
      agentId,
      action,
      timestamp: Date.now(),
      ...context,
    };

    const matchingPolicies = this.findMatchingPolicies(fullContext);
    
    if (matchingPolicies.length === 0) {
      return { allowed: true, action: 'allow' };
    }

    // Return highest priority (lowest number) matching policy
    const policy = matchingPolicies[0];
    
    return {
      allowed: policy.action === 'allow',
      action: policy.action,
      policy,
      reason: policy.reason,
    };
  }

  private findMatchingPolicies(context: PolicyContext): Policy[] {
    const matching: Policy[] = [];

    for (const policy of this.policies.values()) {
      if (!policy.enabled) continue;
      if (this.matchesAllConditions(policy.conditions, context)) {
        matching.push(policy);
      }
    }

    return matching.sort((a, b) => a.priority - b.priority);
  }

  private matchesAllConditions(conditions: PolicyCondition[], context: PolicyContext): boolean {
    return conditions.every(condition => this.evaluateCondition(condition, context));
  }

  private evaluateCondition(condition: PolicyCondition, context: PolicyContext): boolean {
    const value = this.getNestedValue(context, condition.field);
    return this.applyOperator(value, condition.operator, condition.value);
  }

  private getNestedValue(obj: unknown, path: string): unknown {
    const parts = path.split('.');
    let current = obj;
    
    for (const part of parts) {
      if (current === null || current === undefined) return undefined;
      if (typeof current !== 'object') return undefined;
      current = (current as Record<string, unknown>)[part];
    }
    
    return current;
  }

  private applyOperator(value: unknown, operator: PolicyOperator, target: unknown): boolean {
    switch (operator) {
      case 'eq':
        return value === target;
      case 'ne':
        return value !== target;
      case 'gt':
        return typeof value === 'number' && typeof target === 'number' && value > target;
      case 'gte':
        return typeof value === 'number' && typeof target === 'number' && value >= target;
      case 'lt':
        return typeof value === 'number' && typeof target === 'number' && value < target;
      case 'lte':
        return typeof value === 'number' && typeof target === 'number' && value <= target;
      case 'contains':
        if (typeof value === 'string' && typeof target === 'string') {
          return value.includes(target);
        }
        if (Array.isArray(value)) {
          return value.includes(target);
        }
        return false;
      case 'not_contains':
        if (typeof value === 'string' && typeof target === 'string') {
          return !value.includes(target);
        }
        if (Array.isArray(value)) {
          return !value.includes(target);
        }
        return true;
      case 'matches':
        return typeof value === 'string' && typeof target === 'string' && new RegExp(target).test(value);
      case 'in':
        return Array.isArray(target) && target.includes(value);
      case 'not_in':
        return Array.isArray(target) && !target.includes(value);
      case 'exists':
        return value !== undefined && value !== null;
      case 'not_exists':
        return value === undefined || value === null;
      default:
        return false;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Preset Policies
  // ─────────────────────────────────────────────────────────────────────────────

  loadDefaultPolicies(): void {
    this.addPolicy({
      id: 'rate-limit',
      name: 'Rate Limit',
      description: 'Prevent excessive action frequency',
      priority: 10,
      enabled: true,
      conditions: [
        { field: 'action', operator: 'eq', value: 'execute' },
        { field: 'rateLimit.exceeded', operator: 'eq', value: true },
      ],
      action: 'deny',
      reason: 'Rate limit exceeded',
    });

    this.addPolicy({
      id: 'unhealthy-restart',
      name: 'Restart Unhealthy Agents',
      description: 'Automatically restart unhealthy agents',
      priority: 20,
      enabled: true,
      conditions: [
        { field: 'action', operator: 'eq', value: 'unhealthy' },
      ],
      action: 'restart',
      reason: 'Agent unhealthy',
    });

    this.addPolicy({
      id: 'sensitive-action-alert',
      name: 'Alert on Sensitive Actions',
      description: 'Send alerts for sensitive operations',
      priority: 5,
      enabled: true,
      conditions: [
        { field: 'action', operator: 'in', value: ['delete', 'modify', 'execute_trade'] },
      ],
      action: 'alert',
      reason: 'Sensitive action performed',
    });
  }
}
