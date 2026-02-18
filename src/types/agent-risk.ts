/**
 * Agent Risk Classification Types
 *
 * NIST AI RMF 1.0 — MAP Function (MP-2, MP-4)
 * NIST AI 600-1 — GenAI Risk Categorization
 *
 * Every agent in EverythingOS must declare a risk tier at registration.
 * The EventBus, ApprovalGateAgent, and AuditLogger use this classification
 * to enforce appropriate controls automatically.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Risk Tier Enum
// ─────────────────────────────────────────────────────────────────────────────

export enum AgentRiskTier {
  /**
   * LOW — Read-only agents with no external calls.
   * Examples: Clock, Metrics, WorldState reader, simulation agents.
   * Controls: None beyond base EventBus ACLs.
   */
  LOW = 'low',

  /**
   * MEDIUM — Agents that call external APIs or interact with users.
   * Examples: Discord bot, Slack integration, trading signal generator.
   * Controls: Input sanitization, PII scrubbing, output filtering, rate limiting.
   */
  MEDIUM = 'medium',

  /**
   * HIGH — Agents with consequential real-world actions.
   * Examples: Trade execution, production deployment, robotics/ROS2, system config.
   * Controls: All MEDIUM controls + human-in-the-loop approval required.
   */
  HIGH = 'high',
}

// ─────────────────────────────────────────────────────────────────────────────
// GenAI Risk Flags (NIST AI 600-1)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Declare which GenAI-specific risks apply to this agent.
 * Used by the content filter and audit logger to apply appropriate controls.
 */
export interface GenAIRiskFlags {
  /** Agent sends user-supplied text to an LLM — prompt injection risk */
  promptInjectionRisk: boolean;

  /** Agent processes or stores personally identifiable information */
  piiRisk: boolean;

  /** Agent makes decisions using LLM output without human verification */
  hallucinationRisk: boolean;

  /** Agent generates content visible to end users */
  harmfulContentRisk: boolean;

  /** Agent uses LLM output to make consequential decisions */
  informationIntegrityRisk: boolean;

  /** Agent interacts with physical hardware or robotics systems */
  physicalSafetyRisk: boolean;

  /** Agent sends data to third-party LLM providers */
  dataPrivacyRisk: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent Risk Configuration
// ─────────────────────────────────────────────────────────────────────────────

export interface AgentRiskConfig {
  /**
   * Risk tier for this agent. Determines which controls are applied automatically.
   * Required — every agent must declare a tier.
   */
  tier: AgentRiskTier;

  /**
   * GenAI-specific risk flags. Required for any agent that integrates with an LLM.
   * Agents with no LLM integration may omit this.
   */
  genAIRisks?: Partial<GenAIRiskFlags>;

  /**
   * Human-readable justification for the assigned risk tier.
   * Required for HIGH tier agents. Recommended for MEDIUM.
   * Example: "Executes real trades on Coinbase — irreversible financial action"
   */
  riskJustification?: string;

  /**
   * Explicit list of EventBus channels this agent may PUBLISH to.
   * The EventBus enforces this at runtime. Attempts to publish outside
   * this list are blocked and logged as a security event.
   */
  allowedPublishChannels: string[];

  /**
   * Explicit list of EventBus channels this agent may SUBSCRIBE to.
   * Wildcards supported: 'user:*' matches 'user:message', 'user:join', etc.
   */
  allowedSubscribeChannels: string[];

  /**
   * For HIGH tier agents: whether this agent requires ApprovalGateAgent
   * approval before executing consequential actions.
   * Defaults to true for HIGH tier, false for LOW/MEDIUM.
   */
  requiresApproval?: boolean;

  /**
   * Maximum number of LLM API calls per minute for this agent.
   * Prevents runaway costs and abuse. Defaults: LOW=0, MEDIUM=60, HIGH=30.
   */
  llmRateLimit?: number;

  /**
   * If true, all inputs to this agent are logged (hashed) for audit.
   * Defaults to true for MEDIUM and HIGH. False for LOW.
   */
  auditInputs?: boolean;

  /**
   * If true, all outputs from this agent are logged (hashed) for audit.
   * Defaults to true for MEDIUM and HIGH. False for LOW.
   */
  auditOutputs?: boolean;

  /**
   * Data classification level for content this agent processes.
   * Affects PII scrubbing aggressiveness and retention policies.
   */
  dataClassification?: 'public' | 'internal' | 'confidential' | 'restricted';
}

// ─────────────────────────────────────────────────────────────────────────────
// Default Configs by Tier
// ─────────────────────────────────────────────────────────────────────────────

export const DEFAULT_RISK_CONFIG: Record<AgentRiskTier, Partial<AgentRiskConfig>> = {
  [AgentRiskTier.LOW]: {
    tier: AgentRiskTier.LOW,
    requiresApproval: false,
    llmRateLimit: 0,
    auditInputs: false,
    auditOutputs: false,
    dataClassification: 'public',
  },
  [AgentRiskTier.MEDIUM]: {
    tier: AgentRiskTier.MEDIUM,
    requiresApproval: false,
    llmRateLimit: 60,
    auditInputs: true,
    auditOutputs: true,
    dataClassification: 'internal',
  },
  [AgentRiskTier.HIGH]: {
    tier: AgentRiskTier.HIGH,
    requiresApproval: true,
    llmRateLimit: 30,
    auditInputs: true,
    auditOutputs: true,
    dataClassification: 'confidential',
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns the merged risk config for an agent, applying tier defaults
 * where the agent has not explicitly specified values.
 */
export function resolveRiskConfig(config: AgentRiskConfig): Required<AgentRiskConfig> {
  const defaults = DEFAULT_RISK_CONFIG[config.tier];
  return {
    ...defaults,
    ...config,
    genAIRisks: config.genAIRisks ?? {
      promptInjectionRisk: false,
      piiRisk: false,
      hallucinationRisk: false,
      harmfulContentRisk: false,
      informationIntegrityRisk: false,
      physicalSafetyRisk: false,
      dataPrivacyRisk: false,
    },
    riskJustification: config.riskJustification ?? '',
    requiresApproval: config.requiresApproval ?? (config.tier === AgentRiskTier.HIGH),
    llmRateLimit: config.llmRateLimit ?? defaults.llmRateLimit ?? 0,
    auditInputs: config.auditInputs ?? defaults.auditInputs ?? false,
    auditOutputs: config.auditOutputs ?? defaults.auditOutputs ?? false,
    dataClassification: config.dataClassification ?? defaults.dataClassification ?? 'internal',
  } as Required<AgentRiskConfig>;
}

/**
 * Returns true if the agent requires input sanitization.
 * MEDIUM and HIGH agents with promptInjectionRisk or piiRisk always require it.
 */
export function requiresSanitization(config: AgentRiskConfig): boolean {
  if (config.tier === AgentRiskTier.LOW) return false;
  const risks = config.genAIRisks ?? {};
  return !!(risks.promptInjectionRisk || risks.piiRisk || risks.dataPrivacyRisk);
}

/**
 * Returns true if the agent requires human approval before consequential actions.
 */
export function requiresHumanApproval(config: AgentRiskConfig): boolean {
  return config.tier === AgentRiskTier.HIGH && (config.requiresApproval !== false);
}
