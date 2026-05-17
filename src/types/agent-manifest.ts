/**
 * AgentManifest — Zod-validated schema every agent must export.
 *
 * The registry refuses to load an agent whose manifest fails validation.
 * This is the contract between the framework and contributors.
 *
 * Convention: every agent module must export:
 *   export const MANIFEST: AgentManifest = { ... };
 *   export default class MyAgent extends Agent { ... }
 */

import { z } from 'zod';
import { AgentRiskTier } from './agent-risk';

// ─────────────────────────────────────────────────────────────────────────────
// Categories
// ─────────────────────────────────────────────────────────────────────────────

export const AgentCategoryEnum = z.enum([
  'foundation',  // system infrastructure — clock, health, shutdown
  'security',    // CVE monitoring, secret scanning, model guard
  'creative',    // generative, divergent, aesthetic processing
  'soc',         // security operations — triage, intel, compliance
  'robotics',    // physical system planning and supervision
  'events',      // live event operations
  'research',    // scientific research support
  'finance',     // trading signals and financial analysis
  'comms',       // messaging integrations — Discord, Slack, etc.
  'data',        // ETL, transformation, enrichment
]);

export type AgentCategory = z.infer<typeof AgentCategoryEnum>;

// ─────────────────────────────────────────────────────────────────────────────
// Capabilities
// Capabilities declare what an agent is allowed to do at runtime.
// ModelGuard checks the capability list before executing any action.
// ─────────────────────────────────────────────────────────────────────────────

export const AgentCapabilityEnum = z.enum([
  'model:call',           // invoke an LLM via LLMRouter
  'model:embed',          // generate text embeddings
  'memory:read',          // read from any memory store
  'memory:write',         // write to any memory store
  'network:http',         // make outbound HTTP requests via http-guard
  'network:ws',           // open WebSocket connections via websocket-guard
  'filesystem:read',      // read files from the local filesystem
  'filesystem:write',     // write files to the local filesystem
  'hardware:gpio',        // access GPIO hardware
  'hardware:serial',      // communicate over serial ports
  'hardware:mqtt',        // publish/subscribe to an MQTT broker
  'hardware:i2c',         // communicate over I2C
  'eventbus:publish',     // publish events to the EventBus
  'eventbus:subscribe',   // subscribe to EventBus channels
  'ledger:write',         // write entries to the DecisionLedger
  'ledger:read',          // read from the DecisionLedger
  'secrets:read',         // request credentials from the CredentialVault
  'agents:spawn',         // spawn sub-agents or delegate to other agents
  'agents:query',         // query the AgentRegistry for peer agents
]);

export type AgentCapability = z.infer<typeof AgentCapabilityEnum>;

// ─────────────────────────────────────────────────────────────────────────────
// Manifest schema
// ─────────────────────────────────────────────────────────────────────────────

export const AgentManifestSchema = z.object({
  /** Unique identifier — lowercase letters, numbers, hyphens only */
  id: z
    .string()
    .min(1)
    .regex(/^[a-z0-9-]+$/, 'Agent IDs must be lowercase letters, numbers, and hyphens only'),

  /** Human-readable name */
  name: z.string().min(1),

  /** Semver version string */
  version: z
    .string()
    .regex(/^\d+\.\d+\.\d+$/, 'Version must follow semver: x.y.z'),

  /** Functional category */
  category: AgentCategoryEnum,

  /** What this agent does — minimum 10 chars to discourage placeholder text */
  description: z.string().min(10),

  /**
   * Everything this agent is allowed to do.
   * The registry and ModelGuard enforce this list at runtime.
   * Claim only what you actually use — principle of least capability.
   */
  capabilities: z.array(AgentCapabilityEnum).min(1),

  /** Risk tier — determines approval gates, rate limits, and audit depth */
  trustLevel: z.nativeEnum(AgentRiskTier),

  /** Agent IDs this agent sends events to or receives events from */
  peers: z.array(z.string()).optional().default([]),

  /** Searchable tags */
  tags: z.array(z.string()).optional().default([]),

  /** Author or team name */
  author: z.string().optional(),

  /** Link to documentation or satellite repo */
  homepage: z.string().url().optional(),
});

export type AgentManifest = z.infer<typeof AgentManifestSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────────────────────

export function validateManifest(raw: unknown): AgentManifest {
  const result = AgentManifestSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  ${i.path.join('.') || 'root'}: ${i.message}`)
      .join('\n');
    throw new Error(`[AgentManifest] Validation failed:\n${issues}`);
  }
  return result.data;
}

export function isValidManifest(raw: unknown): raw is AgentManifest {
  return AgentManifestSchema.safeParse(raw).success;
}
