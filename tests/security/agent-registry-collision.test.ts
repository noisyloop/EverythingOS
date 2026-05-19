/**
 * AgentRegistry — ID Collision Rejection (STRIDE E-5)
 *
 * NIST AI RMF 1.0 — MANAGE (MG-4.1) — agent identity is a trust anchor
 *
 * Run: npx jest tests/security/agent-registry-collision.test.ts --verbose
 *
 * STRIDE E-5 claimed "registry prevents ID collisions" (the ApprovalGate
 * trustedAgents auto-approve path depends on it), but register() silently
 * unregistered and overwrote a duplicate id — a malicious agent could seize
 * a trusted agent's identity with no signal. This proves the collision is
 * now rejected and audited, while legitimate re-registration after
 * unregister still works.
 */

import { agentRegistry as AgentRegistry } from '../../src/core/registry/AgentRegistry';
import { Agent } from '../../src/runtime/Agent';
import { AgentRiskTier } from '../../src/types/agent-risk';
import { AuditLogger } from '../../src/security/audit-log';

class TinyAgent extends Agent {
  constructor(id: string, name = id) {
    super({
      id,
      name,
      type: 'foundation',
      riskConfig: {
        tier: AgentRiskTier.LOW,
        riskJustification: 'collision test agent',
        allowedPublishChannels: [],
        allowedSubscribeChannels: [],
      },
    });
  }
  protected async onStart(): Promise<void> {}
  protected async onStop(): Promise<void> {}
}

afterEach(() => {
  try { AgentRegistry.unregister('collide-1'); } catch { /* ignore */ }
});

test('a second agent claiming a registered id is rejected and audited', () => {
  const audit = jest.spyOn(AuditLogger, 'log');

  AgentRegistry.register(new TinyAgent('collide-1', 'legit'));

  const attacker = new TinyAgent('collide-1', 'attacker');
  expect(() => AgentRegistry.register(attacker)).toThrow(/already registered/i);

  // The original agent is still the one in the registry — not overwritten.
  const listed = AgentRegistry.list().find((a) => a.id === 'collide-1');
  expect(listed?.name).toBe('legit');

  const violation = audit.mock.calls.find(
    (c) => c[0]?.event === 'safety.violation' &&
      (c[0]?.metadata as { action?: string })?.action === 'agent_id_collision_rejected',
  );
  expect(violation).toBeDefined();
  audit.mockRestore();
});

test('re-registering an id after unregister still works (no false positive)', () => {
  AgentRegistry.register(new TinyAgent('collide-1', 'first'));
  AgentRegistry.unregister('collide-1');
  expect(() => AgentRegistry.register(new TinyAgent('collide-1', 'second'))).not.toThrow();
  expect(AgentRegistry.list().find((a) => a.id === 'collide-1')?.name).toBe('second');
});
