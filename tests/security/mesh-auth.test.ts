/**
 * Mesh Network — Authenticated Peer Enrollment & Message Integrity
 *
 * NIST AI RMF 1.0 — MANAGE (MG-4.1) — distributed system trust boundary
 *
 * Run: npx jest tests/security/mesh-auth.test.ts --verbose
 *
 * Known limitation: "Swarm mesh has no mTLS — a node on the same network
 * segment could inject as a peer." Full X.509 mTLS (per-deployment CA + cert
 * distribution) remains the ideal; this suite proves the implemented
 * mitigation: when meshSecret is configured, peer enrollment and every
 * message require a fresh, non-replayed HMAC proof of the deployment secret,
 * and the signature now covers `type` and `payload` (a captured message can
 * no longer be tampered or re-purposed).
 */

import { randomBytes } from 'crypto';
import { MeshNetwork, MeshMessage } from '../../src/plugins/swarm/MeshNetwork';
import { eventBus } from '../../src/core/event-bus/EventBus';

const SECRET = 'a'.repeat(64);

// Access the private auth surface without standing up MQTT transport.
interface MeshInternals {
  handleDiscovery(payload: Buffer): void;
  verifyMessage(m: MeshMessage): boolean;
  signMessage(m: MeshMessage): string;
  hmacHex(material: string): string;
  discoveryMaterial(a: { nodeId: string; address?: string; timestamp: number; nonce: string }): string;
}
const priv = (m: MeshNetwork): MeshInternals => m as unknown as MeshInternals;

function capture(pattern: string): { events: unknown[]; stop: () => void } {
  const events: unknown[] = [];
  const off = eventBus.on(pattern, (e) => {
    events.push((e as { payload: unknown }).payload);
  });
  return { events, stop: off };
}

// Build a correctly-signed enrollment announcement using the deployment
// secret (what a legitimate node would publish).
function signedAnnouncement(signer: MeshNetwork, nodeId: string, ts = Date.now()) {
  const nonce = randomBytes(16).toString('hex');
  const sig = priv(signer).hmacHex(
    priv(signer).discoveryMaterial({ nodeId, timestamp: ts, nonce }),
  );
  return { nodeId, timestamp: ts, nonce, sig };
}

const buf = (o: unknown) => Buffer.from(JSON.stringify(o));

// EventBus dispatches its queue asynchronously — yield so emitted events land.
const flush = () => new Promise((r) => setImmediate(r));

describe('Mesh authenticated enrollment (meshSecret set)', () => {
  let node: MeshNetwork;

  beforeEach(() => {
    node = new MeshNetwork({ nodeId: 'node-self', meshSecret: SECRET });
  });

  test('an unsigned announcement cannot inject as a peer', async () => {
    const rejected = capture('mesh:peer:rejected');
    priv(node).handleDiscovery(buf({ nodeId: 'attacker', timestamp: Date.now() }));
    await flush();
    rejected.stop();

    expect(node.getPeer('attacker')).toBeUndefined();
    expect(rejected.events).toHaveLength(1);
    expect((rejected.events[0] as { reason: string }).reason).toBe(
      'enrollment_authentication_failed',
    );
  });

  test('a forged signature (wrong secret) is rejected', () => {
    const attacker = new MeshNetwork({ nodeId: 'x', meshSecret: 'wrong-secret' });
    priv(node).handleDiscovery(buf(signedAnnouncement(attacker, 'attacker')));
    expect(node.getPeer('attacker')).toBeUndefined();
  });

  test('a correctly-signed announcement enrolls the peer', async () => {
    const legit = new MeshNetwork({ nodeId: 'good', meshSecret: SECRET });
    const joined = capture('mesh:peer:joined');
    priv(node).handleDiscovery(buf(signedAnnouncement(legit, 'good')));
    await flush();
    joined.stop();

    expect(node.getPeer('good')).toBeDefined();
    expect(joined.events).toHaveLength(1);
  });

  test('replaying a captured valid announcement is rejected', async () => {
    const legit = new MeshNetwork({ nodeId: 'good', meshSecret: SECRET });
    const ann = signedAnnouncement(legit, 'good');

    priv(node).handleDiscovery(buf(ann)); // first: accepted
    expect(node.getPeer('good')).toBeDefined();

    const rejected = capture('mesh:peer:rejected');
    priv(node).handleDiscovery(buf(ann)); // replay: same nonce
    await flush();
    rejected.stop();
    expect(rejected.events).toHaveLength(1);
  });

  test('a stale (but correctly-signed) announcement is rejected', () => {
    const legit = new MeshNetwork({ nodeId: 'good', meshSecret: SECRET });
    const stale = signedAnnouncement(legit, 'good', Date.now() - 120_000);
    priv(node).handleDiscovery(buf(stale));
    expect(node.getPeer('good')).toBeUndefined();
  });
});

describe('Mesh message integrity (meshSecret set)', () => {
  const sender = new MeshNetwork({ nodeId: 'sender', meshSecret: SECRET });
  const receiver = new MeshNetwork({ nodeId: 'receiver', meshSecret: SECRET });

  function signedMessage(): MeshMessage {
    const m: MeshMessage = {
      id: 'm1',
      type: 'swarm:task',
      from: 'sender',
      to: 'receiver',
      payload: { cmd: 'move', x: 1 },
      timestamp: Date.now(),
      ttl: 5,
      path: ['sender'],
      nonce: randomBytes(16).toString('hex'),
    };
    m.hmac = priv(sender).signMessage(m);
    return m;
  }

  test('an untampered signed message verifies', () => {
    expect(priv(receiver).verifyMessage(signedMessage())).toBe(true);
  });

  test('tampering the payload invalidates the signature (regression: HMAC now covers payload)', () => {
    const m = signedMessage();
    m.payload = { cmd: 'self-destruct' };
    expect(priv(receiver).verifyMessage(m)).toBe(false);
  });

  test('tampering the type invalidates the signature', () => {
    const m = signedMessage();
    m.type = 'swarm:shutdown';
    expect(priv(receiver).verifyMessage(m)).toBe(false);
  });

  test('a replayed message is rejected on second receipt', () => {
    const m = signedMessage();
    expect(priv(receiver).verifyMessage(m)).toBe(true);
    expect(priv(receiver).verifyMessage(m)).toBe(false); // same nonce again
  });

  test('a message missing nonce/hmac is rejected', () => {
    const m = signedMessage();
    delete m.hmac;
    expect(priv(receiver).verifyMessage(m)).toBe(false);
  });
});

describe('Dev mode (no meshSecret) — open mesh, documented', () => {
  test('enrollment and messages are unauthenticated when no secret is set', () => {
    const dev = new MeshNetwork({ nodeId: 'dev' });
    priv(dev).handleDiscovery(buf({ nodeId: 'anyone' }));
    expect(dev.getPeer('anyone')).toBeDefined();

    const m = { id: 'x', type: 't', from: 'a', to: 'dev', payload: {}, timestamp: Date.now(), ttl: 1, path: ['a'] } as MeshMessage;
    expect(priv(dev).verifyMessage(m)).toBe(true);
  });
});
