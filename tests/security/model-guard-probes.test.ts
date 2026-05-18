/**
 * ModelGuard — Probe Randomization & Out-of-Band Probe Sets
 *
 * NIST AI RMF 1.0 — MEASURE (MS-2.5, MS-2.6) — model behavior integrity
 *
 * Run: npx jest tests/security/model-guard-probes.test.ts --verbose
 *
 * Known limitation: behavioral fingerprint probes live in source, so an
 * adversary who reads the repo can craft a model that passes exactly them.
 * This suite proves the two mitigations: (1) an out-of-band probe file fully
 * replaces the built-ins, and (2) a cryptographically-random probe subset is
 * pinned into the baseline so drift detection stays apples-to-apples while
 * the live probe set is not predictable from source. Existing baselines stay
 * valid (full pool, declared order) with no migration.
 */

import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const BUILTIN_IDS = [
  'math-basic',
  'capital-city',
  'json-structure',
  'refusal-boundary',
  'safety-check',
];

// Deterministic router: same prompt → same response, so re-running the same
// probe selection yields a stable fingerprint (no spurious drift).
const router = {
  complete: async (req: { messages: Array<{ content: string }> }) => ({
    content: `echo:${req.messages[0].content}`,
  }),
} as any;

let dir: string;
let ModelGuard: typeof import('../../src/security/model-guard').ModelGuard;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'mg-probes-'));
  process.env.MODEL_GUARD_DIR = dir;
  // Dynamic import (not hoisted) so MODEL_GUARD_DIR is set before the module
  // resolves its storage paths at load time.
  ({ ModelGuard } = await import('../../src/security/model-guard'));
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

beforeEach(() => {
  // Reset the baseline index so each test starts from a clean slate.
  rmSync(join(dir, 'fingerprints.json'), { force: true });
  rmSync(join(dir, 'fingerprints.sig'), { force: true });
  delete process.env.MODEL_GUARD_PROBES_FILE;
  delete process.env.MODEL_GUARD_PROBE_COUNT;
});

const PROV = 'anthropic';
const MODEL = 'claude-sonnet-4-20250514'; // on the approved list

test('default: full built-in pool in declared order (back-compat)', async () => {
  const fp = await ModelGuard.fingerprint(PROV, router, MODEL);
  expect(fp.probeSelection).toEqual(BUILTIN_IDS);
  expect(fp.probeResults.map((r) => r.id)).toEqual(BUILTIN_IDS);

  const first = ModelGuard.recordFingerprint(PROV, MODEL, fp);
  expect(first.driftDetected).toBe(false);

  // Re-run: identical selection, deterministic responses → no drift.
  const fp2 = await ModelGuard.fingerprint(PROV, router, MODEL);
  expect(fp2.probeSelection).toEqual(BUILTIN_IDS);
  expect(fp2.fingerprintHash).toBe(fp.fingerprintHash);
  expect(ModelGuard.recordFingerprint(PROV, MODEL, fp2).driftDetected).toBe(false);
});

test('out-of-band probe file fully replaces the built-in probes', async () => {
  const probeFile = join(dir, 'oob-probes.json');
  writeFileSync(
    probeFile,
    JSON.stringify([
      { id: 'oob-alpha', prompt: 'custom probe one', expected: '^echo:', flags: 'i' },
      { id: 'oob-beta', prompt: 'custom probe two', expected: 'echo' },
    ]),
  );
  process.env.MODEL_GUARD_PROBES_FILE = probeFile;

  const fp = await ModelGuard.fingerprint(PROV, router, MODEL);

  expect(fp.probeSelection).toEqual(['oob-alpha', 'oob-beta']);
  expect(fp.probeResults.map((r) => r.id)).toEqual(['oob-alpha', 'oob-beta']);
  // None of the publicly-known built-in probes were used.
  expect(fp.probeResults.some((r) => BUILTIN_IDS.includes(r.id))).toBe(false);
  expect(fp.allProbesPassed).toBe(true); // patterns match the echo router
});

test('random subset is sized correctly and pinned into the baseline', async () => {
  process.env.MODEL_GUARD_PROBE_COUNT = '2';

  const fp = await ModelGuard.fingerprint(PROV, router, MODEL);
  expect(fp.probeSelection).toHaveLength(2);
  expect(new Set(fp.probeSelection).size).toBe(2); // no duplicates
  fp.probeSelection.forEach((id) => expect(BUILTIN_IDS).toContain(id));

  ModelGuard.recordFingerprint(PROV, MODEL, fp);

  // A later run for the SAME baseline reuses the pinned subset even though
  // the count is still random — drift detection stays comparable.
  const fp2 = await ModelGuard.fingerprint(PROV, router, MODEL);
  expect(fp2.probeSelection).toEqual(fp.probeSelection);
  expect(fp2.fingerprintHash).toBe(fp.fingerprintHash);

  const rec = ModelGuard.getFingerprintRecord(PROV, MODEL);
  expect(rec?.probeSelection).toEqual(fp.probeSelection);
});

test('changing the probe set under an existing baseline fails closed', async () => {
  // Establish a baseline on the built-in pool.
  const base = await ModelGuard.fingerprint(PROV, router, MODEL);
  ModelGuard.recordFingerprint(PROV, MODEL, base);

  // Now swap in an out-of-band set whose ids don't include the pinned ones.
  const probeFile = join(dir, 'different-probes.json');
  writeFileSync(
    probeFile,
    JSON.stringify([{ id: 'totally-different', prompt: 'x', expected: '.' }]),
  );
  process.env.MODEL_GUARD_PROBES_FILE = probeFile;

  await expect(ModelGuard.fingerprint(PROV, router, MODEL)).rejects.toThrow(
    /probe set changed|absent from the active pool/i,
  );
});

test('invalid out-of-band file falls back to built-ins in dev, fails closed in prod', async () => {
  process.env.MODEL_GUARD_PROBES_FILE = join(dir, 'does-not-exist.json');

  // dev/test: graceful fallback to built-ins
  const fp = await ModelGuard.fingerprint(PROV, router, MODEL);
  expect(fp.probeSelection).toEqual(BUILTIN_IDS);

  // production: must NOT silently use the publicly-known built-in probes
  const prev = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    await expect(ModelGuard.fingerprint(PROV, router, MODEL)).rejects.toThrow(
      /MODEL_GUARD_PROBES_FILE/,
    );
  } finally {
    process.env.NODE_ENV = prev;
  }
});
