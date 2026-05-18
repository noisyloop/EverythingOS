/**
 * Decision Ledger — Tamper-Evident Hash Chain (STRIDE T-4)
 *
 * NIST AI RMF 1.0 — MEASURE (MS-2.6) — decision provenance / non-repudiation
 *
 * Run: npx jest tests/security/decision-ledger-chain.test.ts --verbose
 *
 * STRIDE T-4 ("decision ledger hash chain") was marked resolved but the
 * ledger only had per-entry hashes — deletion/reordering was undetectable.
 * This proves the implemented cross-entry chain: a clean ledger verifies,
 * content tampering and entry deletion are both caught with the breaking
 * index, and pre-chain (legacy) entries remain verifiable (back-compat).
 */

import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash } from 'crypto';

let dir: string;
let path: string;
let DL: typeof import('../../src/security/decision-ledger').DecisionLedger;
let flush: typeof import('../../src/security/decision-ledger').flushDecisionLedger;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'dl-chain-'));
  path = join(dir, 'decisions.jsonl');
  process.env.DECISION_LEDGER_PATH = path;
  const mod = await import('../../src/security/decision-ledger');
  DL = mod.DecisionLedger;
  flush = mod.flushDecisionLedger;
});

afterAll(() => rmSync(dir, { recursive: true, force: true }));

beforeEach(async () => {
  await flush(); // close any open append stream from the prior test
  writeFileSync(path, '', 'utf8');
  DL.initialize(); // resets chain head to GENESIS for the empty file
});

function record(n: number) {
  return DL.record({
    agentId: `agent-${n}`,
    decisionType: 'llm.completion',
    context: DL.buildContext({ modelId: 'm', promptTemplate: `p${n}` }),
    inputHash: `in${n}`,
    outputHash: `out${n}`,
  });
}

const lines = () => readFileSync(path, 'utf8').split('\n').filter((l) => l.trim());

test('a clean ledger verifies and entries are linked', async () => {
  const e1 = record(1);
  const e2 = record(2);
  const e3 = record(3);
  await flush();

  expect(e1.previousHash).toBe('GENESIS');
  expect(e2.previousHash).toBe(e1.entryHash);
  expect(e3.previousHash).toBe(e2.entryHash);

  const res = await DL.verifyChain();
  expect(res).toEqual({ valid: true, totalEntries: 3 });
});

test('content tampering is detected at the modified entry', async () => {
  record(1); record(2); record(3);
  await flush();

  const ls = lines();
  const middle = JSON.parse(ls[1]);
  middle.outcome = { tampered: true }; // change content, keep its entryHash
  ls[1] = JSON.stringify(middle);
  writeFileSync(path, ls.join('\n') + '\n', 'utf8');

  const res = await DL.verifyChain();
  expect(res.valid).toBe(false);
  expect(res.brokenAt).toBe(1);
  expect(res.reason).toMatch(/hash mismatch/i);
});

test('deleting an entry breaks the chain at the next entry', async () => {
  record(1); record(2); record(3);
  await flush();

  const ls = lines();
  ls.splice(1, 1); // delete the middle entry
  writeFileSync(path, ls.join('\n') + '\n', 'utf8');

  const res = await DL.verifyChain();
  expect(res.valid).toBe(false);
  expect(res.brokenAt).toBe(1);
  expect(res.reason).toMatch(/chain broken|deleted|reordered/i);
});

test('reordering entries is detected', async () => {
  record(1); record(2); record(3);
  await flush();
  const ls = lines();
  [ls[0], ls[1]] = [ls[1], ls[0]]; // swap first two
  writeFileSync(path, ls.join('\n') + '\n', 'utf8');

  const res = await DL.verifyChain();
  expect(res.valid).toBe(false);
});

test('legacy entries without previousHash remain verifiable (back-compat)', async () => {
  const sha = (v: string) => createHash('sha256').update(v).digest('hex');

  // Two pre-chain entries: no `previousHash` field at all.
  const legacy = [1, 2].map((n) => {
    const base = {
      agentId: `legacy-${n}`,
      decisionType: 'llm.completion',
      context: DL.buildContext({ modelId: 'm', promptTemplate: `lp${n}` }),
      inputHash: `lin${n}`,
      outputHash: `lout${n}`,
      ledgerId: `legacy-id-${n}`,
      recordedAt: new Date().toISOString(),
      recordedAtMs: Date.now(),
    };
    return { ...base, entryHash: sha(JSON.stringify(base)) };
  });
  writeFileSync(path, legacy.map((e) => JSON.stringify(e)).join('\n') + '\n', 'utf8');

  // initialize() bootstraps the chain head from the last (legacy) entry,
  // so a new chained entry links onto it.
  DL.initialize();
  record(99);
  await flush();

  const res = await DL.verifyChain();
  expect(res).toEqual({ valid: true, totalEntries: 3 });
});
