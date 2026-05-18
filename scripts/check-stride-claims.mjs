#!/usr/bin/env node
/**
 * STRIDE claim ↔ evidence gate.
 *
 * D-6 (and the 2026-05-18 audit) showed a finding can be marked "✅ resolved"
 * in docs/STRIDE.md while the code does nothing. This gate makes that class
 * of drift fail CI:
 *
 *   - Every finding in the STRIDE summary table MUST have a manifest entry
 *     here (a new finding cannot be added without a conscious decision).
 *   - A finding the table marks ✅ MUST be backed by either:
 *       • `test`: an attack-path regression test that exists AND references
 *         the finding id, OR
 *       • `attested`: an explicit code anchor (verified by audit, no
 *         dedicated automated test yet) — surfaced as debt, not silent.
 *   - A finding the table does NOT mark ✅ (⚠️/❌/🔬) MUST be declared
 *     `resolved:false` here, so flipping it to ✅ requires editing both the
 *     doc and this manifest — they cannot silently diverge.
 *
 * Run: node scripts/check-stride-claims.mjs   (npm run check:stride)
 */
import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const stridePath = resolve(root, 'docs/STRIDE.md');

// ── Evidence manifest ────────────────────────────────────────────────────────
// test     → attack-path regression test (must exist and mention the id)
// attested → code anchor verified by the 2026-05-18 audit (tracked debt)
// resolved:false → the finding is NOT claimed resolved (⚠️/❌/🔬)
const MANIFEST = {
  'S-1': { resolved: false }, // ⚠️ external-replay only; in-process theft open
  'S-2': { attested: 'ApprovalGateAgent.ts submitDecision() — no approval:decision EventBus intake' },
  'S-3': { resolved: false }, // ⚠️ no caller auth; only post-startup lock
  'S-4': { attested: 'PolicyEngine.lock(); SupervisorAgent.start() calls it' },
  'T-1': { attested: 'audit-log.ts initialize() → verifyChain() + alert' },
  'T-2': { resolved: false }, // ⚠️ falls back to EOS_AGENT_SECRET
  'T-3': { attested: 'agent-auth.ts persistRevocation()/loadPersistentRevocations() hash chain, fail-closed' },
  'T-4': { test: 'tests/security/decision-ledger-chain.test.ts' },
  'T-5': { test: 'tests/security/plugin-return-sanitization.test.ts' },
  'T-6': { attested: 'safe-regex.ts re2Pattern used across sanitize.ts/content-filter.ts' },
  'R-1': { attested: 'ApprovalGateAgent.ts verifyApprovalToken — challengeNonce + approvedBy in HMAC' },
  'R-2': { attested: 'shutdown.ts uncaughtException/unhandledRejection → emergencyFlush' },
  'R-3': { attested: 'decision-ledger.ts createWriteStream (no appendFileSync on write path)' },
  'I-1': { attested: 'agent-auth.ts lockIssuance(); issueToken() throws when locked' },
  'I-2': { attested: 'secrets-provider.ts lockSecretsProvider(); setSecretsProvider() throws when locked' },
  'I-3': { attested: 'audit-log.ts scrubMetadata() → scrubPII() on the write path' },
  'I-4': { attested: 'plugin-sandbox.ts validateConfig() CREDENTIAL_*_RE invoked in constructor' },
  'I-5': { resolved: false }, // ⚠️
  'D-1': { attested: 'agent-auth.ts setInterval(5m).unref() purges expired tokens + nonces' },
  'D-2': { attested: 'EventBus.ts checkGlobalRateLimit() — 10k/60s global ceiling in emit()' },
  'D-3': { attested: 'sanitize.ts setInterval(5m).unref() purges stale rate-limit counters' },
  'D-4': { attested: 'decision-ledger.ts queryDisk() + audit-log verifyChain() readline streaming' },
  'D-5': { resolved: false }, // 🔬 formal proof pending
  'D-6': { test: 'tests/security/glasswally-line-buffer.test.ts' },
  'E-1': { attested: 'ApprovalGateAgent.ts authenticated submitDecision() + per-approval challenge nonce' },
  'E-2': { resolved: false }, // ❌ IsolatedAgentRunner exists but unwired
  'E-3': { attested: 'SupervisorAgent.start() → policyEngine.lock(); addPolicy() throws when locked' },
  'E-4': { attested: 'shutdown.ts finalizeStartup() → ModelGuard.lockModels(); approve() throws when locked' },
  'E-5': { test: 'tests/security/agent-registry-collision.test.ts' },
};

// ── Parse the STRIDE finding summary table ───────────────────────────────────
const md = readFileSync(stridePath, 'utf8');
const table = new Map(); // id -> { resolved: boolean, status: string }
for (const line of md.split('\n')) {
  const m = /^\|\s*([STRIDE]-\d+|[A-Z]-\d+)\s*\|/.exec(line);
  if (!m) continue;
  const cells = line.split('|').map((c) => c.trim());
  const id = cells[1];
  const status = cells[4] ?? '';
  table.set(id, { resolved: status.includes('✅'), status });
}

if (table.size === 0) {
  console.error('FAIL: could not parse any findings from docs/STRIDE.md table');
  process.exit(1);
}

// ── Enforce ──────────────────────────────────────────────────────────────────
const errors = [];
const tested = [];
const attested = [];
const notResolved = [];

for (const [id, { resolved, status }] of table) {
  const entry = MANIFEST[id];
  if (!entry) {
    errors.push(`${id}: in STRIDE table (status "${status}") but missing from the evidence manifest. Add an entry to scripts/check-stride-claims.mjs.`);
    continue;
  }

  if (resolved) {
    if (entry.resolved === false) {
      errors.push(`${id}: STRIDE marks it ✅ but the manifest declares it unresolved. Reconcile the doc and the manifest.`);
      continue;
    }
    if (entry.test) {
      const p = resolve(root, entry.test);
      if (!existsSync(p)) {
        errors.push(`${id}: linked test "${entry.test}" does not exist.`);
      } else if (!readFileSync(p, 'utf8').includes(id)) {
        errors.push(`${id}: linked test "${entry.test}" does not reference "${id}" — link unverifiable.`);
      } else {
        tested.push(id);
      }
    } else if (entry.attested && String(entry.attested).trim()) {
      attested.push(id);
    } else {
      errors.push(`${id}: STRIDE marks it ✅ but the manifest provides neither a "test" nor an "attested" code anchor.`);
    }
  } else {
    if (entry.resolved !== false) {
      errors.push(`${id}: STRIDE status is "${status}" (not ✅) but the manifest does not declare resolved:false. A non-resolved finding must not carry resolution evidence.`);
    } else {
      notResolved.push(id);
    }
  }
}

for (const id of Object.keys(MANIFEST)) {
  if (!table.has(id)) {
    errors.push(`${id}: present in the manifest but not in the STRIDE table — stale manifest entry.`);
  }
}

// ── Report ───────────────────────────────────────────────────────────────────
console.log(`STRIDE findings: ${table.size}`);
console.log(`  ✅ test-backed   (${tested.length}): ${tested.join(', ') || '—'}`);
console.log(`  ✅ attested-only (${attested.length}): ${attested.join(', ') || '—'}`);
console.log(`  ▫ not resolved   (${notResolved.length}): ${notResolved.join(', ') || '—'}`);
if (attested.length) {
  console.log(`\nDEBT: ${attested.length} resolved findings are audit-attested but have no automated attack-path test. Convert these to "test" over time.`);
}

if (errors.length) {
  console.error(`\nFAIL — STRIDE claim/evidence gate (${errors.length}):`);
  for (const e of errors) console.error(`  ✗ ${e}`);
  process.exit(1);
}
console.log('\nPASS — every STRIDE ✅ is test-backed or audit-attested; doc and manifest agree.');
