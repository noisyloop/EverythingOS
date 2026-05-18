// Per-worker isolation of on-disk security logs.
//
// AuditLogger, AgentAuthManager (revocation log) and DecisionLedger resolve
// their file paths from env at module load and APPEND to them. Jest runs test
// files across parallel worker processes; pointing every worker at the same
// default files (./everythingos-audit.jsonl, ./agent-revocations.jsonl,
// ./everythingos-decisions.jsonl) makes independent processes interleave
// appends — corrupting the audit hash chain and leaking persistent agent
// revocations across unrelated suites.
//
// setupFiles runs before any module is imported in the worker, so giving each
// worker its own temp paths fully isolates suites while keeping tests parallel.

import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const worker = process.env.JEST_WORKER_ID ?? String(process.pid);
const dir = mkdtempSync(join(tmpdir(), `eos-test-w${worker}-`));

process.env.AUDIT_LOG_PATH = join(dir, 'audit.jsonl');
process.env.AGENT_REVOCATION_LOG = join(dir, 'revocations.jsonl');
process.env.DECISION_LEDGER_PATH = join(dir, 'decisions.jsonl');
process.env.MODEL_GUARD_DIR = join(dir, 'model-guard');
