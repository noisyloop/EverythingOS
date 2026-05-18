/**
 * GlasswallyAgent — Partial-Line Buffer Cap (STRIDE D-6)
 *
 * NIST AI RMF 1.0 — MANAGE (MG-4.1) — denial-of-service resilience
 *
 * Run: npx jest tests/security/glasswally-line-buffer.test.ts --verbose
 *
 * Threat: Glasswally is a separate privileged process. If it writes to
 * enforcement_actions.jsonl without ever emitting a newline — a write
 * truncated mid-entry, or a compromised Glasswally — GlasswallyAgent's
 * partial-line buffer would grow by up to MAX_BYTES_PER_TICK every tick,
 * unbounded, exhausting the EverythingOS process memory. STRIDE D-6 declared
 * this mitigated ("lineBuffer capped"); this suite proves the cap exists,
 * bounds memory, and recovers cleanly at the next valid record.
 */

import { mkdtempSync, writeFileSync, appendFileSync, rmSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import GlasswallyAgent from '../../src/agents/security/glasswally/index';
import { AuditLogger } from '../../src/security/audit-log';

const MAX_LINE_BUFFER = 1024 * 1024; // mirrors the constant in glasswally/index.ts

// readNewLines is private; exercise it directly without starting the agent
// (it performs no EventBus publishes, so no auth token is required).
type TailResult = { lines: string[]; newOffset: number };
interface TailInternals {
  readNewLines(filePath: string, offset: number): TailResult;
  lineBuffer: string;
  skipOversizedLine: boolean;
}
const internals = (a: GlasswallyAgent): TailInternals => a as unknown as TailInternals;

describe('GlasswallyAgent partial-line buffer cap (STRIDE D-6)', () => {
  let outputDir: string;
  let filePath: string;
  let agent: GlasswallyAgent;
  let auditSpy: jest.SpyInstance;

  beforeEach(() => {
    outputDir = mkdtempSync(join(tmpdir(), 'glasswally-test-'));
    filePath = join(outputDir, 'enforcement_actions.jsonl');
    agent = new GlasswallyAgent({ outputDir, iocSecret: 'test-secret' });
    auditSpy = jest.spyOn(AuditLogger, 'log').mockImplementation((e) => e as never);
  });

  afterEach(() => {
    auditSpy.mockRestore();
    rmSync(outputDir, { recursive: true, force: true });
  });

  // Drains the file through readNewLines exactly as onTick would, one
  // MAX_BYTES_PER_TICK read at a time, until the offset reaches EOF.
  function drain(start: number): { lines: string[]; offset: number } {
    let offset = start;
    const lines: string[] = [];
    // Bounded loop — each iteration advances by ≥1 byte or stops at EOF.
    for (let i = 0; i < 64; i++) {
      const size = statSync(filePath).size;
      if (offset >= size) break;
      const r = internals(agent).readNewLines(filePath, offset);
      lines.push(...r.lines);
      if (r.newOffset === offset) break;
      offset = r.newOffset;
    }
    return { lines, offset };
  }

  test('an unterminated multi-megabyte line never grows the buffer past the cap', () => {
    // 4 MB of non-newline bytes — a Glasswally write that never terminates.
    writeFileSync(filePath, Buffer.alloc(4 * 1024 * 1024, 0x41));

    const { lines, offset } = drain(0);

    expect(lines).toHaveLength(0); // no complete record was ever emitted
    expect(internals(agent).lineBuffer.length).toBeLessThanOrEqual(MAX_LINE_BUFFER);
    // The whole 4 MB blob was consumed without retaining it.
    expect(offset).toBe(statSync(filePath).size);
    expect(internals(agent).skipOversizedLine).toBe(true);

    const overflow = auditSpy.mock.calls.find(
      (c) => c[0]?.event === 'security.glasswally_line_buffer_overflow',
    );
    expect(overflow).toBeDefined();
    expect(overflow![0].metadata.cap).toBe(MAX_LINE_BUFFER);
  });

  test('parsing recovers at the next valid record after an oversized line is discarded', () => {
    writeFileSync(filePath, Buffer.alloc(3 * 1024 * 1024, 0x41));
    const afterGarbage = drain(0).offset;
    expect(internals(agent).skipOversizedLine).toBe(true);

    const record = JSON.stringify({
      action_type: 'RateLimit',
      account_id: 'acct-recovered',
      reason: 'velocity threshold exceeded',
      composite_score: 0.61,
      timestamp: '2026-05-18T00:00:00Z',
    });
    // The oversized line is finally terminated, followed by a clean record.
    appendFileSync(filePath, '\n' + record + '\n');

    const { lines } = drain(afterGarbage);

    expect(lines).toContain(record);
    expect(internals(agent).skipOversizedLine).toBe(false);
    expect(internals(agent).lineBuffer).toBe('');
  });

  test('complete records preceding an oversized fragment are still delivered', () => {
    const good = JSON.stringify({
      action_type: 'FlagForReview',
      account_id: 'acct-good',
      reason: 'flagged',
      composite_score: 0.4,
      timestamp: '2026-05-18T00:00:00Z',
    });
    // valid line + newline, then a 3 MB unterminated fragment in one file
    writeFileSync(filePath, good + '\n' + 'B'.repeat(3 * 1024 * 1024));

    const { lines } = drain(0);

    expect(lines).toContain(good);
    expect(internals(agent).lineBuffer.length).toBeLessThanOrEqual(MAX_LINE_BUFFER);
    expect(internals(agent).skipOversizedLine).toBe(true);
  });

  test('normal tailing is unaffected — buffer stays empty between whole lines', () => {
    const rec = (id: string) =>
      JSON.stringify({
        action_type: 'FlagForReview',
        account_id: id,
        reason: 'r',
        composite_score: 0.4,
        timestamp: '2026-05-18T00:00:00Z',
      });
    writeFileSync(filePath, rec('a') + '\n' + rec('b') + '\n');

    const { lines } = drain(0);

    expect(lines).toEqual([rec('a'), rec('b')]);
    expect(internals(agent).lineBuffer).toBe('');
    expect(internals(agent).skipOversizedLine).toBe(false);
    expect(
      auditSpy.mock.calls.some((c) => c[0]?.event === 'security.glasswally_line_buffer_overflow'),
    ).toBe(false);
  });
});
