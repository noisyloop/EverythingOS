/**
 * RE2-backed pattern factory — guaranteed linear-time matching (STRIDE T-6)
 *
 * NIST AI RMF 1.0 — MANAGE (MG-2.2)
 *
 * V8's default regex engine uses a backtracking NFA which can degrade to
 * O(2^n) on adversarial input. RE2 uses a DFA/NFA hybrid that guarantees
 * O(n) matching time at the cost of not supporting backreferences or
 * lookbehinds.
 *
 * All injection and content-filter patterns are compiled here. The one
 * pattern that requires dotAll (s flag) is rewritten to use [\s\S]{0,N}
 * with an explicit length bound — linear time AND multi-line capable.
 */

import RE2 from 're2';

/**
 * Compile a pattern with RE2.
 * @param source - Regex source string
 * @param flags  - Standard flags (g, i, m). Do NOT pass 's' (dotAll) —
 *                 use expandDotAll() first and pass the rewritten source.
 */
export function re2Pattern(source: string, flags = ''): RE2 {
  return new RE2(source, flags);
}

/**
 * Rewrite a dotAll pattern for RE2 compatibility.
 * Replaces bare `.` (not inside a character class, not escaped) with
 * `[\s\S]` and strips the `s` flag. Also enforces a quantifier bound on
 * `[\s\S]*` to prevent degenerate worst-case matching.
 *
 * This is intentionally narrow — it handles the one specific pattern in
 * content-filter.ts. Do not generalise without additional testing.
 *
 * @param source     - Regex source with bare `.` intended as dotAll
 * @param maxSpan    - Max chars the `[\s\S]` span can match (default 500)
 */
export function dotAllToRE2(source: string, maxSpan = 500): string {
  // Replace unescaped `.*` → `[\s\S]{0,N}` and bare `.` → `[\s\S]`
  return source
    .replace(/(?<!\\)\.\*/g, `[\\s\\S]{0,${maxSpan}}`)
    .replace(/(?<!\\)\.\+/g, `[\\s\\S]{1,${maxSpan}}`)
    .replace(/(?<!\\)\./g,   '[\\s\\S]');
}
