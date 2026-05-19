#!/usr/bin/env node
// EverythingOS CLI launcher.
// The CLI is authored in TypeScript (cli/index.ts) and the project build
// is noEmit, so run it through the local `tsx` runtime that ships as a
// dev dependency. This makes `npx everythingos ...` work from a cloned
// repo after `npm ci` with no separate build step.

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { existsSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const cliEntry = resolve(here, 'index.ts');
const localTsx = resolve(
  here,
  '..',
  'node_modules',
  '.bin',
  process.platform === 'win32' ? 'tsx.cmd' : 'tsx',
);

const runner = existsSync(localTsx) ? localTsx : 'tsx';

const child = spawn(runner, [cliEntry, ...process.argv.slice(2)], {
  stdio: 'inherit',
});

child.on('exit', (code) => process.exit(code ?? 0));
child.on('error', (err) => {
  console.error('[everythingos] failed to launch CLI:', err.message);
  console.error('[everythingos] ensure dependencies are installed: npm ci');
  process.exit(1);
});
