/**
 * Credential Sealing — secrets removed from process.env in production
 *
 * NIST AI RMF 1.0 — GOVERN (GV-2), MANAGE (MG-2.2) — credential exposure
 *
 * Run: npx jest tests/security/credential-sealing.test.ts --verbose
 *
 * Known limitation: "Credential vault uses environment variables — API keys
 * live in process.env, readable by any in-process code (including plugins)."
 * An external secrets manager/HSM remains the ideal; this suite proves the
 * implemented mitigation: at startup finalization (prod-gated) credentials
 * are captured into a sealed in-memory store and DELETED from process.env,
 * so in-process code can no longer read raw keys there, while the gated
 * getSecret()/requireSecret() and credential consumers still resolve them.
 */

const ENV_KEYS = ['SEALME', 'OTHER_CFG', 'ANTHROPIC_API_KEY', 'EOS_SEAL_SECRETS', 'NODE_ENV'];
let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = {};
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  delete process.env.EOS_SEAL_SECRETS;
  process.env.NODE_ENV = 'test';
  jest.resetModules();
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

async function freshSecrets() {
  return import('../../src/security/secrets-provider');
}

test('sealing is a no-op when disabled (not prod, no flag)', async () => {
  process.env.SEALME = 'plain';
  const sp = await freshSecrets();

  const res = sp.sealSecrets(['SEALME']);

  expect(res.enabled).toBe(false);
  expect(res.sealed).toEqual([]);
  expect(process.env.SEALME).toBe('plain'); // untouched in dev
  expect(sp.getSecret('SEALME')).toBe('plain');
});

test('EOS_SEAL_SECRETS=1 seals: key leaves process.env but getSecret still resolves it', async () => {
  process.env.SEALME = 'topsecret';
  process.env.EOS_SEAL_SECRETS = '1';
  const sp = await freshSecrets();

  const res = sp.sealSecrets(['SEALME']);

  expect(res.enabled).toBe(true);
  expect(res.sealed).toEqual(['SEALME']);
  expect(process.env.SEALME).toBeUndefined(); // removed from env
  expect(sp.getSecret('SEALME')).toBe('topsecret'); // still available via gate
  expect(sp.getSecretsProvider()).toBeInstanceOf(sp.SealedSecretsProvider);
});

test('NODE_ENV=production enables sealing', async () => {
  process.env.SEALME = 'prodsecret';
  process.env.NODE_ENV = 'production';
  const sp = await freshSecrets();

  const res = sp.sealSecrets(['SEALME']);

  expect(res.enabled).toBe(true);
  expect(process.env.SEALME).toBeUndefined();
  expect(sp.requireSecret('SEALME')).toBe('prodsecret');
});

test('non-sealed env vars still resolve via fallback after sealing', async () => {
  process.env.SEALME = 's';
  process.env.OTHER_CFG = 'o';
  process.env.EOS_SEAL_SECRETS = '1';
  const sp = await freshSecrets();

  sp.sealSecrets(['SEALME']);

  expect(process.env.SEALME).toBeUndefined();
  expect(process.env.OTHER_CFG).toBe('o'); // not in sealed set
  expect(sp.getSecret('OTHER_CFG')).toBe('o');
  expect(sp.getSecret('SEALME')).toBe('s');
});

test('an LLM provider constructed AFTER sealing still receives its key', async () => {
  process.env.ANTHROPIC_API_KEY = 'sk-ant-test';
  process.env.EOS_SEAL_SECRETS = '1';

  const sp = await freshSecrets();
  // Same reset module graph → ClaudeProvider's getSecret is this sp instance.
  const { ClaudeProvider } = await import('../../src/runtime/providers/ClaudeProvider');

  sp.sealSecrets(['ANTHROPIC_API_KEY']);
  expect(process.env.ANTHROPIC_API_KEY).toBeUndefined();

  const provider = new ClaudeProvider();
  expect((provider as unknown as { apiKey?: string }).apiKey).toBe('sk-ant-test');
});

test('requireSecret throws for a key that was never present', async () => {
  process.env.EOS_SEAL_SECRETS = '1';
  const sp = await freshSecrets();
  sp.sealSecrets(['SEALME']); // SEALME not set
  expect(() => sp.requireSecret('SEALME')).toThrow(/not found|not set/i);
});

test('sealSecrets refuses to run after the provider is locked', async () => {
  process.env.EOS_SEAL_SECRETS = '1';
  const sp = await freshSecrets();
  sp.lockSecretsProvider();
  expect(() => sp.sealSecrets(['SEALME'])).toThrow(/before lockSecretsProvider/);
});
