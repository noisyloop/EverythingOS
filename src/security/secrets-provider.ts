/**
 * Secrets Provider — Abstraction over credential storage backends
 *
 * NIST AI RMF 1.0 — GOVERN (GV-2), MANAGE (MG-2.2)
 *
 * The default EnvSecretsProvider reads from process.env (current behavior).
 * Replace with HashiCorpVaultProvider, AWSSecretsManagerProvider, or any
 * external secrets manager by calling setSecretsProvider() at startup.
 *
 * Usage:
 *   // Production with HashiCorp Vault
 *   import { setSecretsProvider } from './secrets-provider';
 *   setSecretsProvider(new HashiCorpVaultProvider(vaultConfig));
 *
 *   // Then consume via:
 *   import { getSecret, requireSecret } from './secrets-provider';
 *   const key = requireSecret('ANTHROPIC_API_KEY');
 */

// ─────────────────────────────────────────────────────────────────────────────
// Interface
// ─────────────────────────────────────────────────────────────────────────────

export interface SecretsProvider {
  /**
   * Retrieve a secret by key. Returns undefined if not found.
   * Implementations that fetch remotely should cache values after warmup().
   */
  get(key: string): string | undefined;

  /**
   * Retrieve a secret, throwing if absent.
   */
  require(key: string): string;

  /**
   * Optional: pre-fetch secrets at startup to avoid cold lookups at call time.
   * Call await provider.warmup(['KEY_A', 'KEY_B']) before locking providers.
   */
  warmup?(keys: string[]): Promise<void>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Default: environment variables
// ─────────────────────────────────────────────────────────────────────────────

export class EnvSecretsProvider implements SecretsProvider {
  get(key: string): string | undefined {
    return process.env[key];
  }

  require(key: string): string {
    const val = process.env[key];
    if (!val) {
      throw new Error(
        `[SecretsProvider] Required secret "${key}" is not set. ` +
        `Set it in your environment or configure an external secrets provider via setSecretsProvider().`
      );
    }
    return val;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache-backed wrapper — for async remote providers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Wraps any async fetch function to provide a synchronous get() interface
 * after warmup(). Intended for use with HashiCorp Vault, AWS Secrets Manager,
 * GCP Secret Manager, Azure Key Vault, etc.
 *
 * Usage:
 *   const provider = new CachedRemoteProvider(async (key) => {
 *     return vaultClient.readSecret(key);
 *   });
 *   await provider.warmup(['ANTHROPIC_API_KEY', 'OPENAI_API_KEY']);
 *   setSecretsProvider(provider);
 */
export class CachedRemoteProvider implements SecretsProvider {
  private cache = new Map<string, string>();

  constructor(
    private readonly fetcher: (key: string) => Promise<string | undefined>
  ) {}

  async warmup(keys: string[]): Promise<void> {
    await Promise.all(
      keys.map(async (key) => {
        const val = await this.fetcher(key);
        if (val !== undefined) this.cache.set(key, val);
      })
    );
  }

  get(key: string): string | undefined {
    return this.cache.get(key) ?? process.env[key]; // env fallback during dev
  }

  require(key: string): string {
    const val = this.get(key);
    if (!val) throw new Error(`[SecretsProvider] Required secret "${key}" not found in cache or environment.`);
    return val;
  }

  /** Force-refresh a specific key from the remote source. */
  async refresh(key: string): Promise<void> {
    const val = await this.fetcher(key);
    if (val !== undefined) this.cache.set(key, val);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Process-wide singleton
// ─────────────────────────────────────────────────────────────────────────────

let _provider: SecretsProvider = new EnvSecretsProvider();
// STRIDE I-2: freeze provider registry after startup
let _providerLocked = false;

/**
 * Freeze the secrets provider. Call once at startup after all agents are
 * registered. Prevents a compromised in-process agent from swapping in a
 * malicious provider to exfiltrate secrets via getSecret() calls.
 */
export function lockSecretsProvider(): void {
  _providerLocked = true;
}

/**
 * Replace the process-wide secrets provider.
 * Call at startup before lockSecretsProvider() — throws after locking.
 */
export function setSecretsProvider(provider: SecretsProvider): void {
  if (_providerLocked) {
    throw new Error(
      '[SecretsProvider] Provider is locked. setSecretsProvider() must be called at startup, before lockSecretsProvider().'
    );
  }
  _provider = provider;
}

export function getSecretsProvider(): SecretsProvider {
  return _provider;
}

/** Retrieve a secret from the active provider. Returns undefined if absent. */
export function getSecret(key: string): string | undefined {
  return _provider.get(key);
}

/** Retrieve a secret, throwing if absent. */
export function requireSecret(key: string): string {
  return _provider.require(key);
}
