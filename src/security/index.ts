// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Security Module
// ═══════════════════════════════════════════════════════════════════════════════
export {
  SecurityManager,
  security,
  InputValidator,
  RateLimiter,
  AuthManager,
  SecretsManager,
  AuditLog,
} from './SecurityManager';

export type {
  SecurityConfig,
  ValidationResult,
  Schema,
  SchemaType,
  RateLimitConfig,
  RateLimitResult,
  AuthConfig,
  AuthToken,
  SecretsConfig,
  AuditEntry,
  AuditConfig,
} from './SecurityManager';

// Model Guard — approved model allowlist + behavioral fingerprinting
export { ModelGuard } from './model-guard';
export type {
  FingerprintResult,
  FingerprintRecord,
  ModelGuardViolation,
} from './model-guard';
