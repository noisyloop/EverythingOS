/**
 * EverythingOS — HTTP Guard
 *
 * Fixes:
 *   CVE-2025-27152 — axios SSRF via absolute URL bypass (axios < 1.8.2)
 *   CVE-2025-58754 — axios DoS via unbounded data: URI memory allocation (axios < 1.11.0)
 *
 * NIST CSF 2.0: Protect (PR.PS-1, PR.PS-6)
 * NIST AI RMF: MANAGE (MG-2.2)
 *
 * ALL outbound HTTP calls in EverythingOS must use createHttpClient() from this
 * module. Direct axios imports are prohibited — enforced via ESLint rule below.
 *
 * ESLint rule to add to eslint.config.js:
 *   "no-restricted-imports": ["error", { "paths": ["axios"] }]
 *
 * Usage:
 *   import { createHttpClient, safeGet, safePost } from '../security/http-guard';
 *
 *   // For LLM provider calls:
 *   const client = createHttpClient({
 *     allowedHosts: ['api.anthropic.com', 'api.openai.com'],
 *     maxResponseBytes: 1_000_000,
 *   });
 *   const res = await client.get('/v1/messages');
 *
 *   // For plugin calls (Discord, Slack, etc.):
 *   const res = await safeGet('https://discord.com/api/v10/channels/123', {
 *     allowedHosts: ['discord.com'],
 *   });
 */

import axios, {
  AxiosInstance,
  AxiosRequestConfig,
  InternalAxiosRequestConfig,
  AxiosResponse,
} from 'axios';
import { AuditLogger } from './audit-log';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/** Default max response size: 10 MB */
const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

/** Default timeout: 30 seconds */
const DEFAULT_TIMEOUT_MS = 30_000;

/** Blocked URL schemes — CVE-2025-58754 mitigation */
const BLOCKED_SCHEMES = ['data:', 'file:', 'ftp:', 'javascript:', 'vbscript:'];

/** Blocked internal IP ranges — SSRF mitigation for CVE-2025-27152 */
const BLOCKED_IP_PATTERNS = [
  /^127\./,           // loopback
  /^10\./,            // RFC1918
  /^172\.(1[6-9]|2[0-9]|3[01])\./,  // RFC1918
  /^192\.168\./,      // RFC1918
  /^169\.254\./,      // link-local
  /^::1$/,            // IPv6 loopback
  /^fc00:/,           // IPv6 ULA
  /^fe80:/,           // IPv6 link-local
  /^0\.0\.0\.0$/,     // invalid
];

/** Hostnames always blocked regardless of allowlist */
const BLOCKED_HOSTNAMES = [
  'localhost',
  'metadata.google.internal',  // GCP metadata service
  '169.254.169.254',           // AWS/Azure IMDS
  '100.100.100.200',           // Alibaba Cloud metadata
];

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface HttpGuardOptions {
  /**
   * Allowlist of hostnames this client may connect to.
   * If provided, requests to any other host are blocked.
   * Example: ['api.anthropic.com', 'api.openai.com']
   */
  allowedHosts?: string[];

  /**
   * Maximum response body size in bytes. Requests exceeding this are aborted.
   * Fixes CVE-2025-58754 (unbounded memory from data: URIs).
   * Default: 10 MB
   */
  maxResponseBytes?: number;

  /** Request timeout in milliseconds. Default: 30s */
  timeoutMs?: number;

  /** Agent ID for audit logging. Defaults to 'http-guard' */
  agentId?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// URL Validation
// ─────────────────────────────────────────────────────────────────────────────

export class SSRFError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SSRFError';
  }
}

/**
 * Validates a URL against SSRF and scheme-injection risks.
 * Throws SSRFError if the URL is unsafe.
 */
export function validateUrl(url: string, allowedHosts?: string[]): URL {
  // Reject blocked schemes — CVE-2025-58754
  const urlLower = url.toLowerCase().trimStart();
  for (const scheme of BLOCKED_SCHEMES) {
    if (urlLower.startsWith(scheme)) {
      throw new SSRFError(`Blocked URL scheme: ${scheme} — CVE-2025-58754`);
    }
  }

  // Must be parseable as a URL
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new SSRFError(`Invalid URL: ${url}`);
  }

  // Only allow http/https
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new SSRFError(`Blocked protocol: ${parsed.protocol}`);
  }

  const hostname = parsed.hostname.toLowerCase();

  // Block always-blocked hostnames
  if (BLOCKED_HOSTNAMES.includes(hostname)) {
    throw new SSRFError(`Blocked hostname (SSRF): ${hostname}`);
  }

  // Block internal IP ranges — CVE-2025-27152
  for (const pattern of BLOCKED_IP_PATTERNS) {
    if (pattern.test(hostname)) {
      throw new SSRFError(`Blocked internal IP (SSRF): ${hostname}`);
    }
  }

  // Enforce allowlist if provided
  if (allowedHosts && allowedHosts.length > 0) {
    const hostAllowed = allowedHosts.some(
      (allowed) => hostname === allowed.toLowerCase() || hostname.endsWith(`.${allowed.toLowerCase()}`)
    );
    if (!hostAllowed) {
      throw new SSRFError(
        `Host "${hostname}" is not in the allowed hosts list: [${allowedHosts.join(', ')}]`
      );
    }
  }

  return parsed;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardened Axios Instance Factory
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Creates a hardened axios instance with SSRF protection and content limits.
 *
 * Fixes:
 *   - CVE-2025-27152: validates absolute URLs against SSRF patterns
 *   - CVE-2025-58754: enforces maxContentLength and maxBodyLength
 */
export function createHttpClient(options: HttpGuardOptions = {}): AxiosInstance {
  const {
    allowedHosts,
    maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    agentId = 'http-guard',
  } = options;

  const instance = axios.create({
    timeout: timeoutMs,
    // CVE-2025-58754 fix — enforce content size limits
    maxContentLength: maxResponseBytes,
    maxBodyLength: maxResponseBytes,
    // CVE-2025-27152 fix — disallow absolute URL override of baseURL
    // (axios 1.8.2+ respects this, older versions ignored it)
    allowAbsoluteUrls: false,
  });

  // Request interceptor — validate URL before every request
  instance.interceptors.request.use((config: InternalAxiosRequestConfig) => {
    const url = config.url ?? '';
    const baseURL = config.baseURL ?? '';
    const fullUrl = url.startsWith('http') ? url : `${baseURL}${url}`;

    try {
      validateUrl(fullUrl, allowedHosts);
    } catch (err) {
      const msg = err instanceof SSRFError ? err.message : String(err);
      AuditLogger.log({
        agentId,
        event: 'security.injection_detected',
        metadata: { type: 'ssrf_blocked', url: fullUrl, reason: msg },
      });
      throw err;
    }

    return config;
  });

  // Response interceptor — log large responses
  instance.interceptors.response.use((response: AxiosResponse) => {
    const contentLength = Number(response.headers['content-length'] ?? 0);
    if (contentLength > maxResponseBytes * 0.8) {
      AuditLogger.log({
        agentId,
        event: 'content_filter.flagged',
        metadata: { type: 'large_response', bytes: contentLength, limit: maxResponseBytes },
      });
    }
    return response;
  });

  return instance;
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience wrappers for one-off calls
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Safe GET — validates URL before making request.
 * Use for one-off calls where you don't need a persistent client.
 */
export async function safeGet<T = unknown>(
  url: string,
  options: HttpGuardOptions & AxiosRequestConfig = {},
): Promise<AxiosResponse<T>> {
  const { allowedHosts, maxResponseBytes, timeoutMs, agentId, ...axiosConfig } = options;
  const client = createHttpClient({ allowedHosts, maxResponseBytes, timeoutMs, agentId });
  return client.get<T>(url, axiosConfig);
}

/**
 * Safe POST — validates URL before making request.
 */
export async function safePost<T = unknown>(
  url: string,
  data?: unknown,
  options: HttpGuardOptions & AxiosRequestConfig = {},
): Promise<AxiosResponse<T>> {
  const { allowedHosts, maxResponseBytes, timeoutMs, agentId, ...axiosConfig } = options;
  const client = createHttpClient({ allowedHosts, maxResponseBytes, timeoutMs, agentId });
  return client.post<T>(url, data, axiosConfig);
}

// ─────────────────────────────────────────────────────────────────────────────
// Pre-configured clients for known EverythingOS integrations
// ─────────────────────────────────────────────────────────────────────────────

/** Hardened client for Anthropic API calls */
export const anthropicClient = createHttpClient({
  allowedHosts: ['api.anthropic.com'],
  maxResponseBytes: 2 * 1024 * 1024, // 2 MB — LLM responses should never exceed this
  agentId: 'llm-router:anthropic',
});

/** Hardened client for OpenAI API calls */
export const openaiClient = createHttpClient({
  allowedHosts: ['api.openai.com'],
  maxResponseBytes: 2 * 1024 * 1024,
  agentId: 'llm-router:openai',
});

/** Hardened client for Discord API calls */
export const discordClient = createHttpClient({
  allowedHosts: ['discord.com', 'discordapp.com', 'cdn.discordapp.com'],
  maxResponseBytes: 10 * 1024 * 1024,
  agentId: 'plugin:discord',
});

/** Hardened client for Slack API calls */
export const slackClient = createHttpClient({
  allowedHosts: ['slack.com', 'api.slack.com', 'hooks.slack.com'],
  maxResponseBytes: 10 * 1024 * 1024,
  agentId: 'plugin:slack',
});
