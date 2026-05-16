/**
 * EverythingOS — HTTP Guard
 *
 * Fixes:
 *   CVE-2025-27152 — axios SSRF via absolute URL bypass (axios < 1.8.2)
 *   CVE-2025-58754 — axios DoS via unbounded data: URI memory allocation (axios < 1.11.0)
 *   DNS rebinding — hostname validated at request time AND after DNS resolution
 *   Redirect SSRF  — redirects disabled; a Location header cannot route to an internal IP
 *
 * NIST CSF 2.0: Protect (PR.PS-1, PR.PS-6)
 * NIST AI RMF: MANAGE (MG-2.2)
 *
 * ALL outbound HTTP calls in EverythingOS must use createHttpClient() from this
 * module. Direct axios imports are prohibited — enforced via ESLint rule below.
 *
 * ESLint rule to add to eslint.config.js:
 *   "no-restricted-imports": ["error", { "paths": ["axios"] }]
 */

import axios, {
  AxiosInstance,
  AxiosRequestConfig,
  InternalAxiosRequestConfig,
  AxiosResponse,
} from 'axios';
import { resolve4, resolve6 } from 'dns/promises';
import { AuditLogger } from './audit-log';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;

const BLOCKED_SCHEMES = ['data:', 'file:', 'ftp:', 'javascript:', 'vbscript:'];

const BLOCKED_IP_PATTERNS = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i,
  /^0\.0\.0\.0$/,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,  // RFC 6598 shared address space
];

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  '169.254.169.254',
  '100.100.100.200',
  'metadata.azure.internal',
]);

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface HttpGuardOptions {
  allowedHosts?: string[];
  maxResponseBytes?: number;
  timeoutMs?: number;
  agentId?: string;
}

export class SSRFError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SSRFError';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// IP validation helper (used for both static hostname checks and DNS results)
// ─────────────────────────────────────────────────────────────────────────────

function assertIpNotBlocked(ip: string): void {
  const normalized = ip.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(normalized)) {
    throw new SSRFError(`Blocked hostname/IP (SSRF): ${ip}`);
  }
  for (const pattern of BLOCKED_IP_PATTERNS) {
    if (pattern.test(normalized)) {
      throw new SSRFError(`Blocked internal IP (SSRF): ${ip}`);
    }
  }
}

function looksLikeIp(hostname: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ||
         (/^[0-9a-fA-F:]+$/.test(hostname) && hostname.includes(':'));
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS rebinding protection
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resolve the hostname and validate every returned IP is not in a blocked range.
 * Prevents DNS rebinding: attacker advertises an allowed hostname that later
 * resolves to an internal IP at TCP connect time.
 *
 * Skipped for hostnames that are already IP literals (already validated statically).
 */
async function resolveAndValidateHost(hostname: string): Promise<void> {
  if (looksLikeIp(hostname)) return; // already validated statically by validateUrl

  let ips4: string[] = [];
  let ips6: string[] = [];

  try {
    ips4 = await resolve4(hostname);
  } catch { /* NXDOMAIN or timeout — let the request fail naturally */ }

  try {
    ips6 = await resolve6(hostname);
  } catch { /* same */ }

  // If we got no IPs at all, the request will fail at connect — that's fine.
  // We only block if we positively identify a resolved IP as internal.
  for (const ip of [...ips4, ...ips6]) {
    assertIpNotBlocked(ip);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// URL validation (static — scheme, hostname, allowlist)
// ─────────────────────────────────────────────────────────────────────────────

export function validateUrl(url: string, allowedHosts?: string[]): URL {
  const urlLower = url.toLowerCase().trimStart();
  for (const scheme of BLOCKED_SCHEMES) {
    if (urlLower.startsWith(scheme)) {
      throw new SSRFError(`Blocked URL scheme: ${scheme} — CVE-2025-58754`);
    }
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new SSRFError(`Invalid URL: ${url}`);
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new SSRFError(`Blocked protocol: ${parsed.protocol}`);
  }

  const hostname = parsed.hostname.toLowerCase();

  if (BLOCKED_HOSTNAMES.has(hostname)) {
    throw new SSRFError(`Blocked hostname (SSRF): ${hostname}`);
  }

  // Static IP range check (catches IP literals in the URL)
  assertIpNotBlocked(hostname);

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
// Hardened axios instance factory
// ─────────────────────────────────────────────────────────────────────────────

export function createHttpClient(options: HttpGuardOptions = {}): AxiosInstance {
  const {
    allowedHosts,
    maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    agentId = 'http-guard',
  } = options;

  const instance = axios.create({
    timeout: timeoutMs,
    maxContentLength: maxResponseBytes,   // CVE-2025-58754
    maxBodyLength: maxResponseBytes,       // CVE-2025-58754
    allowAbsoluteUrls: false,             // CVE-2025-27152
    maxRedirects: 0,                      // Disable redirect following to prevent redirect-based SSRF
  });

  // Async request interceptor — static URL validation + DNS rebinding check
  instance.interceptors.request.use(async (config: InternalAxiosRequestConfig) => {
    const url = config.url ?? '';
    const baseURL = config.baseURL ?? '';
    const fullUrl = url.startsWith('http') ? url : `${baseURL}${url}`;

    let parsed: URL;
    try {
      parsed = validateUrl(fullUrl, allowedHosts);
    } catch (err) {
      const msg = err instanceof SSRFError ? err.message : String(err);
      AuditLogger.log({
        agentId,
        event: 'security.injection_detected',
        metadata: { type: 'ssrf_blocked', url: fullUrl, reason: msg },
      });
      throw err;
    }

    // DNS rebinding check — resolves the hostname and validates all returned IPs
    try {
      await resolveAndValidateHost(parsed.hostname);
    } catch (err) {
      const msg = err instanceof SSRFError ? err.message : String(err);
      AuditLogger.log({
        agentId,
        event: 'security.injection_detected',
        metadata: { type: 'dns_rebind_blocked', hostname: parsed.hostname, reason: msg },
      });
      throw err;
    }

    return config;
  });

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
// Convenience wrappers
// ─────────────────────────────────────────────────────────────────────────────

export async function safeGet<T = unknown>(
  url: string,
  options: HttpGuardOptions & AxiosRequestConfig = {},
): Promise<AxiosResponse<T>> {
  const { allowedHosts, maxResponseBytes, timeoutMs, agentId, ...axiosConfig } = options;
  const client = createHttpClient({ allowedHosts, maxResponseBytes, timeoutMs, agentId });
  return client.get<T>(url, axiosConfig);
}

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
// Pre-configured clients for known integrations
// ─────────────────────────────────────────────────────────────────────────────

export const anthropicClient = createHttpClient({
  allowedHosts: ['api.anthropic.com'],
  maxResponseBytes: 2 * 1024 * 1024,
  agentId: 'llm-router:anthropic',
});

export const openaiClient = createHttpClient({
  allowedHosts: ['api.openai.com'],
  maxResponseBytes: 2 * 1024 * 1024,
  agentId: 'llm-router:openai',
});

export const discordClient = createHttpClient({
  allowedHosts: ['discord.com', 'discordapp.com', 'cdn.discordapp.com'],
  maxResponseBytes: 10 * 1024 * 1024,
  agentId: 'plugin:discord',
});

export const slackClient = createHttpClient({
  allowedHosts: ['slack.com', 'api.slack.com', 'hooks.slack.com'],
  maxResponseBytes: 10 * 1024 * 1024,
  agentId: 'plugin:slack',
});
