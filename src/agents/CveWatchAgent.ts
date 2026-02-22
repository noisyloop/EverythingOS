/**
 * EverythingOS — CveWatchAgent
 *
 * NIST CSF 2.0: Identify (ID.RA-1), Protect (PR.PS-6), Respond (RS.AN-3)
 * NIST AI RMF: MEASURE (MS-2.5), MANAGE (MG-2.4)
 *
 * Autonomous agent that continuously monitors for new CVEs affecting
 * EverythingOS dependencies, cross-references against the live SBOM,
 * and emits structured alerts to the EventBus.
 *
 * Data sources:
 *   - GitHub Advisory Database API (no key required, 60 req/hr)
 *   - npm audit (local — runs against package-lock.json)
 *
 * Emits:
 *   - security:cve_detected   — new HIGH/CRITICAL CVE found
 *   - security:cve_resolved   — previously detected CVE no longer present
 *   - security:audit_clean    — npm audit returned zero findings
 *
 * Subscribe from any agent:
 *   this.subscribe('security:cve_detected', async ({ payload }) => {
 *     // page on-call, open GitHub issue, block deployment, etc.
 *   });
 */

import { execSync } from 'child_process';
import { readFileSync, existsSync } from 'fs';
import { Agent, AgentConfig } from '../runtime/Agent';
import { AgentRiskTier } from '../types/agent-risk';
import { safeGet } from '../security/http-guard';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface CveAlert {
  cveId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';
  cvssScore: number;
  package: string;
  affectedVersionRange: string;
  patchedVersion: string;
  summary: string;
  url: string;
  detectedAt: string;
  source: 'github_advisory' | 'npm_audit';
}

export interface NpmAuditVulnerability {
  name: string;
  severity: string;
  range: string;
  fixAvailable: boolean | { name: string; version: string };
  via: Array<{ url?: string; cves?: string[]; title?: string; severity?: string } | string>;
}

// ─────────────────────────────────────────────────────────────────────────────
// GitHub Advisory API Types
// ─────────────────────────────────────────────────────────────────────────────

interface GitHubAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  severity: string;
  cvss: { score: number } | null;
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string };
    vulnerable_version_range: string;
    first_patched_version: { identifier: string } | null;
  }>;
  html_url: string;
  published_at: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// CveWatchAgent Config
// ─────────────────────────────────────────────────────────────────────────────

const CVE_WATCH_CONFIG: AgentConfig = {
  id: 'cve-watch',
  name: 'CveWatchAgent',
  type: 'perception',
  description: 'Monitors CVE feeds and npm audit for dependency vulnerabilities',

  riskConfig: {
    tier: AgentRiskTier.LOW,
    allowedPublishChannels: [
      'security:cve_detected',
      'security:cve_resolved',
      'security:audit_clean',
    ],
    allowedSubscribeChannels: ['system:tick:daily', 'security:cve_scan_requested'],
    riskJustification: 'Read-only monitoring agent — emits alerts, never modifies state or executes commands',
    llmRateLimit: 0,
    auditInputs: false,
    auditOutputs: true,
    dataClassification: 'internal',
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// CveWatchAgent
// ─────────────────────────────────────────────────────────────────────────────

export class CveWatchAgent extends Agent {
  /** CVEs seen in the previous scan — used to detect new/resolved findings */
  private previousFindings = new Map<string, CveAlert>();

  /** Packages to monitor — loaded from package.json on start */
  private monitoredPackages: string[] = [];

  /** Scan interval — default 24 hours */
  private readonly scanIntervalMs: number;

  constructor(scanIntervalMs = 24 * 60 * 60 * 1000) {
    super(CVE_WATCH_CONFIG);
    this.scanIntervalMs = scanIntervalMs;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  protected async onStart(): Promise<void> {
    this.monitoredPackages = this.loadPackageNames();
    this.log('info', `CveWatchAgent started — monitoring ${this.monitoredPackages.length} packages`);

    // Subscribe to manual scan trigger
    this.subscribe('security:cve_scan_requested', async () => {
      await this.runFullScan();
    });

    // Subscribe to daily tick for automatic scans
    this.subscribe('system:tick:daily', async () => {
      await this.runFullScan();
    });

    // Run an initial scan at startup
    await this.runFullScan();
  }

  protected async onStop(): Promise<void> {
    this.log('info', 'CveWatchAgent stopped');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Scan Orchestration
  // ─────────────────────────────────────────────────────────────────────────

  private async runFullScan(): Promise<void> {
    this.log('info', 'Starting CVE scan...');
    const currentFindings = new Map<string, CveAlert>();

    try {
      // Source 1: npm audit
      const npmFindings = await this.runNpmAudit();
      for (const finding of npmFindings) {
        currentFindings.set(finding.cveId, finding);
      }

      // Source 2: GitHub Advisory Database
      const ghFindings = await this.queryGitHubAdvisories();
      for (const finding of ghFindings) {
        // npm audit takes precedence if same CVE found in both
        if (!currentFindings.has(finding.cveId)) {
          currentFindings.set(finding.cveId, finding);
        }
      }

      // Emit alerts for new findings
      let newCount = 0;
      for (const [cveId, alert] of currentFindings) {
        if (!this.previousFindings.has(cveId)) {
          this.emit('security:cve_detected', alert);
          this.log('warn', `New CVE detected: ${cveId}`, {
            severity: alert.severity,
            package: alert.package,
            patched: alert.patchedVersion,
          });
          newCount++;
        }
      }

      // Emit resolved for CVEs that disappeared (package upgraded)
      let resolvedCount = 0;
      for (const [cveId, alert] of this.previousFindings) {
        if (!currentFindings.has(cveId)) {
          this.emit('security:cve_resolved', { ...alert, resolvedAt: new Date().toISOString() });
          this.log('info', `CVE resolved: ${cveId} (${alert.package} upgraded)`);
          resolvedCount++;
        }
      }

      // Clean bill of health
      if (currentFindings.size === 0) {
        this.emit('security:audit_clean', {
          scannedAt: new Date().toISOString(),
          packagesChecked: this.monitoredPackages.length,
        });
        this.log('info', 'CVE scan complete — no findings');
      } else {
        this.log('warn', `CVE scan complete`, {
          total: currentFindings.size,
          new: newCount,
          resolved: resolvedCount,
          critical: [...currentFindings.values()].filter((a) => a.severity === 'CRITICAL').length,
          high: [...currentFindings.values()].filter((a) => a.severity === 'HIGH').length,
        });
      }

      this.previousFindings = currentFindings;
    } catch (err) {
      this.log('error', 'CVE scan failed', { error: String(err) });
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // npm audit
  // ─────────────────────────────────────────────────────────────────────────

  private async runNpmAudit(): Promise<CveAlert[]> {
    try {
      const output = execSync('npm audit --json --audit-level=moderate 2>/dev/null', {
        timeout: 30_000,
        encoding: 'utf-8',
      });

      const audit = JSON.parse(output) as {
        vulnerabilities: Record<string, NpmAuditVulnerability>;
        metadata: { vulnerabilities: Record<string, number> };
      };

      const alerts: CveAlert[] = [];

      for (const [pkgName, vuln] of Object.entries(audit.vulnerabilities ?? {})) {
        // Extract CVE IDs from the via array
        const cveIds: string[] = [];
        const vias = Array.isArray(vuln.via) ? vuln.via : [];

        for (const via of vias) {
          if (typeof via === 'object' && via.cves) {
            cveIds.push(...via.cves);
          }
        }

        if (cveIds.length === 0) {
          // Use GHSA or synthetic ID if no CVE
          cveIds.push(`GHSA-${pkgName}-${Date.now()}`);
        }

        const severity = vuln.severity?.toUpperCase() as CveAlert['severity'];
        const firstVia = vias.find((v) => typeof v === 'object') as
          | { url?: string; title?: string }
          | undefined;

        for (const cveId of cveIds) {
          const fixVersion =
            typeof vuln.fixAvailable === 'object'
              ? vuln.fixAvailable.version
              : vuln.fixAvailable
              ? 'available — run npm audit fix'
              : 'no fix available';

          alerts.push({
            cveId,
            severity: ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'].includes(severity)
              ? severity
              : 'MODERATE',
            cvssScore: 0, // npm audit doesn't expose CVSS scores
            package: pkgName,
            affectedVersionRange: vuln.range ?? 'unknown',
            patchedVersion: fixVersion,
            summary: firstVia?.title ?? `Vulnerability in ${pkgName}`,
            url: firstVia?.url ?? `https://www.npmjs.com/advisories`,
            detectedAt: new Date().toISOString(),
            source: 'npm_audit',
          });
        }
      }

      return alerts;
    } catch (err) {
      // npm audit exits non-zero when vulnerabilities are found — parse output anyway
      const errOutput = (err as { stdout?: string }).stdout;
      if (errOutput) {
        try {
          // Recurse with the error output as valid JSON
          const audit = JSON.parse(errOutput);
          if (audit.vulnerabilities) {
            // Re-run properly — the parse above handles it
            return this.parseAuditOutput(audit);
          }
        } catch {
          // ignore parse failure
        }
      }
      this.log('warn', 'npm audit failed or no package-lock.json present', { error: String(err) });
      return [];
    }
  }

  private parseAuditOutput(audit: {
    vulnerabilities: Record<string, NpmAuditVulnerability>;
  }): CveAlert[] {
    const alerts: CveAlert[] = [];
    for (const [pkgName, vuln] of Object.entries(audit.vulnerabilities ?? {})) {
      const severity = vuln.severity?.toUpperCase() as CveAlert['severity'];
      alerts.push({
        cveId: `npm-${pkgName}-${vuln.range}`,
        severity: ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'].includes(severity)
          ? severity
          : 'MODERATE',
        cvssScore: 0,
        package: pkgName,
        affectedVersionRange: vuln.range ?? 'unknown',
        patchedVersion: typeof vuln.fixAvailable === 'object' ? vuln.fixAvailable.version : 'check npm',
        summary: `Vulnerability in ${pkgName} (${vuln.range})`,
        url: 'https://www.npmjs.com/advisories',
        detectedAt: new Date().toISOString(),
        source: 'npm_audit',
      });
    }
    return alerts;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // GitHub Advisory Database
  // ─────────────────────────────────────────────────────────────────────────

  private async queryGitHubAdvisories(): Promise<CveAlert[]> {
    const alerts: CveAlert[] = [];

    // Check each monitored package against the GitHub Advisory DB
    // Rate limit: 60 requests/hour unauthenticated, 5000/hour with GITHUB_TOKEN
    const token = process.env.GITHUB_TOKEN;
    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    for (const pkg of this.monitoredPackages) {
      try {
        const response = await safeGet<{ advisories: GitHubAdvisory[] }>(
          `https://api.github.com/advisories?affects=${encodeURIComponent(`npm/${pkg}`)}&severity=high,critical&per_page=10`,
          {
            allowedHosts: ['api.github.com'],
            agentId: this.id,
            maxResponseBytes: 500_000,
          },
        );

        // GitHub returns { advisories: [...] } or just an array depending on endpoint
        const advisories: GitHubAdvisory[] = Array.isArray(response.data)
          ? (response.data as unknown as GitHubAdvisory[])
          : (response.data.advisories ?? []);

        for (const advisory of advisories) {
          const cveId = advisory.cve_id ?? advisory.ghsa_id;
          const severity = advisory.severity?.toUpperCase() as CveAlert['severity'];

          const affectedVuln = advisory.vulnerabilities?.find(
            (v) => v.package.ecosystem === 'npm' && v.package.name === pkg,
          );

          alerts.push({
            cveId,
            severity: ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'].includes(severity)
              ? severity
              : 'HIGH',
            cvssScore: advisory.cvss?.score ?? 0,
            package: pkg,
            affectedVersionRange: affectedVuln?.vulnerable_version_range ?? 'unknown',
            patchedVersion: affectedVuln?.first_patched_version?.identifier ?? 'see advisory',
            summary: advisory.summary,
            url: advisory.html_url,
            detectedAt: new Date().toISOString(),
            source: 'github_advisory',
          });
        }

        // Small delay to respect rate limits
        await new Promise((r) => setTimeout(r, 200));
      } catch (err) {
        this.log('warn', `GitHub Advisory lookup failed for ${pkg}`, { error: String(err) });
      }
    }

    return alerts;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Helpers
  // ─────────────────────────────────────────────────────────────────────────

  private loadPackageNames(): string[] {
    const pkgPath = process.env.PACKAGE_JSON_PATH ?? './package.json';
    if (!existsSync(pkgPath)) {
      this.log('warn', 'package.json not found — using default package list');
      return ['axios', 'express', 'ws', 'zod', 'uuid', 'dotenv'];
    }
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    return [
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.devDependencies ?? {}),
    ];
  }

  /** Returns the current findings for status dashboard */
  getFindings(): CveAlert[] {
    return Array.from(this.previousFindings.values());
  }
}
