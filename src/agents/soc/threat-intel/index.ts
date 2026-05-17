// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Threat Intel
// Fetches threat intelligence feeds via http-guard, maintains an IOC database,
// and correlates current activity against known indicators of compromise.
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent, AgentConfig } from '../../../runtime/Agent';
import { AgentRiskTier } from '../../../types/agent-risk';
import { AgentManifest, validateManifest } from '../../../types/agent-manifest';
import { createHttpClient } from '../../../security/http-guard';

export const MANIFEST: AgentManifest = validateManifest({
  id: 'threat-intel',
  name: 'Threat Intel',
  version: '1.0.0',
  category: 'soc',
  description: 'Fetches threat intelligence feeds, maintains an IOC database, and correlates current activity against known threats.',
  capabilities: [
    'network:http', 'eventbus:subscribe', 'eventbus:publish',
    'memory:read', 'memory:write', 'ledger:write',
  ],
  trustLevel: AgentRiskTier.HIGH,
  tags: ['soc', 'threat-intel', 'ioc', 'security', 'feeds'],
  author: 'EverythingOS',
});

export type IOCType = 'ip' | 'domain' | 'hash' | 'url' | 'email';

export interface IOC {
  value: string;
  type: IOCType;
  confidence: number; // 0–1
  source: string;
  addedAt: number;
  expiresAt?: number;
}

export interface ThreatFeed {
  url: string;
  name: string;
  refreshIntervalMs: number;
  lastFetched?: number;
}

function guessIOCType(value: string): IOCType | null {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return 'ip';
  if (/^[a-f0-9]{32,64}$/i.test(value)) return 'hash';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value) && !value.includes('/')) return 'domain';
  if (/^https?:\/\//i.test(value)) return 'url';
  if (/@/.test(value)) return 'email';
  return null;
}

export default class ThreatIntelAgent extends Agent {
  private iocs: Map<string, IOC> = new Map(); // normalized value -> IOC
  private feeds: ThreatFeed[];
  private readonly http = createHttpClient();
  private correlationHits = 0;

  constructor(feeds?: ThreatFeed[], config?: Partial<AgentConfig>) {
    super({
      id: MANIFEST.id,
      name: MANIFEST.name,
      type: 'perception',
      description: MANIFEST.description,
      tickRate: 300_000, // refresh feeds every 5 minutes
      riskConfig: {
        tier: AgentRiskTier.HIGH,
        riskJustification: 'Makes outbound HTTP to threat feeds; HIGH tier for full audit trail on IOC matches',
        requiresApproval: false,
        genAIRisks: {
          informationIntegrityRisk: true,
          promptInjectionRisk: false,
          piiRisk: false,
          hallucinationRisk: false,
          harmfulContentRisk: false,
          physicalSafetyRisk: false,
          dataPrivacyRisk: false,
        },
        allowedPublishChannels: ['intel:ioc:match', 'intel:ioc:added', 'intel:feed:updated', 'intel:stats'],
        allowedSubscribeChannels: ['intel:correlate', 'intel:feed:add', 'intel:ioc:add', 'intel:ioc:bundle'],
        auditInputs: true,
        auditOutputs: true,
      },
      ...config,
    });
    this.feeds = feeds ?? [];
  }

  protected async onStart(): Promise<void> {
    this.subscribe<{ value: string; context?: string }>('intel:correlate', (event) => {
      this.correlate(event.payload.value, event.payload.context);
    });

    this.subscribe<ThreatFeed>('intel:feed:add', (event) => {
      this.feeds.push(event.payload);
      this.log('info', `Threat feed added: ${event.payload.name}`);
    });

    this.subscribe<IOC>('intel:ioc:add', (event) => {
      this.addIOC(event.payload);
    });

    // Receives verified IOC bundles from GlasswallyAgent — pre-HMAC-verified,
    // batched to avoid per-IOC EventBus rate limits on large cluster bundles
    this.subscribe<{
      cluster_id: string;
      ips: string[];
      subnets: string[];
      tls_fingerprints: string[];
      confidence: number;
      source: string;
      timestamp: string;
    }>('intel:ioc:bundle', (event) => {
      const { ips, subnets, tls_fingerprints, confidence, source } = event.payload;
      let added = 0;
      for (const ip of ips) {
        this.addIOC({ value: ip, type: 'ip', confidence, source, addedAt: Date.now() });
        added++;
      }
      for (const subnet of subnets) {
        this.addIOC({ value: subnet, type: 'ip', confidence, source, addedAt: Date.now() });
        added++;
      }
      for (const fp of tls_fingerprints) {
        this.addIOC({ value: fp, type: 'hash', confidence, source, addedAt: Date.now() });
        added++;
      }
      if (added > 0) {
        this.log('info', `IOC bundle ingested from ${source}: +${added} IOCs`);
      }
    });

    await this.refreshFeeds();
    this.log('info', `Threat intel started — ${this.iocs.size} IOCs from ${this.feeds.length} feeds`);
  }

  protected async onStop(): Promise<void> {
    this.log('info', `Threat intel stopped — ${this.correlationHits} correlations hit`);
  }

  protected async onTick(): Promise<void> {
    await this.refreshFeeds();
    this.emit('intel:stats', {
      iocCount: this.iocs.size,
      feedCount: this.feeds.length,
      correlationHits: this.correlationHits,
    });
  }

  addIOC(ioc: IOC): void {
    this.iocs.set(ioc.value.toLowerCase().trim(), ioc);
    this.emit('intel:ioc:added', { value: ioc.value, type: ioc.type, source: ioc.source });
  }

  correlate(value: string, context?: string): boolean {
    const normalized = value.toLowerCase().trim();
    const ioc = this.iocs.get(normalized);
    if (!ioc) return false;

    if (ioc.expiresAt && Date.now() > ioc.expiresAt) {
      this.iocs.delete(normalized);
      return false;
    }

    this.correlationHits++;
    this.act('intel:ioc:match', {
      value,
      ioc,
      context,
      matchedAt: new Date().toISOString(),
    }, { reason: `IOC match: ${ioc.type} "${value}" from feed "${ioc.source}"` });

    this.log('warn', `IOC match: [${ioc.type}] ${value}`, {
      source: ioc.source,
      confidence: ioc.confidence,
    });
    return true;
  }

  private async refreshFeeds(): Promise<void> {
    const now = Date.now();
    for (const feed of this.feeds) {
      if (feed.lastFetched && now - feed.lastFetched < feed.refreshIntervalMs) continue;
      await this.fetchFeed(feed);
    }
  }

  private async fetchFeed(feed: ThreatFeed): Promise<void> {
    try {
      const resp = await this.http.get<unknown>(feed.url, { responseType: 'text' });
      const text = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);
      let added = 0;

      for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
        const type = guessIOCType(trimmed);
        if (!type) continue;
        this.iocs.set(trimmed.toLowerCase(), {
          value: trimmed, type, confidence: 0.7,
          source: feed.name, addedAt: Date.now(),
        });
        added++;
      }

      feed.lastFetched = Date.now();
      this.emit('intel:feed:updated', { feed: feed.name, added, total: this.iocs.size });
      this.log('info', `Feed refreshed: ${feed.name} (+${added} IOCs)`);
    } catch (err) {
      this.log('warn', `Feed fetch failed: ${feed.name}`, { error: String(err) });
    }
  }
}
