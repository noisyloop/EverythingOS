// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - API Server
// REST API for external control
// ═══════════════════════════════════════════════════════════════════════════════

import { eventBus } from '../core/event-bus/EventBus';
import { workflowRegistry } from '../core/workflow/WorkflowRegistry';
import { agentRegistry } from '../core/registry/AgentRegistry';
import { pluginRegistry } from '../core/registry/PluginRegistry';
import { worldState } from '../core/state/WorldState';
import { decisionExplainability } from '../services/explainability';
import { pluginTrustManager, TrustLevel } from '../services/trust';

// Security initialization
import { AuditLogger } from '../security/audit-log';
import { DecisionLedger } from '../security/decision-ledger';
import { QuarantineManager } from '../security/quarantine';

// Simple HTTP server without Express dependency for now
import { createServer, IncomingMessage, ServerResponse } from 'http';

const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────────────────────────────────────
// Security Bootstrap
// Must run before any agents start or requests are handled.
// ─────────────────────────────────────────────────────────────────────────────

function initializeSecurity(): void {
  // 1. Audit log — tamper-evident, hash-chained event trail
  AuditLogger.initialize();

  // 2. Decision ledger — provenance record for every LLM call
  DecisionLedger.initialize();

  // 3. Quarantine manager — surgical per-agent isolation
  //    Wired to registry so quarantine() can stop agents without circular deps
  QuarantineManager.initialize({
    stopAgent: async (id: string) => {
      await agentRegistry.stopAgent(id);
    },
    getAgentState: (id: string) => {
      const agent = agentRegistry.get(id);
      return agent ? { id: agent.id, status: agent.status, type: agent.config?.type } : {};
    },
    getAgentSubscriptions: (_id: string) => {
      // EventBus subscription list — return empty array if not exposed
      // Replace with eventBus.getSubscriptions(id) if your EventBus supports it
      return [];
    },
  });

  AuditLogger.log({
    agentId: 'system',
    event: 'agent.started',
    metadata: { component: 'security-bootstrap', version: process.env.EOS_POLICY_VERSION || '1.0.0' },
  });

  console.log('🔒 Security subsystems initialized (audit-log, decision-ledger, quarantine)');
}

// ─────────────────────────────────────────────────────────────────────────────
// Request Handling
// ─────────────────────────────────────────────────────────────────────────────

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url || '/', `http://localhost:${PORT}`);
  const path = url.pathname;
  const method = req.method || 'GET';

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    const body = await parseBody(req);
    const result = await route(method, path, body, url.searchParams);
    
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(result.status);
    res.end(JSON.stringify(result.data));
  } catch (error) {
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(500);
    res.end(JSON.stringify({ error: String(error) }));
  }
}

async function parseBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        resolve({});
      }
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Routing
// ─────────────────────────────────────────────────────────────────────────────

async function route(
  method: string,
  path: string,
  body: unknown,
  params: URLSearchParams
): Promise<{ status: number; data: unknown }> {
  
  // Health check
  if (path === '/health' || path === '/api/health') {
    return { status: 200, data: { status: 'ok', timestamp: Date.now() } };
  }

  // Workflows
  if (path === '/api/workflows') {
    if (method === 'GET') {
      return { status: 200, data: workflowRegistry.list() };
    }
    if (method === 'POST') {
      workflowRegistry.register(body as Parameters<typeof workflowRegistry.register>[0]);
      return { status: 201, data: { success: true } };
    }
  }

  if (path.startsWith('/api/workflows/')) {
    const id = path.split('/')[3];
    
    if (method === 'GET') {
      const workflow = workflowRegistry.get(id);
      return workflow ? { status: 200, data: workflow } : { status: 404, data: { error: 'Not found' } };
    }
    
    if (method === 'POST' && path.endsWith('/execute')) {
      const workflowId = path.split('/')[3];
      const execution = await workflowRegistry.execute(workflowId, body as Record<string, unknown>);
      return { status: 200, data: execution };
    }
    
    if (method === 'DELETE') {
      const deleted = workflowRegistry.unregister(id);
      return { status: deleted ? 200 : 404, data: { success: deleted } };
    }
  }

  // Agents
  if (path === '/api/agents') {
    return { status: 200, data: agentRegistry.getAll().map(a => ({ id: a.id, config: a.config, status: a.status })) };
  }

  if (path.startsWith('/api/agents/')) {
    const id = path.split('/')[3];
    const action = path.split('/')[4];
    
    if (action === 'start') {
      await agentRegistry.startAgent(id);
      return { status: 200, data: { success: true } };
    }
    
    if (action === 'stop') {
      await agentRegistry.stopAgent(id);
      return { status: 200, data: { success: true } };
    }
  }

  // Plugins
  if (path === '/api/plugins') {
    return { status: 200, data: pluginRegistry.getAll().map(p => ({ id: p.id, name: p.name, version: p.version })) };
  }

  if (path === '/api/plugins/actions') {
    return { status: 200, data: pluginRegistry.getAllActions() };
  }

  if (path.startsWith('/api/plugins/') && path.includes('/execute')) {
    const parts = path.split('/');
    const pluginId = parts[3];
    const actionName = parts[5];
    const result = await pluginRegistry.execute(pluginId, actionName, body);
    return { status: 200, data: result };
  }

  // Events
  if (path === '/api/events' && method === 'POST') {
    const { type, payload } = body as { type: string; payload: unknown };
    eventBus.emit(type, payload);
    return { status: 200, data: { success: true } };
  }

  if (path === '/api/events/history') {
    const limit = parseInt(params.get('limit') || '100');
    return { status: 200, data: eventBus.getHistory({ limit }) };
  }

  // Approvals
  if (path === '/api/approvals' && method === 'GET') {
    const pending = agentRegistry.get('approval-gate');
    if (pending && 'getPending' in pending) {
      return { status: 200, data: (pending as { getPending: () => unknown[] }).getPending() };
    }
    return { status: 200, data: [] };
  }

  if (path.startsWith('/api/approvals/') && path.endsWith('/approve') && method === 'POST') {
    const approvalId = path.split('/')[3];
    const { approvedBy, reason } = body as { approvedBy?: string; reason?: string };
    
    eventBus.emit('approval:decision', {
      approvalId,
      approved: true,
      approvedBy: approvedBy || 'api',
      reason,
      timestamp: Date.now(),
    });
    
    return { status: 200, data: { success: true, approvalId, action: 'approved' } };
  }

  if (path.startsWith('/api/approvals/') && path.endsWith('/deny') && method === 'POST') {
    const approvalId = path.split('/')[3];
    const { deniedBy, reason } = body as { deniedBy?: string; reason?: string };
    
    eventBus.emit('approval:decision', {
      approvalId,
      approved: false,
      approvedBy: deniedBy || 'api',
      reason: reason || 'Denied via API',
      timestamp: Date.now(),
    });
    
    return { status: 200, data: { success: true, approvalId, action: 'denied' } };
  }

  // Decisions (Explainability)
  if (path === '/api/decisions' && method === 'GET') {
    const agentId = params.get('agentId') ?? undefined;
    const status = params.get('status') as 'pending' | 'completed' | 'failed' | undefined;
    const limit = parseInt(params.get('limit') || '50');
    
    const records = decisionExplainability.query({ agentId, status, limit });
    return { status: 200, data: records };
  }

  if (path === '/api/decisions/stats' && method === 'GET') {
    return { status: 200, data: decisionExplainability.stats() };
  }

  if (path.startsWith('/api/decisions/') && method === 'GET') {
    const id = path.split('/')[3];
    
    if (path.endsWith('/explain')) {
      const decisionId = path.split('/')[3];
      const explanation = decisionExplainability.explain(decisionId);
      return explanation 
        ? { status: 200, data: { explanation } }
        : { status: 404, data: { error: 'Decision not found' } };
    }
    
    const record = decisionExplainability.get(id);
    return record 
      ? { status: 200, data: record }
      : { status: 404, data: { error: 'Decision not found' } };
  }

  // Trust Management
  if (path === '/api/trust' && method === 'GET') {
    return { status: 200, data: pluginTrustManager.listConfigs() };
  }

  if (path === '/api/trust/stats' && method === 'GET') {
    return { status: 200, data: pluginTrustManager.stats() };
  }

  if (path === '/api/trust/violations' && method === 'GET') {
    const pluginId = params.get('pluginId') ?? undefined;
    const limit = parseInt(params.get('limit') || '100');
    return { status: 200, data: pluginTrustManager.getViolations({ pluginId, limit }) };
  }

  if (path.startsWith('/api/trust/') && method === 'GET') {
    const pluginId = path.split('/')[3];
    const config = pluginTrustManager.getTrustConfig(pluginId);
    return config 
      ? { status: 200, data: config }
      : { status: 404, data: { error: 'Plugin trust config not found' } };
  }

  if (path.startsWith('/api/trust/') && path.endsWith('/level') && method === 'POST') {
    const pluginId = path.split('/')[3];
    const { level, approvedBy } = body as { level: TrustLevel; approvedBy?: string };
    
    if (!['trusted', 'restricted', 'sandboxed'].includes(level)) {
      return { status: 400, data: { error: 'Invalid trust level' } };
    }
    
    pluginTrustManager.setTrustLevel(pluginId, level, { approvedBy: approvedBy || 'api' });
    return { status: 200, data: { success: true, pluginId, level } };
  }

  if (path.startsWith('/api/trust/') && path.endsWith('/grant') && method === 'POST') {
    const pluginId = path.split('/')[3];
    const { permission, grantedBy } = body as { permission: string; grantedBy?: string };
    
    pluginTrustManager.grantPermission(pluginId, permission as any, { grantedBy: grantedBy || 'api' });
    return { status: 200, data: { success: true, pluginId, permission } };
  }

  if (path.startsWith('/api/trust/') && path.endsWith('/revoke') && method === 'POST') {
    const pluginId = path.split('/')[3];
    const { permission } = body as { permission: string };
    
    const revoked = pluginTrustManager.revokePermission(pluginId, permission as any);
    return { status: 200, data: { success: revoked, pluginId, permission } };
  }

  // State
  if (path === '/api/state') {
    return { status: 200, data: worldState.export() };
  }

  // 404
  return { status: 404, data: { error: 'Not found' } };
}

// ─────────────────────────────────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────────────────────────────────

export function startServer(port = PORT): void {
  // Security must initialize before the server accepts any connections
  initializeSecurity();

  const server = createServer(handleRequest);
  
  server.listen(port, () => {
    console.log(`🚀 EverythingOS API running on http://localhost:${port}`);
    console.log('');
    console.log('Endpoints:');
    console.log('  GET  /health                      - Health check');
    console.log('  GET  /api/workflows               - List workflows');
    console.log('  POST /api/workflows               - Create workflow');
    console.log('  POST /api/workflows/:id/execute   - Execute workflow');
    console.log('  GET  /api/agents                  - List agents');
    console.log('  POST /api/agents/:id/start        - Start agent');
    console.log('  POST /api/agents/:id/stop         - Stop agent');
    console.log('  GET  /api/plugins                 - List plugins');
    console.log('  POST /api/events                  - Emit event');
    console.log('  GET  /api/state                   - Get world state');
    console.log('  GET  /api/approvals               - List pending approvals');
    console.log('  POST /api/approvals/:id/approve   - Approve request');
    console.log('  POST /api/approvals/:id/deny      - Deny request');
    console.log('  GET  /api/decisions               - List decisions');
    console.log('  GET  /api/decisions/stats         - Decision statistics');
    console.log('  GET  /api/decisions/:id           - Get decision record');
    console.log('  GET  /api/decisions/:id/explain   - Explain decision');
    console.log('  GET  /api/trust                   - List trust configs');
    console.log('  GET  /api/trust/stats             - Trust statistics');
    console.log('  GET  /api/trust/:id               - Get plugin trust config');
    console.log('  POST /api/trust/:id/level         - Set trust level');
    console.log('  POST /api/trust/:id/grant         - Grant permission');
    console.log('  POST /api/trust/:id/revoke        - Revoke permission');
  });

  eventBus.emit('api:started', { port });
}

// Start if run directly
if (require.main === module) {
  startServer();
}
