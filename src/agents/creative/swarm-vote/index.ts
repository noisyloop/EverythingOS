// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Swarm Vote
// Coordinates N-instance consensus voting across agents.
// A session opens with a question; voters cast responses within a TTL;
// the session resolves by majority when quorum is reached or on timeout.
// ═══════════════════════════════════════════════════════════════════════════════

import { Agent, AgentConfig } from '../../../runtime/Agent';
import { AgentRiskTier } from '../../../types/agent-risk';
import { AgentManifest, validateManifest } from '../../../types/agent-manifest';

export const MANIFEST: AgentManifest = validateManifest({
  id: 'swarm-vote',
  name: 'Swarm Vote',
  version: '1.0.0',
  category: 'creative',
  description: 'Coordinates N-instance consensus voting across agent responses, resolving disagreement via majority vote when quorum is reached or TTL expires.',
  capabilities: ['eventbus:subscribe', 'eventbus:publish', 'agents:query'],
  trustLevel: AgentRiskTier.MEDIUM,
  tags: ['creative', 'swarm', 'consensus', 'voting', 'coordination'],
  author: 'EverythingOS',
});

interface VoteSession {
  id: string;
  question: string;
  votes: Map<string, string>; // voterId -> vote
  quorum: number;
  createdAt: number;
  ttlMs: number;
  resolved: boolean;
}

interface TallyResult {
  winner: string;
  counts: Record<string, number>;
  consensusRatio: number;
}

function tally(votes: string[]): TallyResult {
  const counts: Record<string, number> = {};
  for (const v of votes) counts[v] = (counts[v] ?? 0) + 1;
  const [winner, winCount] = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
  return { winner, counts, consensusRatio: winCount / votes.length };
}

export default class SwarmVoteAgent extends Agent {
  private sessions: Map<string, VoteSession> = new Map();
  private sessionCounter = 0;

  constructor(config?: Partial<AgentConfig>) {
    super({
      id: MANIFEST.id,
      name: MANIFEST.name,
      type: 'orchestration',
      description: MANIFEST.description,
      tickRate: 5_000, // check for expired sessions every 5 seconds
      riskConfig: {
        tier: AgentRiskTier.MEDIUM,
        riskJustification: 'Consensus arbitration — no external calls, only aggregates votes from other agents',
        allowedPublishChannels: ['swarm:vote:created', 'swarm:vote:result', 'swarm:vote:expired'],
        allowedSubscribeChannels: ['swarm:vote:open', 'swarm:vote:cast'],
      },
      ...config,
    });
  }

  protected async onStart(): Promise<void> {
    this.subscribe<{ question: string; quorum?: number; ttlMs?: number }>('swarm:vote:open', (event) => {
      const id = this.openSession(
        event.payload.question,
        event.payload.quorum ?? 3,
        event.payload.ttlMs ?? 30_000,
      );
      this.emit('swarm:vote:created', { sessionId: id, question: event.payload.question });
    });

    this.subscribe<{ sessionId: string; voterId: string; vote: string }>('swarm:vote:cast', (event) => {
      this.castVote(event.payload.sessionId, event.payload.voterId, event.payload.vote);
    });

    this.log('info', 'Swarm vote coordinator started');
  }

  protected async onStop(): Promise<void> {
    this.sessions.clear();
    this.log('info', 'Swarm vote coordinator stopped');
  }

  protected async onTick(): Promise<void> {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (!session.resolved && now > session.createdAt + session.ttlMs) {
        this.resolveSession(session, 'timeout');
        this.sessions.delete(id);
      }
    }
  }

  openSession(question: string, quorum: number, ttlMs: number): string {
    const id = `vote_${++this.sessionCounter}_${Date.now()}`;
    this.sessions.set(id, {
      id, question,
      votes: new Map(),
      quorum, createdAt: Date.now(), ttlMs,
      resolved: false,
    });
    return id;
  }

  castVote(sessionId: string, voterId: string, vote: string): void {
    const session = this.sessions.get(sessionId);
    if (!session || session.resolved) return;

    session.votes.set(voterId, vote);

    if (session.votes.size >= session.quorum) {
      this.resolveSession(session, 'quorum');
      this.sessions.delete(sessionId);
    }
  }

  private resolveSession(session: VoteSession, reason: string): void {
    session.resolved = true;
    const votes = Array.from(session.votes.values());

    if (votes.length === 0) {
      this.emit('swarm:vote:expired', { sessionId: session.id, question: session.question, reason });
      return;
    }

    const { winner, counts, consensusRatio } = tally(votes);
    this.emit('swarm:vote:result', {
      sessionId: session.id,
      question: session.question,
      winner,
      counts,
      consensusRatio,
      totalVotes: votes.length,
      reason,
    });

    this.log('info', `Vote resolved: "${winner}" (${Math.round(consensusRatio * 100)}% consensus)`, {
      sessionId: session.id,
      reason,
    });
  }
}
