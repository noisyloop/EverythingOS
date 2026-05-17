// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Creative Agents
// ═══════════════════════════════════════════════════════════════════════════════

export { default as EchoChamberAgent, MANIFEST as ECHO_CHAMBER_MANIFEST } from './echo-chamber/index';
export { default as HaikuLoggerAgent, MANIFEST as HAIKU_LOGGER_MANIFEST } from './haiku-logger/index';
export { default as SignalNoiseAgent, MANIFEST as SIGNAL_NOISE_MANIFEST } from './signal-noise/index';
export { default as MemoryPalaceAgent, MANIFEST as MEMORY_PALACE_MANIFEST } from './memory-palace/index';
export { default as SwarmVoteAgent, MANIFEST as SWARM_VOTE_MANIFEST } from './swarm-vote/index';

export type { Memory } from './memory-palace/index';
export type { SignalRule } from './signal-noise/index';
