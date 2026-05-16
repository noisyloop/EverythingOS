// ═══════════════════════════════════════════════════════════════════════════════
// EVERYTHINGOS - Event Bus
// Central nervous system for all agent communication
// ═══════════════════════════════════════════════════════════════════════════════

import { PriorityQueue } from './PriorityQueue';
import { DeadLetterQueue } from './DeadLetterQueue';

export type EventPriority = 'critical' | 'high' | 'normal' | 'low';

export interface Event<T = unknown> {
  id: string;
  type: string;
  payload: T;
  source: string;
  target?: string;
  priority: EventPriority;
  timestamp: number;
  correlationId?: string;
  replyTo?: string;
  metadata?: Record<string, unknown>;
}

export type EventHandler<T = unknown> = (event: Event<T>) => Promise<void> | void;

export interface Subscription {
  id: string;
  pattern: string;
  handler: EventHandler;
  once: boolean;
}

// Per-source publish rate limit — prevents a compromised or runaway agent from
// flooding the bus and starving other agents.
const PUBLISH_RATE_LIMIT   = 200;        // max publishes per window
const PUBLISH_RATE_WINDOW  = 60_000;     // 60-second sliding window

interface PublishRateEntry { count: number; windowStart: number }
const publishRates = new Map<string, PublishRateEntry>();

function checkPublishRateLimit(source: string): boolean {
  const now = Date.now();
  const entry = publishRates.get(source);

  if (!entry || now - entry.windowStart > PUBLISH_RATE_WINDOW) {
    publishRates.set(source, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count >= PUBLISH_RATE_LIMIT) return false;
  entry.count++;
  return true;
}

// Periodically purge stale rate limit entries to avoid unbounded memory growth
setInterval(() => {
  const cutoff = Date.now() - PUBLISH_RATE_WINDOW * 2;
  for (const [src, entry] of publishRates) {
    if (entry.windowStart < cutoff) publishRates.delete(src);
  }
}, 5 * 60_000);

export class EventBus {
  private subscriptions: Map<string, Subscription[]> = new Map();
  private queue: PriorityQueue<Event>;
  private deadLetter: DeadLetterQueue;
  private processing = false;
  private history: Event[] = [];
  private maxHistory = 1000;

  constructor() {
    this.queue = new PriorityQueue();
    this.deadLetter = new DeadLetterQueue();
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Publishing
  // ─────────────────────────────────────────────────────────────────────────────

  emit<T>(type: string, payload: T, options: Partial<Omit<Event<T>, 'id' | 'type' | 'payload' | 'timestamp'>> = {}): string {
    const source = options.source || 'system';
    if (!checkPublishRateLimit(source)) {
      throw new Error(
        `[EventBus] Publish rate limit exceeded for source "${source}" ` +
        `(${PUBLISH_RATE_LIMIT} events/${PUBLISH_RATE_WINDOW / 1000}s). ` +
        `Agent may be flooding the bus.`
      );
    }

    const event: Event<T> = {
      id: this.generateId(),
      type,
      payload,
      source: options.source || 'system',
      target: options.target,
      priority: options.priority || 'normal',
      timestamp: Date.now(),
      correlationId: options.correlationId,
      replyTo: options.replyTo,
      metadata: options.metadata,
    };

    this.queue.enqueue(event, event.priority);
    this.recordHistory(event);
    this.processQueue();
    
    return event.id;
  }

  // Request-response pattern
  async request<T, R>(type: string, payload: T, timeoutMs = 30000): Promise<R> {
    return new Promise((resolve, reject) => {
      const correlationId = this.generateId();
      const replyType = `${type}:reply:${correlationId}`;
      
      const timeout = setTimeout(() => {
        this.off(replyType);
        reject(new Error(`Request timeout: ${type}`));
      }, timeoutMs);

      this.once(replyType, (event: Event<R>) => {
        clearTimeout(timeout);
        resolve(event.payload);
      });

      this.emit(type, payload, { correlationId, replyTo: replyType });
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Subscribing
  // ─────────────────────────────────────────────────────────────────────────────

  on<T>(pattern: string, handler: EventHandler<T>): () => void {
    return this.subscribe(pattern, handler as EventHandler, false);
  }

  once<T>(pattern: string, handler: EventHandler<T>): () => void {
    return this.subscribe(pattern, handler as EventHandler, true);
  }

  off(pattern: string, handler?: EventHandler): void {
    const subs = this.subscriptions.get(pattern);
    if (!subs) return;

    if (handler) {
      const idx = subs.findIndex(s => s.handler === handler);
      if (idx > -1) subs.splice(idx, 1);
    } else {
      this.subscriptions.delete(pattern);
    }
  }

  private subscribe(pattern: string, handler: EventHandler, once: boolean): () => void {
    const subscription: Subscription = {
      id: this.generateId(),
      pattern,
      handler,
      once,
    };

    if (!this.subscriptions.has(pattern)) {
      this.subscriptions.set(pattern, []);
    }
    this.subscriptions.get(pattern)!.push(subscription);

    return () => this.off(pattern, handler);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Processing
  // ─────────────────────────────────────────────────────────────────────────────

  private async processQueue(): Promise<void> {
    if (this.processing) return;
    this.processing = true;

    while (!this.queue.isEmpty()) {
      const event = this.queue.dequeue();
      if (event) {
        await this.dispatch(event);
      }
    }

    this.processing = false;
  }

  private async dispatch(event: Event): Promise<void> {
    const handlers = this.getMatchingHandlers(event.type);
    
    for (const sub of handlers) {
      try {
        await sub.handler(event);
        if (sub.once) {
          this.off(sub.pattern, sub.handler);
        }
      } catch (error) {
        this.deadLetter.add(event, error instanceof Error ? error : new Error(String(error)));
      }
    }
  }

  private getMatchingHandlers(eventType: string): Subscription[] {
    const handlers: Subscription[] = [];

    for (const [pattern, subs] of this.subscriptions) {
      if (this.matchPattern(eventType, pattern)) {
        handlers.push(...subs);
      }
    }

    return handlers;
  }

  private matchPattern(eventType: string, pattern: string): boolean {
    if (pattern === '*') return true;
    if (pattern === eventType) return true;
    if (pattern.endsWith(':*')) {
      return eventType.startsWith(pattern.slice(0, -1));
    }
    if (pattern.startsWith('*:')) {
      return eventType.endsWith(pattern.slice(1));
    }
    return false;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // History & Dead Letters
  // ─────────────────────────────────────────────────────────────────────────────

  private recordHistory(event: Event): void {
    this.history.push(event);
    if (this.history.length > this.maxHistory) {
      this.history = this.history.slice(-this.maxHistory / 2);
    }
  }

  getHistory(filter?: { type?: string; since?: number; limit?: number }): Event[] {
    let events = [...this.history];
    if (filter?.type) events = events.filter(e => this.matchPattern(e.type, filter.type!));
    if (filter?.since) events = events.filter(e => e.timestamp >= filter.since!);
    if (filter?.limit) events = events.slice(-filter.limit);
    return events;
  }

  getDeadLetters(): ReturnType<DeadLetterQueue['getAll']> {
    return this.deadLetter.getAll();
  }

  retryDeadLetter(eventId: string): boolean {
    return this.deadLetter.retry(eventId, (event) => {
      this.queue.enqueue(event, event.priority);
      this.processQueue();
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Utilities
  // ─────────────────────────────────────────────────────────────────────────────

  private generateId(): string {
    return `${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 9)}`;
  }

  getStats(): { subscriptions: number; queueSize: number; deadLetters: number; historySize: number } {
    return {
      subscriptions: Array.from(this.subscriptions.values()).reduce((acc, subs) => acc + subs.length, 0),
      queueSize: this.queue.size(),
      deadLetters: this.deadLetter.size(),
      historySize: this.history.length,
    };
  }
}

// Singleton export
export const eventBus = new EventBus();
