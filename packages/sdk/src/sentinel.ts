// TIMPS-Parasol · sentinel.ts

import { randomUUID } from 'node:crypto';
import type { AuditEntry } from './types.js';

export type SentinelAction =
  | 'LOG_READ'
  | 'LOG_WRITE'
  | 'LOG_AUTH'
  | 'LOG_AI_CALL'
  | 'LOG_BREACH'
  | 'LOG_KEY_ROTATION';

export interface SentinelConfig {
  webhookUrl?: string;
}

type BreachHandler = (entry: AuditEntry) => void | Promise<void>;

/** Append-only sentinel logger for audit and breach monitoring. */
export class SentinelLogger {
  private readonly entries: AuditEntry[] = [];

  private readonly breachHandlers = new Set<BreachHandler>();

  private webhookUrl?: string;

  constructor(config: SentinelConfig = {}) {
    this.webhookUrl = config.webhookUrl;
  }

  configureWebhook(url: string): void {
    this.webhookUrl = url;
  }

  async log(entry: Omit<AuditEntry, 'id' | 'timestamp'>): Promise<AuditEntry> {
    const record: AuditEntry = {
      ...entry,
      id: randomUUID(),
      timestamp: new Date().toISOString()
    };
    this.entries.push(record);
    await this.detectBreach(record);
    return record;
  }

  query(userId?: string): AuditEntry[] {
    return this.entries.filter((entry) => (userId ? entry.userId === userId : true));
  }

  export(userId: string): string {
    return JSON.stringify(this.query(userId), null, 2);
  }

  onBreach(handler: BreachHandler): void {
    this.breachHandlers.add(handler);
  }

  private async detectBreach(entry: AuditEntry): Promise<void> {
    if (entry.action !== 'LOG_AUTH' || entry.result !== 'failure') {
      return;
    }
    const cutoff = Date.now() - 60_000;
    const failedAuth = this.entries.filter((candidate) => {
      return (
        candidate.action === 'LOG_AUTH' &&
        candidate.result === 'failure' &&
        candidate.ip === entry.ip &&
        new Date(candidate.timestamp).getTime() >= cutoff
      );
    });
    if (failedAuth.length <= 5) {
      return;
    }

    for (const handler of this.breachHandlers) {
      await handler(entry);
    }
    if (this.webhookUrl) {
      await fetch(this.webhookUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ type: 'breach', entry })
      }).catch(() => undefined);
    }
  }
}

/** Create sentinel logger instance. */
export function createSentinel(config: SentinelConfig = {}): SentinelLogger {
  return new SentinelLogger(config);
}
