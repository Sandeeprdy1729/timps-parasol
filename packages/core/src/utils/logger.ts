// TIMPS-Parasol · utils/logger.ts
// Structured JSON logger for all Parasol layers.
//
// Design:
//   - Produces newline-delimited JSON (NDJSON) compatible with Loki, Datadog,
//     CloudWatch, and Elastic.
//   - Every log entry carries a correlationId for distributed tracing.
//   - PII redaction is applied to the `meta` field before writing.
//   - Audit-level entries are forwarded to the SentinelLogger queue.
//   - Log level is controlled by the PARASOL_LOG_LEVEL environment variable.
//   - Output destination is pluggable (stdout, stream, no-op for tests).

import type { AuditEvent } from '../types/audit.types.js';
import { ThreatLevel } from '../types/security.types.js';
import { randomB64 } from './crypto.js';

// ---------------------------------------------------------------------------
// Log levels
// ---------------------------------------------------------------------------

export type LogLevel = 'TRACE' | 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'AUDIT' | 'SILENT';

const LOG_LEVEL_ORDINAL: Record<LogLevel, number> = {
  TRACE:  0,
  DEBUG:  1,
  INFO:   2,
  WARN:   3,
  ERROR:  4,
  AUDIT:  5,
  SILENT: 99,
};

// ---------------------------------------------------------------------------
// LogEntry
// ---------------------------------------------------------------------------

/**
 * A structured log entry as it appears in the output stream.
 * All fields are safe for external consumption (no raw PII).
 */
export interface LogEntry {
  /** ISO 8601 UTC timestamp with millisecond precision. */
  timestamp: string;
  /** Log level. */
  level: LogLevel;
  /** Log message string. */
  message: string;
  /** Parasol layer that emitted this log (e.g. "AIShield", "Vault", "Perimeter"). */
  layer: string;
  /** Correlation id linking this entry to a request. */
  correlationId: string;
  /** Id of the acting agent (if known). */
  agentId?: string;
  /** Structured metadata. Must not contain raw PII values. */
  meta?: Record<string, unknown>;
  /** TRiSM threat level (populated for WARN/ERROR/AUDIT entries). */
  threatLevel?: ThreatLevel;
  /** Error details (populated on ERROR entries). */
  error?: { name: string; message: string; stack?: string };
}

// ---------------------------------------------------------------------------
// Output sink
// ---------------------------------------------------------------------------

export type LogSink = (entry: LogEntry) => void;

/** Default sink: writes NDJSON to stdout. */
const stdoutSink: LogSink = (entry) => {
  process.stdout.write(JSON.stringify(entry) + '\n');
};

// ---------------------------------------------------------------------------
// AuditForwarder
// ---------------------------------------------------------------------------

/**
 * Callback type for forwarding AUDIT-level log entries to the SentinelLogger.
 * Implementations call `sentinel.log(...)` with the entry data.
 */
export type AuditForwarder = (
  entry: Omit<AuditEvent, 'id' | 'timestamp'>,
) => void | Promise<void>;

// ---------------------------------------------------------------------------
// LoggerConfig
// ---------------------------------------------------------------------------

export interface LoggerConfig {
  /**
   * Minimum log level to emit.
   * Defaults to the value of PARASOL_LOG_LEVEL env var, or 'INFO'.
   */
  level?: LogLevel;
  /**
   * Parasol layer name included in every log entry (e.g. "AIShield").
   */
  layer: string;
  /**
   * Default correlation id for entries that don't provide one.
   * A fresh id is generated per logger instance if not provided.
   */
  defaultCorrelationId?: string;
  /** Custom output sink. Defaults to stdout NDJSON. */
  sink?: LogSink;
  /**
   * Optional forwarder for AUDIT-level entries.
   * If provided, AUDIT entries are forwarded to the SentinelLogger in addition
   * to being written to the log sink.
   */
  auditForwarder?: AuditForwarder;
  /**
   * If true, PII patterns in `meta` string values are replaced with
   * [REDACTED] markers before writing.
   * Default: true.
   */
  redactMetaPII?: boolean;
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

/**
 * Structured logger for Parasol layers.
 *
 * Usage:
 * ```ts
 * const log = createLogger({ layer: 'AIShield' });
 * log.info('Prompt scanned', { correlationId: ctx.correlationId, matches: 3 });
 * log.audit('PII detected in response', ctx.correlationId, { ... });
 * ```
 */
export class Logger {
  private readonly config: Required<Omit<LoggerConfig, 'auditForwarder' | 'redactMetaPII'>> &
    Pick<LoggerConfig, 'auditForwarder' | 'redactMetaPII'>;

  private readonly minOrdinal: number;

  constructor(config: LoggerConfig) {
    const envLevel = (process.env['PARASOL_LOG_LEVEL'] ?? 'INFO') as LogLevel;
    const effectiveLevel: LogLevel = config.level ?? (envLevel in LOG_LEVEL_ORDINAL ? envLevel : 'INFO');

    this.config = {
      level: effectiveLevel,
      layer: config.layer,
      defaultCorrelationId: config.defaultCorrelationId ?? randomB64(12),
      sink: config.sink ?? stdoutSink,
      auditForwarder: config.auditForwarder,
      redactMetaPII: config.redactMetaPII ?? true,
    };
    this.minOrdinal = LOG_LEVEL_ORDINAL[effectiveLevel];
  }

  // ── Core log method ───────────────────────────────────────────────────────

  private write(
    level: LogLevel,
    message: string,
    options: {
      correlationId?: string;
      agentId?: string;
      meta?: Record<string, unknown>;
      threatLevel?: ThreatLevel;
      error?: Error;
    } = {},
  ): void {
    if (LOG_LEVEL_ORDINAL[level] < this.minOrdinal) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      layer: this.config.layer,
      correlationId: options.correlationId ?? this.config.defaultCorrelationId,
      agentId: options.agentId,
      meta: options.meta ? this.sanitiseMeta(options.meta) : undefined,
      threatLevel: options.threatLevel,
      error: options.error
        ? {
            name: options.error.name,
            message: options.error.message,
            stack: options.error.stack,
          }
        : undefined,
    };

    // Remove undefined fields for clean JSON output
    const cleaned = Object.fromEntries(
      Object.entries(entry).filter(([, v]) => v !== undefined),
    ) as LogEntry;

    this.config.sink(cleaned);
  }

  // ── Level methods ─────────────────────────────────────────────────────────

  trace(message: string, meta?: Record<string, unknown>, correlationId?: string): void {
    this.write('TRACE', message, { meta, correlationId });
  }

  debug(message: string, meta?: Record<string, unknown>, correlationId?: string): void {
    this.write('DEBUG', message, { meta, correlationId });
  }

  info(message: string, meta?: Record<string, unknown>, correlationId?: string): void {
    this.write('INFO', message, { meta, correlationId });
  }

  warn(
    message: string,
    meta?: Record<string, unknown>,
    correlationId?: string,
    threatLevel?: ThreatLevel,
  ): void {
    this.write('WARN', message, { meta, correlationId, threatLevel: threatLevel ?? ThreatLevel.MODERATE });
  }

  error(
    message: string,
    err?: Error,
    meta?: Record<string, unknown>,
    correlationId?: string,
  ): void {
    this.write('ERROR', message, {
      error: err,
      meta,
      correlationId,
      threatLevel: ThreatLevel.HIGH,
    });
  }

  /**
   * Emit an AUDIT-level entry. These are always written regardless of
   * the configured minimum log level (they bypass the ordinal check).
   *
   * If `auditForwarder` is configured, the entry is also forwarded to the
   * SentinelLogger.
   */
  audit(
    message: string,
    correlationId: string,
    meta: Record<string, unknown>,
    agentId?: string,
    threatLevel?: ThreatLevel,
  ): void {
    // AUDIT entries always bypass the level filter
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: 'AUDIT',
      message,
      layer: this.config.layer,
      correlationId,
      agentId,
      meta: this.sanitiseMeta(meta),
      threatLevel: threatLevel ?? ThreatLevel.NONE,
    };
    this.config.sink(entry);

    if (this.config.auditForwarder) {
      void this.config.auditForwarder({
        category: 'AGENT_ACTION',
        agentId: agentId ?? 'unknown',
        action: message,
        result: 'SUCCESS',
        threatLevel: threatLevel ?? ThreatLevel.NONE,
        layer: this.config.layer,
        correlationId,
        metadata: meta,
      });
    }
  }

  // ── Child logger ──────────────────────────────────────────────────────────

  /**
   * Create a child logger that inherits this logger's configuration but
   * uses a fixed correlationId and optional sub-layer name.
   */
  child(correlationId: string, subLayer?: string): Logger {
    return createLogger({
      ...this.config,
      layer: subLayer ? `${this.config.layer}:${subLayer}` : this.config.layer,
      defaultCorrelationId: correlationId,
    });
  }

  // ── Meta sanitisation ─────────────────────────────────────────────────────

  /**
   * Sanitise a meta object before writing to the log.
   * Replaces obvious PII patterns in string values with [REDACTED].
   */
  private sanitiseMeta(meta: Record<string, unknown>): Record<string, unknown> {
    if (!this.config.redactMetaPII) return meta;
    const sanitised: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(meta)) {
      if (typeof value === 'string') {
        sanitised[key] = sanitiseString(value);
      } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        sanitised[key] = this.sanitiseMeta(value as Record<string, unknown>);
      } else {
        sanitised[key] = value;
      }
    }
    return sanitised;
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a Logger instance.
 *
 * @param config - Logger configuration.
 */
export function createLogger(config: LoggerConfig): Logger {
  return new Logger(config);
}

/**
 * Create a no-op logger that discards all output (useful in tests).
 */
export function createNullLogger(layer: string): Logger {
  return new Logger({ layer, sink: () => undefined, level: 'SILENT' });
}

// ---------------------------------------------------------------------------
// PII sanitisation helpers (minimal — full redaction is in PiiContextRedactor)
// ---------------------------------------------------------------------------

/** Patterns for quick meta sanitisation. */
const QUICK_REDACT_PATTERNS: ReadonlyArray<[RegExp, string]> = [
  [/\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b/gi, '[REDACTED-email]'],
  [/(?:\+91[\s\-]?)?[6-9]\d{9}\b/g, '[REDACTED-phone]'],
  [/\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b/g, '[REDACTED-aadhaar]'],
  [/\b[A-Z]{5}[0-9]{4}[A-Z]\b/gi, '[REDACTED-pan]'],
  [/\b(?!000|666|9\d\d)\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b/g, '[REDACTED-ssn]'],
  [
    /\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b/g,
    '[REDACTED-card]',
  ],
];

/**
 * Apply quick PII redaction to a string for safe log output.
 * This is a best-effort sanitisation; use PIIContextRedactor for full coverage.
 */
function sanitiseString(value: string): string {
  let result = value;
  for (const [pattern, replacement] of QUICK_REDACT_PATTERNS) {
    result = result.replace(pattern, replacement);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Module-level default logger  (used when no logger is injected)
// ---------------------------------------------------------------------------

/** Default module-level logger for Parasol core utilities. */
export const coreLogger = createLogger({ layer: 'core' });
