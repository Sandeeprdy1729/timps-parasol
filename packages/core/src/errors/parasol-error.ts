// TIMPS-Parasol · errors/parasol-error.ts
// Base error class for the entire Parasol error hierarchy.
// All Parasol errors extend ParasolError, enabling instanceof checks
// at catch boundaries without importing every concrete subclass.

import type { ThreatLevel } from '../types/security.types.js';

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/**
 * Structured error codes for machine-readable categorisation.
 * Each code maps to a single concrete error class.
 *
 * Ranges:
 *   P0xx — Base / internal
 *   P1xx — Policy & enforcement
 *   P2xx — Identity & authentication
 *   P3xx — PII & data protection
 *   P4xx — Cryptographic operations
 *   P5xx — Vault access
 *   P6xx — Resource / budget
 *   P7xx — Flow violations
 *   P8xx — AI layer errors
 */
export type ParasolErrorCode =
  // Base
  | 'P001' // Generic Parasol error
  | 'P002' // Configuration error
  | 'P003' // Unsupported operation
  // Policy
  | 'P101' // Policy violation (DENY)
  | 'P102' // Policy requires confirmation
  | 'P103' // Policy evaluation failed
  | 'P104' // Policy not found
  // Identity
  | 'P201' // Spoofing detected
  | 'P202' // Verification failed
  | 'P203' // Token expired
  | 'P204' // Insufficient trust score
  | 'P205' // Credential revoked
  | 'P206' // Challenge expired or consumed
  // PII
  | 'P301' // PII leak attempt
  | 'P302' // PII redaction failed
  | 'P303' // PII policy violation
  // Crypto
  | 'P401' // Signature verification failed
  | 'P402' // Encryption failed
  | 'P403' // Decryption failed
  | 'P404' // Key not found
  // Vault
  | 'P501' // Vault access denied
  | 'P502' // Secret not found
  | 'P503' // Vault locked
  // Resource
  | 'P601' // Budget exceeded
  | 'P602' // Rate limit exceeded
  // Flow
  | 'P701' // Flow violation
  | 'P702' // Cycle detected in flow graph
  // AI
  | 'P801' // Injection detected
  | 'P802' // AI shield block
  | 'P803' // Provider unavailable;

// ---------------------------------------------------------------------------
// ParasolErrorContext
// ---------------------------------------------------------------------------

/**
 * Structured diagnostic context attached to every Parasol error.
 * Included in audit logs when the error is caught and logged.
 */
export interface ParasolErrorContext {
  /** Unique code for machine-readable categorisation. */
  code: ParasolErrorCode;
  /** TRiSM threat level associated with this error. */
  threatLevel: ThreatLevel;
  /** Id of the agent that triggered the error (if known). */
  agentId?: string;
  /** Id of the object / resource involved (if applicable). */
  resourceId?: string;
  /** Correlation id for distributed tracing. */
  correlationId?: string;
  /** ISO 8601 timestamp of the error. */
  timestamp: string;
  /** Arbitrary additional context (no raw PII). */
  details?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// ParasolError  (base class)
// ---------------------------------------------------------------------------

/**
 * Base class for all Parasol errors.
 *
 * Usage:
 * ```ts
 * try {
 *   doSomething();
 * } catch (err) {
 *   if (err instanceof ParasolError) {
 *     logger.error(err.context.code, err.message);
 *   }
 * }
 * ```
 */
export class ParasolError extends Error {
  /** Structured diagnostic context. */
  readonly context: ParasolErrorContext;

  constructor(message: string, context: Omit<ParasolErrorContext, 'timestamp'>) {
    super(message);
    this.name = 'ParasolError';
    this.context = {
      ...context,
      timestamp: new Date().toISOString(),
    };

    // Maintain proper prototype chain in transpiled environments
    Object.setPrototypeOf(this, new.target.prototype);

    // Capture V8 stack trace if available
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, new.target);
    }
  }

  /**
   * Convert to a safe JSON-serialisable object for logging.
   * Never includes raw PII or secret material.
   */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      context: this.context,
      stack: this.stack,
    };
  }

  /**
   * Return a short string representation suitable for one-line log entries.
   */
  override toString(): string {
    return `[${this.context.code}] ${this.name}: ${this.message}`;
  }
}

// ---------------------------------------------------------------------------
// ConfigurationError
// ---------------------------------------------------------------------------

/**
 * Thrown when Parasol encounters an invalid or missing configuration value.
 */
export class ConfigurationError extends ParasolError {
  /** The configuration key that was invalid or missing. */
  readonly configKey: string;

  constructor(
    configKey: string,
    message: string,
    details?: Record<string, unknown>,
  ) {
    super(message, {
      code: 'P002',
      threatLevel: 2 as ThreatLevel, // MODERATE
      details: { configKey, ...details },
    });
    this.name = 'ConfigurationError';
    this.configKey = configKey;
  }
}
