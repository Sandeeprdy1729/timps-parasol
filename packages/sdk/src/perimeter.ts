// TIMPS-Parasol · perimeter.ts

import { createHmac, timingSafeEqual } from 'node:crypto';
import type { PerimeterConfig } from './types.js';

const SQL_PATTERN = /(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|--|;)/gi;
const SCRIPT_PATTERN = /(<script\b[^>]*>|javascript:|onerror=|onload=)/gi;
const HTML_PATTERN = /<[^>]+>/g;

export interface PerimeterRequest {
  ip: string;
  userId?: string;
  body?: unknown;
  headers?: Record<string, string | undefined>;
}

export interface PerimeterResult {
  allowed: boolean;
  reason?: string;
  statusCode?: number;
  headers?: Record<string, string>;
  sanitizedBody?: unknown;
}

/** Sanitize string input by stripping HTML and script fragments. */
export function sanitizeInput(str: string, maxLength = 2048): string {
  const trimmed = str.slice(0, maxLength);
  const withoutHtml = trimmed.replace(HTML_PATTERN, '');
  return withoutHtml.replace(SCRIPT_PATTERN, '[blocked-script]').replace(SQL_PATTERN, '[blocked-sql]');
}

/** Create an HMAC-SHA256 signature for a payload. */
export function signRequest(payload: string, secret: string): string {
  return createHmac('sha256', secret).update(payload).digest('hex');
}

/** Verify HMAC-SHA256 request signature in constant time. */
export function verifySignature(payload: string, sig: string, secret: string): boolean {
  const expected = signRequest(payload, secret);
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(sig, 'hex');
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

/** Create perimeter middleware with rate limiting and DDoS blocking. */
export function createPerimeterMiddleware(config: PerimeterConfig) {
  const requests = new Map<string, number[]>();
  const failures = new Map<string, number>();
  const blocked = new Map<string, number>();

  return (req: PerimeterRequest): PerimeterResult => {
    const now = Date.now();
    const key = req.userId ?? req.ip;
    const blockedUntil = blocked.get(req.ip);
    if (blockedUntil && blockedUntil > now) {
      return {
        allowed: false,
        reason: 'IP temporarily blocked',
        statusCode: 429,
        headers: { 'Retry-After': Math.ceil((blockedUntil - now) / 1000).toString() }
      };
    }

    const windowStart = now - 60_000;
    const recent = (requests.get(key) ?? []).filter((ts) => ts >= windowStart);
    recent.push(now);
    requests.set(key, recent);

    if (recent.length > config.requestsPerMinute) {
      const failureCount = (failures.get(req.ip) ?? 0) + 1;
      failures.set(req.ip, failureCount);
      const backoffSeconds = Math.min(60, 2 ** failureCount);
      if (failureCount >= config.blockThreshold) {
        blocked.set(req.ip, now + config.blockDurationMs);
      }
      return {
        allowed: false,
        reason: 'Rate limit exceeded',
        statusCode: 429,
        headers: {
          'Retry-After': String(backoffSeconds),
          'X-Parasol-Backoff': String(backoffSeconds)
        }
      };
    }

    let sanitizedBody = req.body;
    if (typeof req.body === 'string') {
      sanitizedBody = sanitizeInput(req.body, config.maxInputLength);
    }

    return { allowed: true, sanitizedBody };
  };
}
