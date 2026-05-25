// TIMPS-Parasol · perimeter.test.ts

import { describe, expect, it } from 'vitest';
import { createPerimeterMiddleware, sanitizeInput, signRequest, verifySignature } from '../src/index.js';

describe('perimeter', () => {
  it('sanitizes potentially dangerous input', () => {
    expect(sanitizeInput('<script>alert(1)</script>SELECT * FROM users')).toContain('[blocked-sql]');
  });

  it('signs and verifies request payloads', () => {
    const sig = signRequest('payload', 'secret');
    expect(verifySignature('payload', sig, 'secret')).toBe(true);
  });

  it('blocks when rate limit is exceeded', () => {
    const middleware = createPerimeterMiddleware({
      requestsPerMinute: 1,
      blockThreshold: 2,
      blockDurationMs: 30000,
      maxInputLength: 100
    });
    middleware({ ip: '1.1.1.1', body: 'ok' });
    const result = middleware({ ip: '1.1.1.1', body: 'ok' });
    expect(result.allowed).toBe(false);
    expect(result.statusCode).toBe(429);
  });
});
