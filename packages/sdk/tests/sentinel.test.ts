// TIMPS-Parasol · sentinel.test.ts

import { describe, expect, it } from 'vitest';
import { createSentinel } from '../src/index.js';

describe('sentinel', () => {
  it('keeps append-only records and exports user logs', async () => {
    const sentinel = createSentinel();
    await sentinel.log({ userId: 'u1', action: 'LOG_READ', resource: 'vault', ip: '1.1.1.1', result: 'success' });
    expect(sentinel.query('u1')).toHaveLength(1);
    expect(JSON.parse(sentinel.export('u1'))).toHaveLength(1);
  });

  it('triggers breach callback after repeated auth failures', async () => {
    const sentinel = createSentinel();
    let called = false;
    sentinel.onBreach(() => {
      called = true;
    });

    for (let i = 0; i < 6; i += 1) {
      await sentinel.log({ userId: 'u1', action: 'LOG_AUTH', resource: 'auth', ip: '2.2.2.2', result: 'failure' });
    }

    expect(called).toBe(true);
  });
});
