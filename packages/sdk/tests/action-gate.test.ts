// TIMPS-Parasol · action-gate.test.ts

import { describe, expect, it } from 'vitest';
import { irreversibleActionGate, isDestructiveAction } from '../src/index.js';
import { createSentinel } from '../src/index.js';

describe('action gate', () => {
  it('allows non-destructive actions without a signature', async () => {
    const sentinel = createSentinel();
    const result = await irreversibleActionGate('read file', 'owner', sentinel);
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe('non-destructive');
  });

  it('blocks destructive action from non-owner', async () => {
    const sentinel = createSentinel();
    const result = await irreversibleActionGate('delete all records', 'non-owner', sentinel);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('NON_OWNER_DESTRUCTIVE_BLOCKED');
  });

  it('blocks destructive action from owner without signature', async () => {
    const sentinel = createSentinel();
    const result = await irreversibleActionGate('wipe server', 'owner', sentinel);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('OWNER_SIGNATURE_REQUIRED_FOR_DESTRUCTIVE_ACTION');
  });

  it('allows destructive action from owner with signature', async () => {
    const sentinel = createSentinel();
    const result = await irreversibleActionGate('reset database', 'owner', sentinel, 'sig-abc');
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe('owner-verified-destructive');
  });

  it('logs destructive attempts to sentinel', async () => {
    const sentinel = createSentinel();
    await irreversibleActionGate('purge logs', 'non-owner', sentinel);
    const entries = sentinel.query();
    expect(entries.some((e) => e.action === 'DESTRUCTIVE_ACTION_BLOCKED')).toBe(true);
  });

  it('isDestructiveAction identifies keywords', () => {
    expect(isDestructiveAction('rm -rf /var')).toBe(true);
    expect(isDestructiveAction('drop table users')).toBe(true);
    expect(isDestructiveAction('list files')).toBe(false);
  });
});
