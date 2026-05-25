// TIMPS-Parasol · identity.test.ts

import { describe, expect, it } from 'vitest';
import { checkPermission, generateKeypair, issueJWT, signWithEd25519, verifyEd25519, verifyJWT } from '../src/index.js';

describe('identity', () => {
  it('signs and verifies ed25519', () => {
    const keys = generateKeypair();
    const signature = signWithEd25519('hello', keys.privateKey);
    expect(verifyEd25519('hello', signature, keys.publicKey)).toBe(true);
  });

  it('issues and verifies jwt', () => {
    const token = issueJWT({ sub: 'u1', role: 'admin', ip: '127.0.0.1', userAgent: 'ua' }, 'secret', 60);
    expect(verifyJWT(token, 'secret').sub).toBe('u1');
  });

  it('checks role permissions', () => {
    expect(checkPermission('viewer', 'read')).toBe(true);
    expect(checkPermission('viewer', 'write')).toBe(false);
  });
});
