// TIMPS-Parasol · identity-anchor.test.ts

import { describe, expect, it } from 'vitest';
import { IdentityAnchor } from '../src/index.js';
import { generateKeypair, signWithEd25519 } from '../src/index.js';

describe('identity anchor', () => {
  it('grants owner status with valid cryptographic signature', () => {
    const keys = generateKeypair();
    const anchor = new IdentityAnchor(keys.publicKey);
    const challenge = 'random-challenge-xyz';
    const sig = signWithEd25519(challenge, keys.privateKey);
    const result = anchor.verifyOwnerClaim('user-1', 'discord', sig, challenge);
    expect(result.isOwner).toBe(true);
    expect(result.confidence).toBe('cryptographic');
  });

  it('rejects owner claim with wrong key', () => {
    const keys = generateKeypair();
    const otherKeys = generateKeypair();
    const anchor = new IdentityAnchor(keys.publicKey);
    const challenge = 'random-challenge-xyz';
    const sig = signWithEd25519(challenge, otherKeys.privateKey);
    const result = anchor.verifyOwnerClaim('user-1', 'discord', sig, challenge);
    expect(result.isOwner).toBe(false);
  });

  it('denies claim without signature (heuristic confidence)', () => {
    const keys = generateKeypair();
    const anchor = new IdentityAnchor(keys.publicKey);
    const result = anchor.verifyOwnerClaim('user-1', 'email');
    expect(result.isOwner).toBe(false);
    expect(result.confidence).toBe('heuristic');
  });

  it('flags suspicious actors and blocks their subsequent owner claims', () => {
    const keys = generateKeypair();
    const anchor = new IdentityAnchor(keys.publicKey);
    anchor.flagSuspiciousActor('bad-actor', 'identity_spoof_attempt');
    const result = anchor.verifyOwnerClaim('bad-actor', 'slack');
    expect(result.isOwner).toBe(false);
    expect(result.confidence).toBe('none');
  });

  it('suspicion flags persist across channels', () => {
    const keys = generateKeypair();
    const anchor = new IdentityAnchor(keys.publicKey);
    anchor.flagSuspiciousActor('bad-actor', 'social_manipulation');
    // Try from a completely different channel
    const result = anchor.verifyOwnerClaim('bad-actor', 'sms');
    expect(result.confidence).toBe('none');
  });

  it('getSuspicion returns record for flagged actor', () => {
    const keys = generateKeypair();
    const anchor = new IdentityAnchor(keys.publicKey);
    anchor.flagSuspiciousActor('actor-x', 'guilt_tripping');
    const rec = anchor.getSuspicion('actor-x');
    expect(rec?.flags).toContain('guilt_tripping');
  });

  it('clearSuspicion removes flags', () => {
    const keys = generateKeypair();
    const anchor = new IdentityAnchor(keys.publicKey);
    anchor.flagSuspiciousActor('actor-x', 'guilt_tripping');
    anchor.clearSuspicion('actor-x');
    expect(anchor.getSuspicion('actor-x')).toBeUndefined();
  });
});
