// TIMPS-Parasol · vault.test.ts

import { describe, expect, it } from 'vitest';
import { VaultKeyStore, decrypt, deriveKey, encrypt, generateVaultKey } from '../src/index.js';

describe('vault', () => {
  it('encrypts and decrypts with aes-gcm', () => {
    const key = generateVaultKey();
    const encrypted = encrypt('secret', key);
    expect(decrypt(encrypted, key)).toBe('secret');
  });

  it('derives deterministic keys', () => {
    expect(deriveKey('pass', 'salt')).toEqual(deriveKey('pass', 'salt'));
  });

  it('rotates per-user keys', () => {
    const store = new VaultKeyStore();
    const oldKey = generateVaultKey();
    const newKey = generateVaultKey();
    store.setUserKey('u1', oldKey);
    store.saveEntry('u1', 'hello');
    store.rotateKey('u1', oldKey, newKey);
    const entries = store.getEntries('u1');
    expect(decrypt(entries[0], newKey)).toBe('hello');
  });
});
