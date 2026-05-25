// TIMPS-Parasol · vault.ts

import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';

export interface CipherPackage {
  iv: string;
  tag: string;
  data: string;
}

/** Generate random 256-bit vault key. */
export function generateVaultKey(): Buffer {
  return randomBytes(32);
}

/** Derive a vault key with PBKDF2 and 100,000 iterations. */
export function deriveKey(passphrase: string, salt: string): Buffer {
  return pbkdf2Sync(passphrase, salt, 100_000, 32, 'sha256');
}

/** Encrypt plaintext using AES-256-GCM with random 96-bit IV. */
export function encrypt(plaintext: string | Buffer, key: Buffer): CipherPackage {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    data: data.toString('base64')
  };
}

/** Decrypt AES-256-GCM ciphertext package. */
export function decrypt(ciphertext: CipherPackage, key: Buffer): string {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ciphertext.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(ciphertext.tag, 'base64'));
  const data = Buffer.concat([
    decipher.update(Buffer.from(ciphertext.data, 'base64')),
    decipher.final()
  ]);
  return data.toString('utf8');
}

/** Manage per-user isolated vault keys and encrypted entries. */
export class VaultKeyStore {
  private readonly keys = new Map<string, Buffer>();

  private readonly entries = new Map<string, CipherPackage[]>();

  setUserKey(userId: string, key: Buffer): void {
    this.keys.set(userId, key);
  }

  getUserKey(userId: string): Buffer {
    const key = this.keys.get(userId);
    if (!key) {
      throw new Error('User key not found');
    }
    return key;
  }

  saveEntry(userId: string, plaintext: string): CipherPackage {
    const encrypted = encrypt(plaintext, this.getUserKey(userId));
    const list = this.entries.get(userId) ?? [];
    list.push(encrypted);
    this.entries.set(userId, list);
    return encrypted;
  }

  getEntries(userId: string): CipherPackage[] {
    return [...(this.entries.get(userId) ?? [])];
  }

  rotateKey(userId: string, oldKey: Buffer, newKey: Buffer): void {
    const encryptedEntries = this.entries.get(userId) ?? [];
    const reEncrypted = encryptedEntries.map((item) => encrypt(decrypt(item, oldKey), newKey));
    this.entries.set(userId, reEncrypted);
    this.keys.set(userId, newKey);
  }
}
