// TIMPS-Parasol · utils/crypto.ts
// Cryptographic primitives:
//   • Ed25519 sign / verify  (identity anchors, audit export signing)
//   • AES-256-GCM encrypt / decrypt  (Vault secrets, ENCRYPT PII strategy)
//   • PBKDF2 key derivation  (password hashing, secret wrapping)
//   • Secure random utilities (challenge generation, salt generation)
//   • Key serialisation helpers
//
// All operations use the Node.js built-in `node:crypto` module.
// No third-party cryptographic libraries are used.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  generateKeyPairSync,
  pbkdf2Sync,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} from 'node:crypto';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AES_ALGORITHM = 'aes-256-gcm' as const;
const AES_KEY_LENGTH = 32;  // 256 bits
const AES_IV_LENGTH  = 12;  // 96 bits (recommended for GCM)
const AES_TAG_LENGTH = 16;  // 128-bit authentication tag

const PBKDF2_DIGEST    = 'sha256' as const;
const PBKDF2_SALT_LEN  = 32;  // 256 bits
const PBKDF2_ITERATIONS = 310_000;  // NIST SP 800-63B recommendation for SHA-256
const PBKDF2_KEY_LEN   = 32;  // 256-bit derived key

const CHALLENGE_BYTES = 32;  // 256 bits
const HMAC_DIGEST     = 'sha256' as const;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A serialised AES-256-GCM ciphertext bundle. */
export interface AESCipherBundle {
  /** Base64url-encoded IV (12 bytes). */
  iv: string;
  /** Base64url-encoded GCM authentication tag (16 bytes). */
  tag: string;
  /** Base64url-encoded ciphertext. */
  ciphertext: string;
  /** ISO 8601 timestamp of encryption (for key-rotation deadline tracking). */
  encryptedAt: string;
  /**
   * Optional key id — identifies which AES key was used to produce this bundle.
   * Required for key rotation: the decryptor must look up the key by id.
   */
  keyId?: string;
}

/** PBKDF2-derived key bundle (stored alongside the hashed password). */
export interface PBKDF2Bundle {
  /** Base64url-encoded random salt (32 bytes). */
  salt: string;
  /** PBKDF2 iteration count used to produce this hash. */
  iterations: number;
  /** Hash algorithm used. */
  digest: string;
  /** Base64url-encoded derived key. */
  derivedKey: string;
}

/** Ed25519 keypair in PEM format. */
export interface Ed25519Keypair {
  /** SPKI PEM public key. */
  publicKey: string;
  /** PKCS#8 PEM private key. */
  privateKey: string;
}

// ---------------------------------------------------------------------------
// Ed25519  (sign / verify)
// ---------------------------------------------------------------------------

/**
 * Generate an Ed25519 keypair suitable for identity anchors and audit signing.
 *
 * @returns Object with `publicKey` (SPKI PEM) and `privateKey` (PKCS#8 PEM).
 */
export function generateEd25519Keypair(): Ed25519Keypair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

/**
 * Sign `payload` using an Ed25519 private key.
 *
 * @param payload     - UTF-8 string or Buffer to sign.
 * @param privateKey  - PKCS#8 PEM private key string.
 * @returns Base64url-encoded Ed25519 signature.
 */
export function signEd25519(payload: string | Buffer, privateKey: string): string {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  return sign(null, data, privateKey).toString('base64url');
}

/**
 * Verify an Ed25519 signature against a payload and public key.
 *
 * @param payload    - The original payload (UTF-8 string or Buffer).
 * @param signature  - Base64url-encoded signature string.
 * @param publicKey  - SPKI PEM public key string.
 * @returns `true` if the signature is valid; `false` otherwise.
 */
export function verifyEd25519(
  payload: string | Buffer,
  signature: string,
  publicKey: string,
): boolean {
  try {
    const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
    const sig  = Buffer.from(signature, 'base64url');
    return verify(null, data, publicKey, sig);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// AES-256-GCM  (encrypt / decrypt)
// ---------------------------------------------------------------------------

/**
 * Encrypt `plaintext` using AES-256-GCM with the provided 256-bit key.
 *
 * @param plaintext  - UTF-8 string to encrypt.
 * @param key        - 32-byte AES key (Buffer or base64url string).
 * @param keyId      - Optional key id for rotation tracking.
 * @returns An {@link AESCipherBundle} containing IV, tag and ciphertext.
 */
export function encryptAES(
  plaintext: string,
  key: Buffer | string,
  keyId?: string,
): AESCipherBundle {
  const keyBuf = typeof key === 'string' ? Buffer.from(key, 'base64url') : key;
  if (keyBuf.length !== AES_KEY_LENGTH) {
    throw new Error(`AES key must be ${AES_KEY_LENGTH} bytes; got ${keyBuf.length}`);
  }

  const iv = randomBytes(AES_IV_LENGTH);
  const cipher = createCipheriv(AES_ALGORITHM, keyBuf, iv, { authTagLength: AES_TAG_LENGTH });

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return {
    iv:          iv.toString('base64url'),
    tag:         tag.toString('base64url'),
    ciphertext:  encrypted.toString('base64url'),
    encryptedAt: new Date().toISOString(),
    keyId,
  };
}

/**
 * Decrypt an {@link AESCipherBundle} using AES-256-GCM.
 *
 * Throws if the authentication tag does not match (i.e. ciphertext has
 * been tampered with).
 *
 * @param bundle  - The cipher bundle produced by `encryptAES`.
 * @param key     - 32-byte AES key (Buffer or base64url string).
 * @returns Decrypted UTF-8 plaintext.
 */
export function decryptAES(bundle: AESCipherBundle, key: Buffer | string): string {
  const keyBuf = typeof key === 'string' ? Buffer.from(key, 'base64url') : key;
  if (keyBuf.length !== AES_KEY_LENGTH) {
    throw new Error(`AES key must be ${AES_KEY_LENGTH} bytes; got ${keyBuf.length}`);
  }

  const iv         = Buffer.from(bundle.iv, 'base64url');
  const tag        = Buffer.from(bundle.tag, 'base64url');
  const ciphertext = Buffer.from(bundle.ciphertext, 'base64url');

  const decipher = createDecipheriv(AES_ALGORITHM, keyBuf, iv, { authTagLength: AES_TAG_LENGTH });
  decipher.setAuthTag(tag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

/**
 * Generate a cryptographically secure random 256-bit AES key.
 *
 * @returns Base64url-encoded 32-byte key.
 */
export function generateAESKey(): string {
  return randomBytes(AES_KEY_LENGTH).toString('base64url');
}

// ---------------------------------------------------------------------------
// PBKDF2  (password hashing / key wrapping)
// ---------------------------------------------------------------------------

/**
 * Derive a key from a password using PBKDF2-SHA256.
 *
 * Suitable for password hashing (store the full bundle) and for deriving
 * AES wrapping keys from passphrases.
 *
 * @param password    - Plaintext password / passphrase.
 * @param iterations  - Iteration count (default: 310,000).
 * @returns A {@link PBKDF2Bundle} containing salt, iterations, digest and derived key.
 */
export function derivePBKDF2(
  password: string,
  iterations = PBKDF2_ITERATIONS,
): PBKDF2Bundle {
  const salt = randomBytes(PBKDF2_SALT_LEN);
  const derivedKey = pbkdf2Sync(
    password,
    salt,
    iterations,
    PBKDF2_KEY_LEN,
    PBKDF2_DIGEST,
  );
  return {
    salt:       salt.toString('base64url'),
    iterations,
    digest:     PBKDF2_DIGEST,
    derivedKey: derivedKey.toString('base64url'),
  };
}

/**
 * Verify a plaintext password against a stored {@link PBKDF2Bundle}.
 *
 * Uses `timingSafeEqual` to prevent timing-side-channel attacks.
 *
 * @param password  - Plaintext password to verify.
 * @param bundle    - Previously stored PBKDF2 bundle.
 * @returns `true` if the password matches; `false` otherwise.
 */
export function verifyPBKDF2(password: string, bundle: PBKDF2Bundle): boolean {
  const salt = Buffer.from(bundle.salt, 'base64url');
  const derived = pbkdf2Sync(
    password,
    salt,
    bundle.iterations,
    PBKDF2_KEY_LEN,
    bundle.digest as Parameters<typeof pbkdf2Sync>[4],
  );
  const stored = Buffer.from(bundle.derivedKey, 'base64url');
  return derived.length === stored.length && timingSafeEqual(derived, stored);
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

/**
 * Compute an HMAC-SHA256 over `data` using `key`.
 *
 * @param data  - The message to authenticate (UTF-8 string or Buffer).
 * @param key   - The HMAC key (UTF-8 string or Buffer).
 * @returns Base64url-encoded HMAC-SHA256 digest.
 */
export function hmacSHA256(data: string | Buffer, key: string | Buffer): string {
  return createHmac(HMAC_DIGEST, key).update(data).digest('base64url');
}

/**
 * Verify an HMAC-SHA256 in constant time.
 *
 * @param data      - The original message.
 * @param key       - The HMAC key.
 * @param expected  - The base64url-encoded expected HMAC.
 * @returns `true` if the HMAC matches; `false` otherwise.
 */
export function verifyHMAC(
  data: string | Buffer,
  key: string | Buffer,
  expected: string,
): boolean {
  const computed = Buffer.from(hmacSHA256(data, key), 'base64url');
  const expectedBuf = Buffer.from(expected, 'base64url');
  return computed.length === expectedBuf.length && timingSafeEqual(computed, expectedBuf);
}

// ---------------------------------------------------------------------------
// Hash utilities
// ---------------------------------------------------------------------------

/**
 * Compute a SHA-256 hash of the input.
 *
 * @param input   - String or Buffer to hash.
 * @param encoding - Output encoding (default: 'hex').
 */
export function sha256(input: string | Buffer, encoding: 'hex' | 'base64url' = 'hex'): string {
  return createHash('sha256').update(input).digest(encoding);
}

/**
 * Compute a SHA-512 hash of the input.
 */
export function sha512(input: string | Buffer, encoding: 'hex' | 'base64url' = 'hex'): string {
  return createHash('sha512').update(input).digest(encoding);
}

// ---------------------------------------------------------------------------
// Secure random
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically secure random challenge string.
 * Used for WebAuthn and Ed25519 challenge-response flows.
 *
 * @returns Base64url-encoded random bytes ({@link CHALLENGE_BYTES} bytes = 256 bits).
 */
export function generateChallenge(): string {
  return randomBytes(CHALLENGE_BYTES).toString('base64url');
}

/**
 * Generate a cryptographically secure random UUID v4.
 */
export function generateSecureUUID(): string {
  const bytes = randomBytes(16);
  // Set version bits (v4)
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  // Set variant bits (RFC 4122)
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

/**
 * Generate a secure random token string of the given byte length.
 *
 * @param byteLength  - Number of random bytes (default: 32).
 * @returns Base64url-encoded random string.
 */
export function generateToken(byteLength = 32): string {
  return randomBytes(byteLength).toString('base64url');
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/**
 * Compare two strings in constant time to prevent timing attacks.
 *
 * @returns `true` if the strings are equal; `false` otherwise.
 */
export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    // Still perform comparison to avoid early-exit timing differences
    timingSafeEqual(bufA, Buffer.alloc(bufA.length));
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

// ---------------------------------------------------------------------------
// Aliases for cross-module compatibility
// ---------------------------------------------------------------------------

/**
 * Alias for `generateToken`. Generates base64url-encoded random bytes.
 * @param bytes - Number of random bytes (default: 32).
 */
export const randomB64 = generateToken;
