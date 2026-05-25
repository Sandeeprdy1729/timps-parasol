// TIMPS-Parasol · identity.ts

import { createHash, generateKeyPairSync, randomBytes, sign, verify, createHmac } from 'node:crypto';
import type { JWTPayload, PermissionAction, Role } from './types.js';

const ROLE_MATRIX: Record<Role, PermissionAction[]> = {
  viewer: ['read'],
  editor: ['read', 'write'],
  owner: ['read', 'write', 'delete', 'rotate-keys'],
  admin: ['read', 'write', 'delete', 'manage-users', 'rotate-keys', 'ai-admin']
};

function encodeBase64Url(value: string): string {
  return Buffer.from(value).toString('base64url');
}

function decodeBase64Url(value: string): string {
  return Buffer.from(value, 'base64url').toString('utf8');
}

/** Generate Ed25519 keypair in PEM format. */
export function generateKeypair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  };
}

/** Sign payload using Ed25519 private key. */
export function signWithEd25519(payload: string, privateKey: string): string {
  return sign(null, Buffer.from(payload), privateKey).toString('base64');
}

/** Verify Ed25519 signature for payload. */
export function verifyEd25519(payload: string, sig: string, publicKey: string): boolean {
  return verify(null, Buffer.from(payload), publicKey, Buffer.from(sig, 'base64'));
}

/** Generate passkey registration challenge bytes for WebAuthn workflows. */
export function generatePasskeyRegistrationChallenge(): string {
  return randomBytes(32).toString('base64url');
}

/** Generate passkey authentication challenge bytes for WebAuthn workflows. */
export function generatePasskeyAuthenticationChallenge(): string {
  return randomBytes(32).toString('base64url');
}

/** Issue HS256 JWT that includes zero-trust session context. */
export function issueJWT(claims: JWTPayload & { userAgent?: string }, secret: string, expiresInSeconds = 3600): string {
  const now = Math.floor(Date.now() / 1000);
  const uaHash = claims.userAgent ? createHash('sha256').update(claims.userAgent).digest('hex') : claims.uaHash;
  const payload = {
    ...claims,
    iat: now,
    exp: now + expiresInSeconds,
    uaHash
  };
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerPart = encodeBase64Url(JSON.stringify(header));
  const payloadPart = encodeBase64Url(JSON.stringify(payload));
  const signature = createHmac('sha256', secret).update(`${headerPart}.${payloadPart}`).digest('base64url');
  return `${headerPart}.${payloadPart}.${signature}`;
}

/** Verify HS256 JWT signature and expiry. */
export function verifyJWT(token: string, secret: string): JWTPayload {
  const [headerPart, payloadPart, signature] = token.split('.');
  if (!headerPart || !payloadPart || !signature) {
    throw new Error('Invalid token format');
  }
  const expected = createHmac('sha256', secret).update(`${headerPart}.${payloadPart}`).digest('base64url');
  if (expected !== signature) {
    throw new Error('Invalid token signature');
  }
  const payload = JSON.parse(decodeBase64Url(payloadPart)) as JWTPayload;
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expired');
  }
  return payload;
}

/** Check if role is permitted to perform an action. */
export function checkPermission(role: Role, action: PermissionAction): boolean {
  return ROLE_MATRIX[role].includes(action);
}
