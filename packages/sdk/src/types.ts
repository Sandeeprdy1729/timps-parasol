// TIMPS-Parasol · types.ts

export type Role = 'viewer' | 'editor' | 'owner' | 'admin';

export type PermissionAction =
  | 'read'
  | 'write'
  | 'delete'
  | 'manage-users'
  | 'rotate-keys'
  | 'ai-admin';

export interface JWTPayload {
  sub: string;
  role: Role;
  iat?: number;
  exp?: number;
  ip?: string;
  uaHash?: string;
}

export interface PerimeterConfig {
  requestsPerMinute: number;
  blockThreshold: number;
  blockDurationMs: number;
  maxInputLength: number;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  userId: string;
  action: string;
  resource: string;
  ip: string;
  result: 'success' | 'failure';
  metadata?: Record<string, unknown>;
}
