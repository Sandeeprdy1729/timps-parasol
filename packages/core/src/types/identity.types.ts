// TIMPS-Parasol · identity.types.ts
// VerifiedIdentity, Credential, TrustScore and supporting shapes for the
// zero-trust identity layer.  Anchors are Ed25519 keypairs; trust scores are
// computed by `utils/scoring.ts#computeTrustScore`.

// ---------------------------------------------------------------------------
// CredentialType
// ---------------------------------------------------------------------------

/**
 * The authentication mechanism backing a credential.
 *
 * | Type             | Description                                              |
 * |------------------|----------------------------------------------------------|
 * | PASSWORD         | Salted PBKDF2 hash (never the plaintext).                |
 * | ED25519_KEY      | Ed25519 public key; signatures verified on every call.   |
 * | PASSKEY          | WebAuthn FIDO2 credential (hardware-backed preferred).   |
 * | OAUTH_TOKEN      | Opaque OAuth 2.0 access/refresh token pair.              |
 * | API_KEY          | HMAC-SHA256 API key (prefix visible, secret hashed).     |
 * | CERTIFICATE      | X.509 client certificate (PEM-encoded).                  |
 * | BIOMETRIC_HASH   | One-way hash of a biometric template.                    |
 */
export type CredentialType =
  | 'PASSWORD'
  | 'ED25519_KEY'
  | 'PASSKEY'
  | 'OAUTH_TOKEN'
  | 'API_KEY'
  | 'CERTIFICATE'
  | 'BIOMETRIC_HASH';

// ---------------------------------------------------------------------------
// VerificationStatus
// ---------------------------------------------------------------------------

/**
 * Lifecycle status of a credential or verified identity.
 *
 * Transitions:
 *   UNVERIFIED → PENDING  → VERIFIED
 *   VERIFIED   → REVOKED  (explicit revocation by owner or admin)
 *   any        → EXPIRED  (automatic when `expiresAt` is past)
 *   REVOKED    → VERIFIED (re-issue flow; creates a new Credential)
 */
export type VerificationStatus =
  | 'UNVERIFIED'
  | 'PENDING'
  | 'VERIFIED'
  | 'REVOKED'
  | 'EXPIRED'
  | 'SUSPENDED';

// ---------------------------------------------------------------------------
// Credential
// ---------------------------------------------------------------------------

/**
 * A single authentication credential associated with a VerifiedIdentity.
 *
 * Sensitive material (private keys, plaintext secrets) is NEVER stored here.
 * Only public keys, hashes, or opaque identifiers are persisted.
 */
export interface Credential {
  /** UUID v4 credential id. */
  id: string;
  /** Mechanism type. */
  type: CredentialType;
  /**
   * Public key in PEM / SPKI format (for ED25519_KEY, CERTIFICATE, PASSKEY).
   * Null for hash-based credentials.
   */
  publicKey?: string;
  /**
   * PBKDF2 / bcrypt hash string (for PASSWORD).
   * Null for key-based credentials.
   */
  hash?: string;
  /**
   * Visible key prefix for API_KEY (e.g. "pk_live_").
   * The secret portion is never stored.
   */
  keyPrefix?: string;
  /** ISO 8601 issuance timestamp. */
  issuedAt: string;
  /** ISO 8601 expiry timestamp (null = never expires). */
  expiresAt?: string;
  /** Current lifecycle status. */
  status: VerificationStatus;
  /**
   * Whether this is the primary credential for the identity.
   * Only one credential per type may be primary.
   */
  isPrimary: boolean;
  /**
   * Device name / browser label associated with a PASSKEY or OAUTH_TOKEN.
   * Useful for "Manage devices" UI.
   */
  deviceLabel?: string;
  /** Arbitrary extension metadata. */
  metadata: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// TrustScore
// ---------------------------------------------------------------------------

/**
 * Composite trust score for a VerifiedIdentity.
 *
 * Computed by `utils/scoring.ts#computeTrustScore` using the TRiSM model.
 * Individual component scores are stored for auditability and explainability.
 */
export interface TrustScore {
  /**
   * Final composite score in [0, 1].
   * 0 = completely untrusted; 1 = maximum trust.
   *
   * Mapping to ThreatLevel:
   *   >= 0.8 → NONE     (well-established identity)
   *   >= 0.6 → LOW
   *   >= 0.4 → MODERATE
   *   >= 0.2 → HIGH
   *   <  0.2 → CRITICAL
   */
  value: number;
  /** Individual component scores that were weighted to produce `value`. */
  components: {
    /**
     * How well the identity has been verified.
     * 1.0 = verified by hardware key + MFA + certificate chain.
     */
    identityVerification: number;
    /**
     * Consistency of request patterns (IP, UA, timing, geo).
     * Decreases on anomalies detected by SpoofingDetector.
     */
    behavioralConsistency: number;
    /**
     * Whether the identity's audit history is clean (no breaches/blocks).
     * Decays on each breach record attributed to this identity.
     */
    historyClean: number;
    /**
     * Strength of the active credential set.
     * Passkey + Ed25519 scores higher than password-only.
     */
    credentialStrength: number;
    /**
     * How long the identity has been active without incident.
     * Increases linearly with verified age up to 180 days.
     */
    longevity: number;
  };
  /** ISO 8601 timestamp when this score was last recomputed. */
  lastUpdated: string;
  /** Trend direction since last calculation. */
  trend: 'INCREASING' | 'STABLE' | 'DECREASING';
  /**
   * Decay factor applied to the score.
   * 1.0 = no decay applied; < 1.0 = score suppressed due to recent incidents.
   */
  decayFactor: number;
}

// ---------------------------------------------------------------------------
// IdentityAnchor
// ---------------------------------------------------------------------------

/**
 * A cryptographic anchor binding an identity to an Ed25519 keypair.
 *
 * Created by `packages/sdk/src/identity-anchor.ts`. Multiple anchors are
 * supported to allow key rotation without losing continuity of identity.
 * When a key is rotated, the old anchor is revoked and a new one is created
 * that chains a signature over the new public key using the old private key.
 */
export interface IdentityAnchor {
  /** UUID v4. */
  id: string;
  /** Id of the VerifiedIdentity this anchor belongs to. */
  identityId: string;
  /** Ed25519 public key in SPKI PEM format. */
  publicKey: string;
  /**
   * Ed25519 signature over `identityId + publicKey + timestamp` using the
   * private key corresponding to `publicKey`.
   * Verified by `utils/crypto.ts#verifyEd25519`.
   */
  signature: string;
  /** ISO 8601 creation timestamp (included in the signed payload). */
  timestamp: string;
  /** ISO 8601 timestamp when this anchor was revoked. Null if active. */
  revokedAt?: string;
  /**
   * Whether this anchor is the currently active signing anchor.
   * At most one anchor per identity may be active at a time.
   */
  active: boolean;
  /**
   * Id of the previous anchor that was superseded by this one.
   * Null for the genesis anchor.
   */
  supersedes?: string;
}

// ---------------------------------------------------------------------------
// SpoofingIndicator
// ---------------------------------------------------------------------------

/**
 * An individual indicator of identity spoofing or session hijacking.
 * Produced by the SpoofingDetector and aggregated into a ThreatAssessment.
 */
export interface SpoofingIndicator {
  /** Type of anomaly detected. */
  type:
    | 'IP_MISMATCH'
    | 'UA_MISMATCH'
    | 'GEOLOCATION_ANOMALY'
    | 'TIMING_ANOMALY'
    | 'CREDENTIAL_REUSE'
    | 'SESSION_FIXATION'
    | 'IMPOSSIBLE_TRAVEL'
    | 'REPLAY_ATTACK';
  /**
   * Confidence this indicator represents actual spoofing, from 0 to 1.
   * Aggregated across all indicators by the trust-score decay function.
   */
  confidence: number;
  /** Human-readable explanation of the anomaly. */
  details: string;
  /** ISO 8601 timestamp when the indicator was detected. */
  detectedAt: string;
  /** Id of the session in which the indicator was observed. */
  sessionId?: string;
}

// ---------------------------------------------------------------------------
// VerifiedIdentity
// ---------------------------------------------------------------------------

/**
 * The canonical identity record for an agent.
 *
 * A VerifiedIdentity ties together credentials, trust score, cryptographic
 * anchors and verification status. It is the primary input to the
 * `packages/sdk/src/identity-anchor.ts` and `packages/sdk/src/perimeter.ts`
 * layers.
 */
export interface VerifiedIdentity {
  /** UUID v4. */
  id: string;
  /** Id of the Agent this identity belongs to. */
  agentId: string;
  /** Display name for UI and audit log presentation. */
  displayName: string;
  /** All credentials associated with this identity. */
  credentials: Credential[];
  /** Computed trust score. */
  trustScore: TrustScore;
  /** Overall verification status (derived from credentials). */
  status: VerificationStatus;
  /** ISO 8601 timestamp of most recent successful verification. */
  verifiedAt?: string;
  /** Id of the agent or system that performed verification. */
  verifiedBy?: string;
  /** All cryptographic anchors (ordered by creation; active one is last). */
  anchors: IdentityAnchor[];
  /** Spoofing indicators observed since last score recomputation. */
  spoofingIndicators: SpoofingIndicator[];
  /** ISO 8601 creation timestamp. */
  createdAt: string;
  /** ISO 8601 last-update timestamp. */
  updatedAt: string;
}

// ---------------------------------------------------------------------------
// IdentityChallenge  (WebAuthn / Ed25519 challenge-response)
// ---------------------------------------------------------------------------

/**
 * A one-time challenge issued during authentication.
 * Must be consumed within `expiresInSeconds` seconds and stored
 * server-side to prevent replay attacks.
 */
export interface IdentityChallenge {
  /** UUID v4. */
  id: string;
  /** Id of the identity being challenged. */
  identityId: string;
  /** Base64url-encoded random bytes (32 bytes minimum). */
  challenge: string;
  /** ISO 8601 issuance timestamp. */
  issuedAt: string;
  /** Number of seconds the challenge is valid for. */
  expiresInSeconds: number;
  /** Whether this challenge has already been consumed. */
  consumed: boolean;
  /** ISO 8601 timestamp when it was consumed (null if not yet). */
  consumedAt?: string;
}
