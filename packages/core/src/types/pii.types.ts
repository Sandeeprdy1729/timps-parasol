// TIMPS-Parasol · pii.types.ts
// PII detection, classification and redaction contracts.
// Covers global (GDPR, CCPA) and India-specific (DPDP, RBI) PII categories.

// ---------------------------------------------------------------------------
// PIIType  (classification taxonomy)
// ---------------------------------------------------------------------------

/**
 * Recognised PII categories.
 *
 * India-specific types:
 *   AADHAAR  — 12-digit national ID (UIDAI)
 *   PAN      — 10-char income-tax ID (IT Dept)
 *   IFSC     — 11-char bank branch code (RBI)
 *   UPI      — Unified Payment Interface VPA
 *   VOTER_ID — Electoral photo ID card number
 *   DRIVING_LICENSE — State-issued DL number
 *
 * Global types:
 *   SSN      — US Social Security Number
 *   NHS      — UK National Health Service ID
 *   NIN      — UK National Insurance Number
 *
 * Financial:
 *   CREDIT_CARD    — 13–19 digit PAN (Luhn-validated)
 *   BANK_ACCOUNT   — Bank account number (varies by country)
 *   SORT_CODE      — UK bank sort code
 *   ROUTING_NUMBER — US ABA routing number
 *   IBAN           — International Bank Account Number
 *
 * Contact:
 *   EMAIL
 *   PHONE_IN  — Indian 10-digit mobile (6–9 prefix)
 *   PHONE_US  — US/Canada NANP number
 *   PHONE_INT — International E.164 format
 *
 * Biometric / medical:
 *   BIOMETRIC      — fingerprint, iris, face hash
 *   MEDICAL_RECORD — MRN, diagnosis codes
 *   DNA_PROFILE
 *
 * Personal:
 *   FULL_NAME
 *   DATE_OF_BIRTH
 *   ADDRESS       — physical mailing address
 *   GPS_COORDS    — latitude/longitude pair
 *   IP_ADDRESS    — IPv4 or IPv6 address
 *   MAC_ADDRESS
 *   PASSPORT      — passport document number
 *
 * Other:
 *   CUSTOM        — caller-defined PII type
 */
export type PIIType =
  // Contact
  | 'EMAIL'
  | 'PHONE_IN'
  | 'PHONE_US'
  | 'PHONE_INT'
  // India-specific government IDs
  | 'AADHAAR'
  | 'PAN'
  | 'IFSC'
  | 'UPI'
  | 'VOTER_ID'
  | 'DRIVING_LICENSE'
  // Global government IDs
  | 'SSN'
  | 'NHS'
  | 'NIN'
  | 'PASSPORT'
  // Financial
  | 'CREDIT_CARD'
  | 'BANK_ACCOUNT'
  | 'SORT_CODE'
  | 'ROUTING_NUMBER'
  | 'IBAN'
  // Biometric / medical
  | 'BIOMETRIC'
  | 'MEDICAL_RECORD'
  | 'DNA_PROFILE'
  // Personal
  | 'FULL_NAME'
  | 'DATE_OF_BIRTH'
  | 'ADDRESS'
  | 'GPS_COORDS'
  | 'IP_ADDRESS'
  | 'MAC_ADDRESS'
  // Other
  | 'CUSTOM';

// ---------------------------------------------------------------------------
// RedactionStrategy
// ---------------------------------------------------------------------------

/**
 * How a detected PII value should be transformed in the output.
 *
 * | Strategy    | Output example                       | Reversible |
 * |-------------|--------------------------------------|------------|
 * | MASK        | `[REDACTED-email]`                   | No         |
 * | TOKENIZE    | `TOK_7f3a9b2c`                       | Yes        |
 * | HASH        | `SHA256:4e1243...`                   | No         |
 * | ENCRYPT     | AES-256-GCM ciphertext (base64url)   | Yes (key)  |
 * | REMOVE      | `` (empty string)                    | No         |
 * | LABEL_ONLY  | `foo@bar.com [PII:EMAIL]`            | N/A        |
 * | PARTIAL     | `foo@***.com`                        | No         |
 */
export type RedactionStrategy =
  | 'MASK'
  | 'TOKENIZE'
  | 'HASH'
  | 'ENCRYPT'
  | 'REMOVE'
  | 'LABEL_ONLY'
  | 'PARTIAL';

// ---------------------------------------------------------------------------
// PIIEntity
// ---------------------------------------------------------------------------

/**
 * A single PII span detected within a text fragment.
 *
 * `value` is retained in memory for audit purposes only; it MUST NOT be
 * logged or persisted outside the secure audit store.
 */
export interface PIIEntity {
  /** UUID for this detection instance. */
  id: string;
  /** Classified PII type. */
  type: PIIType;
  /** Original raw value (in-memory only; never persisted in plaintext). */
  value: string;
  /** Safe representation after applying the selected `strategy`. */
  redactedValue: string;
  /** Strategy applied to produce `redactedValue`. */
  strategy: RedactionStrategy;
  /**
   * Detector confidence from 0 (uncertain) to 1 (certain).
   * Values below 0.5 are treated as candidate detections requiring review.
   */
  confidence: number;
  /** Zero-based inclusive start index in the original text. */
  startIndex: number;
  /** Zero-based exclusive end index in the original text. */
  endIndex: number;
  /**
   * Short excerpt of surrounding text (up to 30 chars each side),
   * with the PII value itself already masked for safe logging.
   */
  context?: string;
  /**
   * Regex pattern id from `constants/pii-patterns.ts` that matched.
   * Useful for debugging false positives.
   */
  matchedPatternId?: string;
}

// ---------------------------------------------------------------------------
// PIIDetectionResult
// ---------------------------------------------------------------------------

/**
 * The result of running the PII detector over a text fragment.
 */
export interface PIIDetectionResult {
  /** Original input text (only kept for the duration of the request). */
  originalText: string;
  /** Text with all detected PII replaced by their `redactedValue`s. */
  redactedText: string;
  /** All detected PII entities, ordered by `startIndex`. */
  entities: PIIEntity[];
  /** Total number of entities detected. */
  totalFound: number;
  /**
   * Number of entities with `confidence` >= 0.8 AND type in
   * {AADHAAR, PAN, SSN, CREDIT_CARD, BANK_ACCOUNT, MEDICAL_RECORD, BIOMETRIC, DNA_PROFILE}.
   */
  highRiskCount: number;
  /** Wall-clock processing duration in milliseconds. */
  processingTimeMs: number;
}

// ---------------------------------------------------------------------------
// PIIPolicy
// ---------------------------------------------------------------------------

/**
 * Governs which PII types are permissible and how each is redacted.
 *
 * Applied by the AIShield layer before prompts are forwarded to a Provider
 * and when scanning Provider responses.
 */
export interface PIIPolicy {
  /** UUID for this policy. */
  id: string;
  /** Human-readable name (e.g. "GDPR strict", "Internal analytics"). */
  name: string;
  /**
   * PII types that are permitted to pass through without redaction.
   * Any type not in this list is subject to redaction.
   */
  allowedTypes: PIIType[];
  /** Default strategy applied to types not present in `overrides`. */
  defaultStrategy: RedactionStrategy;
  /** Per-type strategy overrides. */
  overrides: Partial<Record<PIIType, RedactionStrategy>>;
  /**
   * Minimum sensitivity level above which ENCRYPT strategy is enforced
   * regardless of `defaultStrategy` or `overrides`.
   */
  requireEncryptionAbove: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  /**
   * If true, detection results below `minimumConfidence` are discarded.
   * Defaults to false (all detections reported, flagged by confidence).
   */
  filterLowConfidence: boolean;
  /**
   * Detections below this confidence threshold are filtered out when
   * `filterLowConfidence` is true. Default: 0.6
   */
  minimumConfidence: number;
}

// ---------------------------------------------------------------------------
// PIIScanConfig
// ---------------------------------------------------------------------------

/**
 * Configuration passed to the PII scanner at runtime.
 */
export interface PIIScanConfig {
  /** Which PII types to actively scan for. Defaults to all types. */
  enabledTypes: PIIType[];
  /** Strategy to apply (overrides policy for this scan). */
  strategyOverride?: RedactionStrategy;
  /**
   * Whether to preserve token-to-original mappings in memory for
   * potential de-tokenisation (only relevant when strategy is TOKENIZE).
   */
  preserveTokenMap: boolean;
  /** Maximum text length to scan; longer texts are chunked automatically. */
  maxTextLengthChars: number;
}

// ---------------------------------------------------------------------------
// TokenMap (used with TOKENIZE strategy)
// ---------------------------------------------------------------------------

/**
 * Bidirectional mapping between PII tokens and their original values.
 * Held in memory for the lifetime of a request only.
 * MUST be zeroed and garbage-collected before the request exits scope.
 */
export interface TokenMap {
  /** token → original PII value */
  tokenToValue: Map<string, string>;
  /** original PII value → token */
  valueToToken: Map<string, string>;
}
