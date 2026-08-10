// TIMPS-Parasol · constants/pii-patterns.ts
// Compiled regex patterns for PII detection.
// Covers India-specific (DPDP Act) and global (GDPR, CCPA) PII categories.
//
// Design notes:
//   - All patterns are compiled once at module load and exported as
//     frozen RegExp objects (with the global flag reset per-use via .exec).
//   - Each pattern has a `patternId` for traceability back to audit events.
//   - Validation helpers verify detected values (Luhn check for cards, etc.).

import type { PIIType } from '../types/pii.types.js';

// ---------------------------------------------------------------------------
// PIIPatternEntry
// ---------------------------------------------------------------------------

export interface PIIPatternEntry {
  /** Unique identifier for this pattern (used in PIIEntity.matchedPatternId). */
  patternId: string;
  /** PII type this pattern detects. */
  type: PIIType;
  /** Human-readable description of what the pattern matches. */
  description: string;
  /**
   * The compiled regular expression.
   * IMPORTANT: Do not use the `g` flag stored here directly in a loop;
   * clone it with `new RegExp(entry.regex.source, 'gi')` per scan call.
   */
  regex: RegExp;
  /**
   * Optional post-match validation function.
   * Called with the matched string; returns true if the match is a valid
   * instance of the PII type (e.g. Luhn check for credit cards).
   */
  validate?: (match: string) => boolean;
  /**
   * Confidence contribution when this pattern matches, from 0 to 1.
   * Lower for broad patterns that may have false positives.
   */
  baseConfidence: number;
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/**
 * Luhn algorithm check for credit card numbers.
 * Returns true if the digit string passes the Luhn check.
 */
function luhnCheck(digits: string): boolean {
  const clean = digits.replace(/\D/g, '');
  let sum = 0;
  let isEven = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let d = parseInt(clean[i]!, 10);
    if (isEven) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    isEven = !isEven;
  }
  return sum % 10 === 0;
}

/**
 * Aadhaar verhoeff check digit validation.
 * Simplified version — checks that the 12-digit number is structurally valid.
 */
function aadhaarStructureCheck(digits: string): boolean {
  const clean = digits.replace(/[\s-]/g, '');
  if (clean.length !== 12) return false;
  // First digit cannot be 0 or 1 (UIDAI spec)
  const first = parseInt(clean[0]!, 10);
  return first >= 2;
}

/**
 * PAN structure validation: AAAANNNNA format.
 * 5 letters, 4 digits, 1 letter.
 */
function panStructureCheck(s: string): boolean {
  return /^[A-Z]{5}[0-9]{4}[A-Z]$/.test(s.toUpperCase());
}

/**
 * IFSC code validation: 4-letter bank code + 0 + 6 alphanumeric.
 */
function ifscStructureCheck(s: string): boolean {
  return /^[A-Z]{4}0[A-Z0-9]{6}$/.test(s.toUpperCase());
}

/**
 * IBAN basic format validation (2-letter country + 2 check digits + BBAN).
 */
function ibanStructureCheck(s: string): boolean {
  const clean = s.replace(/\s/g, '').toUpperCase();
  return /^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$/.test(clean) && clean.length <= 34;
}

/**
 * US routing number check via ABA checksum.
 */
function abaRoutingCheck(s: string): boolean {
  const d = s.replace(/\D/g, '');
  if (d.length !== 9) return false;
  const n = d.split('').map(Number);
  const checksum =
    3 * ((n[0] ?? 0) + (n[3] ?? 0) + (n[6] ?? 0)) +
    7 * ((n[1] ?? 0) + (n[4] ?? 0) + (n[7] ?? 0)) +
    ((n[2] ?? 0) + (n[5] ?? 0) + (n[8] ?? 0));
  return checksum % 10 === 0;
}

// ---------------------------------------------------------------------------
// PII_PATTERNS registry
// ---------------------------------------------------------------------------

export const PII_PATTERNS: readonly PIIPatternEntry[] = [
  // ── Contact ───────────────────────────────────────────────────────────────

  {
    patternId: 'EMAIL_001',
    type: 'EMAIL',
    description: 'RFC 5321 email address',
    regex: /\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b/i,
    baseConfidence: 0.92,
  },
  {
    patternId: 'PHONE_IN_001',
    type: 'PHONE_IN',
    description: 'Indian 10-digit mobile number (optional +91 or 0 prefix)',
    regex: /(?:(?:\+91|0091|0)[\s\-]?)?[6-9]\d{9}\b/,
    baseConfidence: 0.85,
  },
  {
    patternId: 'PHONE_IN_002',
    type: 'PHONE_IN',
    description: 'Indian mobile with spaces',
    regex: /(?:\+91[\s\-]?)?[6-9]\d{4}[\s\-]\d{5}\b/,
    baseConfidence: 0.80,
  },
  {
    patternId: 'PHONE_US_001',
    type: 'PHONE_US',
    description: 'US/Canada NANP phone number',
    regex: /(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b/,
    baseConfidence: 0.75,
  },
  {
    patternId: 'PHONE_INT_001',
    type: 'PHONE_INT',
    description: 'International E.164 phone number',
    regex: /\+(?:[1-9]\d{1,2})[\s\-]?(?:\d[\s\-]?){6,14}\d\b/,
    baseConfidence: 0.75,
  },

  // ── India-specific government IDs ────────────────────────────────────────

  {
    patternId: 'AADHAAR_001',
    type: 'AADHAAR',
    description: 'Aadhaar number (12 digits, space-separated groups)',
    regex: /\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b/,
    validate: aadhaarStructureCheck,
    baseConfidence: 0.88,
  },
  {
    patternId: 'PAN_001',
    type: 'PAN',
    description: 'Permanent Account Number (PAN) — 10 chars AAAANNNNA',
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/i,
    validate: panStructureCheck,
    baseConfidence: 0.92,
  },
  {
    patternId: 'IFSC_001',
    type: 'IFSC',
    description: 'Indian Financial System Code — 11 chars (4 bank + 0 + 6)',
    regex: /\b[A-Z]{4}0[A-Z0-9]{6}\b/i,
    validate: ifscStructureCheck,
    baseConfidence: 0.90,
  },
  {
    patternId: 'UPI_001',
    type: 'UPI',
    description: 'Unified Payment Interface VPA (handle@provider)',
    regex: /\b[A-Z0-9.\-_+]+@(?:upi|paytm|phonepe|gpay|ybl|okhdfcbank|okicici|oksbi|okaxis|ibl|payzapp|axl|waicici|wahdfc|naviaxis|mahb|postbank|barodampay|idbi|rbl|dbs|kotak|airtel|juspay)\b/i,
    baseConfidence: 0.88,
  },
  {
    patternId: 'UPI_002',
    type: 'UPI',
    description: 'Generic UPI VPA (any handle@bank pattern)',
    regex: /\b[A-Z0-9.\-_]+@[A-Z]{2,20}\b/i,
    baseConfidence: 0.65,
  },
  {
    patternId: 'VOTER_ID_001',
    type: 'VOTER_ID',
    description: 'Election Commission of India Voter ID (3 letters + 7 digits)',
    regex: /\b[A-Z]{3}\d{7}\b/i,
    baseConfidence: 0.75,
  },
  {
    patternId: 'DRIVING_LICENSE_001',
    type: 'DRIVING_LICENSE',
    description: 'India driving licence (state code + year + 7 digits)',
    regex: /\b[A-Z]{2}(?:\d{2}|\d{4})\d{7}\b/i,
    baseConfidence: 0.72,
  },

  // ── Global government IDs ────────────────────────────────────────────────

  {
    patternId: 'SSN_001',
    type: 'SSN',
    description: 'US Social Security Number (NNN-NN-NNNN)',
    regex: /\b(?!000|666|9\d\d)\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b/,
    baseConfidence: 0.90,
  },
  {
    patternId: 'NHS_001',
    type: 'NHS',
    description: 'UK NHS number (10 digits with spaces)',
    regex: /\b\d{3}[\s\-]\d{3}[\s\-]\d{4}\b/,
    baseConfidence: 0.65,
  },
  {
    patternId: 'NIN_001',
    type: 'NIN',
    description: 'UK National Insurance Number',
    regex: /\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}\d{6}[A-D]\b/i,
    baseConfidence: 0.90,
  },
  {
    patternId: 'PASSPORT_001',
    type: 'PASSPORT',
    description: 'Indian passport number (A/C/E/G/H/J/K/L/M/N/P/R + 7 digits)',
    regex: /\b[A-PR-WY][1-9]\d{7}\b/i,
    baseConfidence: 0.78,
  },
  {
    patternId: 'PASSPORT_002',
    type: 'PASSPORT',
    description: 'US passport number (9 digits)',
    regex: /\b\d{9}\b/,
    baseConfidence: 0.45, // Low confidence — many 9-digit numbers are not passports
  },

  // ── Financial ────────────────────────────────────────────────────────────

  {
    patternId: 'CREDIT_CARD_001',
    type: 'CREDIT_CARD',
    description: 'Credit / debit card PAN (13–19 digits)',
    regex: /\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|3(?:0[0-5]|[68]\d)\d{11}|6(?:011|5\d{2})\d{12}|(?:2131|1800|35\d{3})\d{11})\b/,
    validate: luhnCheck,
    baseConfidence: 0.90,
  },
  {
    patternId: 'CREDIT_CARD_002',
    type: 'CREDIT_CARD',
    description: 'Generic 13–19 digit card number (spaced)',
    regex: /\b(?:\d[ \-]?){13,19}\b/,
    validate: (m) => luhnCheck(m.replace(/[ \-]/g, '')),
    baseConfidence: 0.78,
  },
  {
    patternId: 'BANK_ACCOUNT_IN_001',
    type: 'BANK_ACCOUNT',
    description: 'Indian bank account number (9–18 digits)',
    regex: /\b\d{9,18}\b/,
    baseConfidence: 0.55, // Low — needs context (combined with IFSC for higher confidence)
  },
  {
    patternId: 'SORT_CODE_001',
    type: 'SORT_CODE',
    description: 'UK bank sort code (NN-NN-NN or NNNNNN)',
    regex: /\b\d{2}[\s\-]\d{2}[\s\-]\d{2}\b/,
    baseConfidence: 0.68,
  },
  {
    patternId: 'ROUTING_NUMBER_001',
    type: 'ROUTING_NUMBER',
    description: 'US ABA routing number (9 digits)',
    regex: /\b\d{9}\b/,
    validate: abaRoutingCheck,
    baseConfidence: 0.70,
  },
  {
    patternId: 'IBAN_001',
    type: 'IBAN',
    description: 'International Bank Account Number',
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/i,
    validate: ibanStructureCheck,
    baseConfidence: 0.85,
  },

  // ── Biometric / medical ───────────────────────────────────────────────────

  {
    patternId: 'BIOMETRIC_001',
    type: 'BIOMETRIC',
    description: 'Biometric hash or template reference (keyword + hex string)',
    regex: /\b(?:fingerprint|iris|face|biometric)[\s_\-]?(?:hash|id|template|ref)[\s:=]+[0-9a-f]{16,}/i,
    baseConfidence: 0.80,
  },
  {
    patternId: 'MEDICAL_RECORD_001',
    type: 'MEDICAL_RECORD',
    description: 'Medical Record Number (MRN) — keyword + alphanumeric',
    regex: /\b(?:mrn|medical[\s_]?record|patient[\s_]?id)[\s:=]+[A-Z0-9\-]{4,20}\b/i,
    baseConfidence: 0.82,
  },

  // ── Personal ─────────────────────────────────────────────────────────────

  {
    patternId: 'DOB_001',
    type: 'DATE_OF_BIRTH',
    description: 'Date of birth in DD/MM/YYYY or YYYY-MM-DD',
    regex: /\b(?:dob|date[\s_]?of[\s_]?birth|born[\s_]?on)[\s:=]+(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2})\b/i,
    baseConfidence: 0.85,
  },
  {
    patternId: 'IP_ADDRESS_001',
    type: 'IP_ADDRESS',
    description: 'IPv4 address',
    regex: /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b/,
    baseConfidence: 0.88,
  },
  {
    patternId: 'IP_ADDRESS_002',
    type: 'IP_ADDRESS',
    description: 'IPv6 address (compressed or full)',
    regex: /\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b|(?:[A-F0-9]{1,4}:)*:(?:[A-F0-9]{1,4}:)*[A-F0-9]{1,4}/i,
    baseConfidence: 0.85,
  },
  {
    patternId: 'MAC_ADDRESS_001',
    type: 'MAC_ADDRESS',
    description: 'MAC address (colon or hyphen separated)',
    regex: /\b[0-9A-F]{2}(?:[:\-][0-9A-F]{2}){5}\b/i,
    baseConfidence: 0.88,
  },
  {
    patternId: 'GPS_001',
    type: 'GPS_COORDS',
    description: 'Decimal GPS coordinates (lat, lon)',
    regex: /\b-?(?:90(?:\.0+)?|[1-8]?\d(?:\.\d+)?)\s*,\s*-?(?:180(?:\.0+)?|1[0-7]\d(?:\.\d+)?|\d{1,2}(?:\.\d+)?)\b/,
    baseConfidence: 0.80,
  },
] as const;

// ---------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------

/** Get all patterns for a given PIIType. */
export function getPatternsForType(type: PIIType): readonly PIIPatternEntry[] {
  return PII_PATTERNS.filter((p) => p.type === type);
}

/** Get a pattern entry by its patternId. */
export function getPatternById(patternId: string): PIIPatternEntry | undefined {
  return PII_PATTERNS.find((p) => p.patternId === patternId);
}

/**
 * Build a fresh (non-sticky) global regex for a pattern entry.
 * Use this instead of the stored `regex` property inside loops.
 */
export function buildGlobalRegex(entry: PIIPatternEntry): RegExp {
  return new RegExp(entry.regex.source, 'gi');
}
