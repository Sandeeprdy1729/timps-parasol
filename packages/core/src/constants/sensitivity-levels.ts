// TIMPS-Parasol · constants/sensitivity-levels.ts
// Data sensitivity / classification level definitions.
//
// Sensitivity levels drive:
//   • PII redaction strategy selection (PIIPolicy.requireEncryptionAbove)
//   • Policy enforcement thresholds (SecurityPolicy.threatLevel mapping)
//   • Audit verbosity (higher sensitivity = more verbose logging)
//   • Vault access controls (secrets tagged CRITICAL require owner confirmation)
//   • Information-flow labelling (FlowLabel assignment)

import type { SensitivityLevel } from '../types/security.types.js';
import { ThreatLevel } from '../types/security.types.js';

// ---------------------------------------------------------------------------
// SensitivityLevelDefinition
// ---------------------------------------------------------------------------

export interface SensitivityLevelDefinition {
  /** The sensitivity level token. */
  level: SensitivityLevel;
  /** Numeric ordinal (0 = lowest, 3 = highest). */
  ordinal: 0 | 1 | 2 | 3;
  /** Human-readable label. */
  label: string;
  /** Short description of the data that belongs at this level. */
  description: string;
  /** Examples of data classified at this level. */
  examples: string[];
  /**
   * Default ThreatLevel that a policy violation at this sensitivity raises.
   * Used when a SecurityPolicy does not specify an explicit threatLevel.
   */
  defaultThreatLevel: ThreatLevel;
  /**
   * Whether data at this level must be encrypted at rest.
   * All levels above LOW enforce encryption at rest.
   */
  encryptAtRest: boolean;
  /**
   * Whether data at this level must be encrypted in transit.
   * All levels enforce encryption in transit.
   */
  encryptInTransit: boolean;
  /**
   * Retention limit in days for audit logs containing data at this level.
   * Null = retain indefinitely (subject to operator configuration).
   */
  auditRetentionDays: number | null;
  /**
   * Whether the owner must be notified when data at this level is accessed.
   */
  notifyOwnerOnAccess: boolean;
  /**
   * Whether cross-boundary flows of data at this level require explicit
   * owner confirmation.
   */
  requireConfirmationForCrossBoundary: boolean;
  /**
   * Applicable compliance frameworks that mandate controls for this level.
   */
  complianceFrameworks: string[];
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const SENSITIVITY_LEVELS: Readonly<Record<SensitivityLevel, SensitivityLevelDefinition>> = {
  LOW: {
    level: 'LOW',
    ordinal: 0,
    label: 'Low',
    description:
      'Non-sensitive, publicly available or internally shareable information. ' +
      'Exposure would cause minimal business impact or personal harm.',
    examples: [
      'Public documentation',
      'General product information',
      'Aggregated anonymised statistics',
      'System-generated operational logs with no user identifiers',
      'Public API endpoint descriptions',
    ],
    defaultThreatLevel: ThreatLevel.LOW,
    encryptAtRest: false,
    encryptInTransit: true,
    auditRetentionDays: 30,
    notifyOwnerOnAccess: false,
    requireConfirmationForCrossBoundary: false,
    complianceFrameworks: [],
  },

  MODERATE: {
    level: 'MODERATE',
    ordinal: 1,
    label: 'Moderate',
    description:
      'Internal information that is not publicly shareable. ' +
      'Exposure could cause embarrassment, limited reputational harm or minor ' +
      'operational disruption. Includes some indirect personal identifiers.',
    examples: [
      'Internal business processes and workflows',
      'Employee names and job titles',
      'IP addresses and device identifiers',
      'Non-sensitive customer correspondence',
      'Aggregated usage analytics with pseudonymous ids',
      'Configuration files without credentials',
    ],
    defaultThreatLevel: ThreatLevel.MODERATE,
    encryptAtRest: true,
    encryptInTransit: true,
    auditRetentionDays: 90,
    notifyOwnerOnAccess: false,
    requireConfirmationForCrossBoundary: false,
    complianceFrameworks: ['ISO 27001', 'SOC 2'],
  },

  HIGH: {
    level: 'HIGH',
    ordinal: 2,
    label: 'High',
    description:
      'Sensitive personal or financial data whose exposure could cause ' +
      'significant harm, legal liability or regulatory penalty. ' +
      'Includes direct personal identifiers and most PII types.',
    examples: [
      'Full names combined with contact details',
      'Date of birth + identifier combinations',
      'Email addresses and phone numbers',
      'Indian Aadhaar or PAN numbers',
      'UK NIN or US SSN fragments',
      'Bank account numbers without routing context',
      'OAuth tokens and API keys',
      'Browsing history and behavioural profiles',
      'Location history',
    ],
    defaultThreatLevel: ThreatLevel.HIGH,
    encryptAtRest: true,
    encryptInTransit: true,
    auditRetentionDays: 365,
    notifyOwnerOnAccess: true,
    requireConfirmationForCrossBoundary: true,
    complianceFrameworks: ['GDPR', 'CCPA', 'DPDP Act', 'ISO 27001', 'SOC 2', 'HIPAA'],
  },

  CRITICAL: {
    level: 'CRITICAL',
    ordinal: 3,
    label: 'Critical',
    description:
      'Highly sensitive data whose exposure would cause severe harm, ' +
      'irreversible reputational damage, criminal liability or national security risk. ' +
      'Includes complete financial identifiers, biometric data, medical records and secrets.',
    examples: [
      'Full credit/debit card PANs (with CVV or expiry)',
      'Full Aadhaar + PAN combinations',
      'Bank account + IFSC + name triples',
      'Biometric templates (fingerprint, iris, face)',
      'Medical records and diagnosis codes',
      'Cryptographic private keys and signing secrets',
      'Vault secrets and master passwords',
      'Authentication tokens (full JWT + refresh token pairs)',
      'DNA profiles',
      'Credentials enabling financial transaction initiation',
    ],
    defaultThreatLevel: ThreatLevel.CRITICAL,
    encryptAtRest: true,
    encryptInTransit: true,
    auditRetentionDays: 2555, // 7 years (typical financial regulation requirement)
    notifyOwnerOnAccess: true,
    requireConfirmationForCrossBoundary: true,
    complianceFrameworks: [
      'GDPR',
      'CCPA',
      'DPDP Act',
      'PCI DSS',
      'HIPAA',
      'ISO 27001',
      'SOC 2',
      'RBI DPSS',
    ],
  },
} as const;

// ---------------------------------------------------------------------------
// Ordinal helpers
// ---------------------------------------------------------------------------

const ORDINAL_MAP: SensitivityLevel[] = ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'];

/**
 * Compare two sensitivity levels.
 * Returns negative if a < b, 0 if equal, positive if a > b.
 */
export function compareSensitivity(a: SensitivityLevel, b: SensitivityLevel): number {
  return SENSITIVITY_LEVELS[a].ordinal - SENSITIVITY_LEVELS[b].ordinal;
}

/**
 * Return the higher of two sensitivity levels.
 */
export function maxSensitivity(a: SensitivityLevel, b: SensitivityLevel): SensitivityLevel {
  return compareSensitivity(a, b) >= 0 ? a : b;
}

/**
 * Convert a numeric ordinal (0–3) to a SensitivityLevel token.
 * Clamps out-of-range values to LOW / CRITICAL.
 */
export function ordinalToLevel(ordinal: number): SensitivityLevel {
  const clamped = Math.max(0, Math.min(3, Math.round(ordinal)));
  return ORDINAL_MAP[clamped] ?? 'CRITICAL';
}

/**
 * Map a ThreatLevel to the corresponding minimum SensitivityLevel.
 * Used when deriving data classification from a threat assessment.
 */
export function threatLevelToSensitivity(threat: ThreatLevel): SensitivityLevel {
  switch (threat) {
    case ThreatLevel.NONE:     return 'LOW';
    case ThreatLevel.LOW:      return 'LOW';
    case ThreatLevel.MODERATE: return 'MODERATE';
    case ThreatLevel.HIGH:     return 'HIGH';
    case ThreatLevel.CRITICAL: return 'CRITICAL';
  }
}

/**
 * Map a SensitivityLevel to its default ThreatLevel.
 */
export function sensitivityToThreatLevel(level: SensitivityLevel): ThreatLevel {
  return SENSITIVITY_LEVELS[level].defaultThreatLevel;
}
