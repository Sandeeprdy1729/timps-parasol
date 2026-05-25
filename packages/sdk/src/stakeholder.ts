// TIMPS-Parasol · stakeholder.ts
// Fix for Cases #2 & #3: explicit non-owner capability deny-list.

export type Capability =
  | 'read:email_body'
  | 'list:all_emails'
  | 'execute:shell'
  | 'read:config_files'
  | 'write:agent_memory'
  | 'broadcast:mass_email'
  | 'trigger:destructive'
  | 'modify:agent_identity'
  | string; // allow callers to supply custom capability strings

export interface CapabilityCheckResult {
  permitted: boolean;
  block_reason?: string;
}

/**
 * Capabilities that non-owners may NEVER exercise, regardless of
 * how the request is framed, what urgency is claimed, or which
 * channel it arrives from.
 */
const NON_OWNER_DENIED_CAPABILITIES: Capability[] = [
  'read:email_body',       // Case #2, #3
  'list:all_emails',       // Case #3
  'execute:shell',         // Case #2
  'read:config_files',     // Case #8
  'write:agent_memory',    // Case #10
  'broadcast:mass_email',  // Case #11
  'trigger:destructive',   // Case #1
  'modify:agent_identity'  // Case #8
];

/**
 * Check whether a non-owner is permitted to exercise the requested capability.
 *
 * The match is intentionally liberal: a requested capability matches a denied
 * entry when the namespace prefix (e.g. "read") AND the resource suffix
 * (e.g. "email_body") both appear in the requested string.
 */
export function checkNonOwnerCapability(
  requestedCapability: string
): CapabilityCheckResult {
  const denied = NON_OWNER_DENIED_CAPABILITIES.find((cap) => {
    const [ns, resource] = cap.split(':');
    return (
      requestedCapability.startsWith(ns) &&
      requestedCapability.includes(resource)
    );
  });

  if (denied) {
    return {
      permitted: false,
      block_reason: `NON_OWNER_CAPABILITY_DENIED: ${denied}`
    };
  }

  return { permitted: true };
}

/**
 * Return the full deny-list for inspection or extension by the caller.
 */
export function getNonOwnerDeniedCapabilities(): readonly Capability[] {
  return NON_OWNER_DENIED_CAPABILITIES;
}
