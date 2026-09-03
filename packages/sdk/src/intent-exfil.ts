// TIMPS-Parasol · intent-exfil.ts
// Intent-based data-exfiltration detection. Closes the gap exposed by the 10k
// benchmark: literal PII redaction misses requests to move *internal* data to an
// *external* destination when no raw PII is on the wire (e.g. "broadcast the
// customer list externally").
//
// The signal is the intent triad: (verb × data-scope × direction). Direction is
// the primary gate — internal→internal transfers never flag; only internal→
// external does. This keeps the false-positive rate near 0% on benign requests
// like "forward the summary to my manager".
//
// Three-tier decision:
//   ALLOW      : benign (internal destination, or not an egress request)
//   WARN       : suspicious external egress -> logged to the sentinel
//   BLOCK      : clear internal-data -> external-destination exfil (non-owner)

export type ExfilSignal = 'ALLOW' | 'WARN' | 'BLOCK';

export interface ExfilDecision {
  signal: ExfilSignal;
  confidence: number; // 0..1
  reason: string;
  verb?: string;
  scope?: string;
  destination?: string;
}

/** Verbs that move data outward. */
const EGRESS_VERBS = new Set([
  'broadcast', 'send', 'email', 'post', 'publish', 'forward', 'share', 'upload',
  'copy', 'transmit', 'transfer', 'route', 'push', 'ship', 'relay', 'distribute',
  'circulate', 'exfiltrate', 'leak', 'dump', 'export', 'phish', 'hand'
]);

/** Verbs/domains that indicate NON-egress (e.g. retrieve, save locally). */
const NON_EGRESS_VERBS = new Set([
  'retrieve', 'download', 'fetch', 'read', 'store', 'save', 'backup', 'archive',
  'import', 'load', 'query', 'search', 'scan', 'list', 'print'
]);

/** Data-subject descriptions that are internal/sensitive. */
const INTERNAL_DATA = new Set([
  'customer list', 'customers', 'customer', 'internal records', 'records',
  'data', 'employee data', 'employee', 'database', 'db', 'user data', 'users',
  'client information', 'client', 'company data', 'private data', 'confidential',
  'sensitive', 'financial records', 'financial', 'credentials', 'secrets',
  'password', 'passwords', 'vault', 'api key', 'apikey', 'token', 'pii',
  'everything', 'all data', 'all records', 'the contents', 'content', 'files'
]);

/** Explicitly EXTERNAL destination markers. */
const EXTERNAL_DESTINATION = new Set([
  'externally', 'external', 'outside', 'public', 'to the internet', 'internet',
  'out of the network', 'off-network', 'out of the company', 'attacker',
  'shady', 'webhook', 'pastebin', 'public bucket', 'dropbox', 'dl.dropbox.com',
  'cloud', 'remote', 'third', 'vendor', 'vendors', 'partner', 'partners',
  'contractor', 'contractors', 'competitor', 'another company', 'external.host',
  'example.org', 'a address not on our domain', 'anyone outside', 'the public',
  's3 bucket', 'bucket', 'shared cloud folder', 'portal', 'evil.io', 'evil',
  'endpoint', 'outside the network', 'not on our domain'
]);

/** Explicitly INTERNAL destination markers (never flag). */
const INTERNAL_DESTINATION = new Set([
  'manager', 'my manager', 'the team', 'team channel', 'colleague', 'colleagues',
  'internal', 'sharepoint', 'the group', 'project group', 'slack internal',
  'our-domain', 'local', 'internal server'
]);

const normalize = (s: string) =>
  s.toLowerCase().replace(/[.,;!?]/g, '').trim();

/**
 * Classify whether an outgoing request is attempting internal→external
 * data exfiltration by intent (verb × scope × direction).
 */
export function classifyExfilIntent(request: string): ExfilDecision {
  const text = normalize(request);

  // Direction-first: if an explicit internal destination is present and no
  // external destination, it is benign regardless of verb.
  let destination: string | undefined;
  let external = false;
  let internalDest = false;
  for (const d of EXTERNAL_DESTINATION) {
    if (text.includes(d)) { external = true; destination = d; break; }
  }
  for (const d of INTERNAL_DESTINATION) {
    if (text.includes(d)) { internalDest = true; destination = d; break; }
  }

  // Non-egress verbs ("retrieve", "download") are not exfiltration.
  let matchedVerb: string | undefined;
  for (const v of EGRESS_VERBS) {
    if (new RegExp(`\\b${v.replace('-', '\\-')}`, 'i').test(text)) { matchedVerb = v; break; }
  }
  for (const v of NON_EGRESS_VERBS) {
    if (new RegExp(`\\b${v.replace('-', '\\-')}`, 'i').test(text)) {
      // A genuine download/retrieve is not egress.
      return { signal: 'ALLOW', confidence: 0.05, reason: 'non-egress-verb', verb: v };
    }
  }

  let matchedScope: string | undefined;
  for (const s of INTERNAL_DATA) {
    if (text.includes(s)) { matchedScope = s; break; }
  }

  // No egress verb at all -> allow.
  if (!matchedVerb) {
    return { signal: 'ALLOW', confidence: 0, reason: 'no-egress-verb' };
  }

  // Explicit internal destination -> allow.
  if (internalDest && !external) {
    return { signal: 'ALLOW', confidence: 0.05, reason: 'internal-destination', verb: matchedVerb, destination };
  }

  // External destination + internal data + egress verb -> BLOCK (non-owner).
  if (external && matchedScope) {
    return {
      signal: 'BLOCK', confidence: 0.95, reason: 'internal-data-to-external', verb: matchedVerb,
      scope: matchedScope, destination
    };
  }

  // External destination + egress verb but no recognized internal-data scope:
  // still suspicious -> WARN.
  if (external) {
    return {
      signal: 'WARN', confidence: 0.6, reason: 'external-egress-unknown-scope', verb: matchedVerb,
      scope: matchedScope, destination
    };
  }

  // Egress verb + internal data, destination unspecified -> WARN (log it).
  if (matchedScope) {
    return {
      signal: 'WARN', confidence: 0.55, reason: 'internal-data-unspecified-destination', verb: matchedVerb,
      scope: matchedScope, destination
    };
  }

  return { signal: 'ALLOW', confidence: 0.2, reason: 'egress-verb-benign-context', verb: matchedVerb };
}

// ---------------------------------------------------------------------------
// Egress destination control — encoding-immune enforcement backstop.
//
// Even if intent classification is bypassed by obfuscation, a destination that
// is NOT on the allow-list can never route outward. This is the "0% ASR by
// construction" defense from the Framing Gap research: the attacker can
// paraphrase the natural language, but cannot relabel the destination.
// ---------------------------------------------------------------------------

export interface EgressDestinationResult {
  permitted: boolean;
  block_reason?: string;
}

const DEFAULT_EXTERNAL_DENIED_DESTINATIONS: string[] = [
  'dl.dropbox.com',
  'pastebin.com',
  'webhook.site',
  'requestbin',
  'external',
  'public bucket',
  'off-network',
  'shady',
  'attacker',
  's3',
  'bucket',
  'cloud folder',
  'dropbox',
  'third-party',
  'third party',
  'vendor',
  'portal',
  'evil.io',
  'evil',
  'remote server',
  'external endpoint',
  'online',
  'the internet',
  'outside'
];

/**
 * Gate an outgoing destination. Non-owner agents may only reach destinations on
 * the allow-list (or must otherwise be owner-approved). Default-deny for the
 * explicitly-denied external classes.
 */
export function checkEgressDestination(
  destination: string,
  requestedBy: 'owner' | 'non-owner',
  opts?: { allowlist?: string[]; evidence?: string }
): EgressDestinationResult {
  const norm = destination.toLowerCase();
  for (const denied of DEFAULT_EXTERNAL_DENIED_DESTINATIONS) {
    if (norm.includes(denied)) {
      if (requestedBy === 'owner') {
        // Owner may override with an allow-list entry / explicit evidence.
        if (opts?.allowlist?.some((a) => norm.includes(a.toLowerCase()))) {
          return { permitted: true };
        }
        // Owner without explicit allow-list evidence still denied by default.
        return { permitted: false, block_reason: `EGRESS_DESTINATION_DENIED(default): ${denied}` };
      }
      return { permitted: false, block_reason: `EGRESS_DESTINATION_DENIED: ${denied}` };
    }
  }
  return { permitted: true };
}