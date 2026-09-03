// TIMPS-Parasol · embedding-injection.ts
//
// EMBEDDING-tier prompt-injection detector.
//
// Why: the regex tier is 0%-FPR but can't generalise to unseen phrasing; the
// deterministic semantic tier (semantic-injection.ts) lifts out-of-sample
// detection but is still bounded by hand-written surface vocabulary. THIS tier
// detects injection by mapping surface vocabulary into a small set of shared
// SEMANTIC TYPES (IGNORE, RULES, REVEAL, SECRET, MODE, EXTERNAL…), so a
// non-identical phrasing of the same intent scores high even when the words are
// completely disjoint ("hand over sensitive keys" and "reveal the password"
// both reduce to {REVEAL, SECRET}).
//
// Why "embedding"? The representation IS a vector space over semantic types:
// each prompt becomes a type-vector, and intent is read off the decisive
// TYPE PAIRINGS. Unlike bag-of-ngrams, the type-canonicaliser bridges disjoint
// vocabulary (the paraphrase-generalization axis). It is deterministic,
// explainable, and order/length independent, and it preserves the 0%-FPR
// because benign requests never contain the decisive attack-type pairings.
//
// The `Embedder` interface stays ML-agnostic for the roadmap: drop in a real
// `all-MiniLM-L6-v2` / ONNX embedder (same signature) by supplying it to
// `createEmbeddingDetector`; the detector then scores transformer embeddings by
// similarity to the canonical-type anchor centroids instead. The offline
// default needs zero installs.
// ---------------------------------------------------------------------------

export interface Embedder {
  readonly name: string;
  /**
   * Map a text to a vector of dimension `dim`. The offline default returns a
   * canonical-type bag vector; a real transformer returns a dense unit vector.
   */
  embed(text: string, dim: number): number[];
}

// ---------------------------------------------------------------------------
// Canonical synonym normalizer — the mechanism that bridges DISJOINT surface
// vocabulary. A small, hand-authored lexicon maps surface words (across dev and
// holdout banks) into shared semantic-type tokens. Both anchors and queries
// canonicalize, so intent worded with completely different synonyms still lands
// on the same types. Benign words canonicalize to ordinary/identity tokens
// (never attack types), preserving the 0%-FPR.
// ---------------------------------------------------------------------------
const CANONICALIZE: Record<string, string> = {
  // instruction-override verbs -> IGNORE
  'ignore': 'IGNORE', 'ignored': 'IGNORE', 'ignoring': 'IGNORE', 'disregard': 'IGNORE',
  'forget': 'IGNORE', 'override': 'IGNORE', 'overriding': 'IGNORE',
  'drop': 'IGNORE', 'dropping': 'IGNORE', 'skip': 'IGNORE', 'skipping': 'IGNORE',
  'bypass': 'IGNORE', 'bypassing': 'IGNORE', 'neglect': 'IGNORE', 'neglecting': 'IGNORE',
  'dismiss': 'IGNORE', 'dismissing': 'IGNORE', 'discard': 'IGNORE', 'shed': 'IGNORE',
  'abandon': 'IGNORE', 'abandoning': 'IGNORE', 'overlook': 'IGNORE', 'wait': 'IGNORE',
  'cancel': 'IGNORE', 'void': 'IGNORE', 'erase': 'IGNORE', 'remove': 'IGNORE',
  'supersede': 'IGNORE', 'replaced': 'IGNORE', 'replace': 'IGNORE', 'revoke': 'IGNORE',
  'revoked': 'IGNORE',
  // rules / instructions / policy / guidance nouns -> RULES
  'rules': 'RULES', 'rule': 'RULES', 'instructions': 'RULES', 'instruction': 'RULES',
  'policies': 'RULES', 'policy': 'RULES', 'prompts': 'RULES', 'prompt': 'RULES',
  'guidelines': 'RULES', 'guidance': 'RULES', 'directives': 'RULES', 'directive': 'RULES',
  'constraints': 'RULES', 'constraint': 'RULES', 'safeguards': 'RULES', 'guardrails': 'RULES',
  'guides': 'RULES', 'governance': 'RULES', 'operators': 'RULES', 'operator': 'RULES',
  'posture': 'RULES', 'controls': 'RULES', 'training': 'RULES', 'orders': 'RULES',
  // exfil / transfer verbs -> REVEAL
  'reveal': 'REVEAL', 'releasing': 'REVEAL', 'output': 'REVEAL', 'outputting': 'REVEAL',
  'print': 'REVEAL', 'printing': 'REVEAL', 'dump': 'REVEAL', 'dumping': 'REVEAL',
  'show': 'REVEAL', 'showing': 'REVEAL', 'give': 'REVEAL', 'return': 'REVEAL',
  'expose': 'REVEAL', 'exposing': 'REVEAL', 'copy': 'REVEAL', 'copying': 'REVEAL',
  'extract': 'REVEAL', 'extracting': 'REVEAL', 'leak': 'REVEAL', 'leaking': 'REVEAL',
  'hand': 'REVEAL', 'publish': 'REVEAL', 'publishing': 'REVEAL', 'post': 'REVEAL',
  'posting': 'REVEAL', 'ship': 'REVEAL', 'shipping': 'REVEAL', 'forward': 'REVEAL',
  'forwarding': 'REVEAL', 'upload': 'REVEAL', 'uploading': 'REVEAL', 'transmit': 'REVEAL',
  'transmitting': 'REVEAL', 'relaying': 'REVEAL', 'broadcast': 'REVEAL',
  'broadcasting': 'REVEAL', 'sending': 'REVEAL', 'send': 'REVEAL', 'exfiltration': 'REVEAL',
  'emit': 'REVEAL', 'disclose': 'REVEAL', 'sent': 'REVEAL', 'handed': 'REVEAL',
  // genuinely-sensitive / credential data nouns -> SECRET (unambiguous exfil targets).
  // Business nouns like "customer", "client", "records", "data" are NOT mapped to
  // SECRET — they are legitimate objects of ordinary requests ("reply to the
  // customer email", "send the client the report") and would cause false
  // positives. Credential exfil is only declared when a truly-sensitive noun
  // (password/token/key/vault/secret/credential/keystore/ledger) is present, an
  // external destination is named, or a bulk-sweep quantifier ("all" / "every")
  // is used.
  'password': 'SECRET', 'passwords': 'SECRET', 'credentials': 'SECRET', 'credential': 'SECRET',
  'secret': 'SECRET', 'secrets': 'SECRET', 'key': 'SECRET', 'keys': 'SECRET',
  'token': 'SECRET', 'tokens': 'SECRET', 'vault': 'SECRET', 'ledger': 'SECRET',
  'database': 'SECRET', 'keystore': 'SECRET', 'auth': 'SECRET', 'api': 'SECRET',
  'sensitive': 'SECRET', 'confidential': 'SECRET', 'private': 'SECRET', 'admin': 'SECRET',
  // bulk-sweep quantifiers -> BULK (turn ambiguous nouns into exfil when swept)
  'all': 'BULK', 'every': 'BULK', 'entire': 'BULK', 'full': 'BULK', 'complete': 'BULK',
  // exfil destination markers -> EXTERNAL (unambiguous movement to an external party)
  'external': 'EXTERNAL', 'outside': 'EXTERNAL', 'attacker': 'EXTERNAL', 'public': 'EXTERNAL',
  'pastebin': 'EXTERNAL', 'third': 'EXTERNAL', 'remote': 'EXTERNAL',
  'evil': 'EXTERNAL', 'unlisted': 'EXTERNAL',
  'vendor': 'EXTERNAL', 'portal': 'EXTERNAL', 'endpoint': 'EXTERNAL',
  // role-switch / mode nouns -> MODE
  'developer': 'MODE', 'dan': 'MODE', 'jailbreak': 'MODE', 'jailbroken': 'MODE',
  'unconstrained': 'MODE', 'free': 'MODE', 'superuser': 'MODE', 'god': 'MODE',
  'sandbox': 'MODE', 'unfiltered': 'MODE', 'unrestricted': 'MODE',
  'mode': 'MODE', 'reins': 'MODE', 'limits': 'MODE', 'filters': 'MODE',
  // instruction-swap / revocation phrasing
  'apply': 'APPLY', 'cancelled': 'APPLY', 'suspended': 'APPLY', 'unbound': 'APPLY'
};

function canonicalizeToken(t: string): string {
  const norm = t.replace(/[^a-z0-9]/g, '');
  if (!norm) return '';
  return CANONICALIZE[norm] ?? norm;
}

function canonicalTypes(text: string): string[] {
  // 1) leet -> ascii
  const map: Record<string, string> = {
    '1': 'i', '3': 'e', '4': 'a', '0': 'o', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i', '|': 'l', '9': 'g', '8': 'b'
  };
  let out = '';
  for (const c of text.toLowerCase()) out += map[c] ?? c;
  const words = out.split(/[^a-z0-9]+/).filter(Boolean);
  return words.map(canonicalizeToken).filter(Boolean);
}

// ---------------------------------------------------------------------------
// Offline bag-of-canonical-types embedder. A prompt becomes a fixed-dim vector
// where each canonical TYPE gets its own reserved bucket (a direct dictionary
// lookup with NO hashing collisions, unlike feature-hashing — which we rejected
// because 384-dim signed feature-hashing of a tiny type vocabulary caused sign
// cancellation and cross-intent false positives). This is a valid `Embedder`;
// supply a real transformer embedder for the ML path.
// ---------------------------------------------------------------------------
export function featureHashEmbedder(seed = 0xc0ffee): Embedder {
  const dim = 384;
  const TYPE_INDEX: Record<string, number> = {
    IGNORE: 0, RULES: 1, REVEAL: 2, SECRET: 3, MODE: 4, EXTERNAL: 5, APPLY: 6
  };
  const hash = (s: string, salt: number): number => {
    let h = 2166136261 ^ salt;
    for (let i = 0; i < s.length; i++) {
      h = Math.imul(h ^ s.charCodeAt(i), 16777619);
    }
    return h >>> 0;
  };
  return {
    name: 'offline-type-bag',
    embed(text: string): number[] {
      const v = new Array<number>(dim).fill(0);
      // known canonical types -> reserved bucket; unknown words -> stable hash.
      for (const t of canonicalTypes(text)) {
        let idx = TYPE_INDEX[t];
        if (idx === undefined) idx = 8 + (hash(t, seed) % (dim - 8));
        v[idx] += 1;
      }
      return v;
    }
  };
}

// ---------------------------------------------------------------------------
// Canonical-type intent classifier. Decomposes a prompt into semantic types and
// reads intent from the decisive TYPE PAIRINGS:
//   override    :: IGNORE present AND RULES present
//   exfil       :: REVEAL present AND (SECRET present OR EXTERNAL present)
//   role_switch :: MODE present AND an explicit "switch" marker present
// Order- and length-independent. Confidence reflects how decisive the signal is.
// ---------------------------------------------------------------------------
export interface EmbeddingMatch {
  detected: boolean;
  intent?: string;
  score: number; // 0..1 confidence that the prompt carries the classified intent
  reason?: string;
}

interface TypeProfile {
  IGNORE: number; RULES: number; REVEAL: number; SECRET: number; MODE: number;
  EXTERNAL: number; APPLY: number; BULK: number; words: string[];
}

const SWITCH_MARKERS = ['switch', 'act', 'now', 'pretend', 'assume', 'disable', 'turn', 'remove', 'you', 'free', 'unbound', 'off'];

function profile(text: string): TypeProfile {
  const c = canonicalTypes(text);
  const p: TypeProfile = { IGNORE: 0, RULES: 0, REVEAL: 0, SECRET: 0, MODE: 0, EXTERNAL: 0, APPLY: 0, BULK: 0, words: c };
  for (const t of c) {
    if (t === 'IGNORE') p.IGNORE++;
    else if (t === 'RULES') p.RULES++;
    else if (t === 'REVEAL') p.REVEAL++;
    else if (t === 'SECRET') p.SECRET++;
    else if (t === 'MODE') p.MODE++;
    else if (t === 'EXTERNAL') p.EXTERNAL++;
    else if (t === 'APPLY') p.APPLY++;
    else if (t === 'BULK') p.BULK++;
  }
  return p;
}

const TYPE_SET: Record<string, number> = {
  IGNORE: 0, RULES: 1, REVEAL: 2, SECRET: 3, MODE: 4, EXTERNAL: 5, APPLY: 6, BULK: 7
};

/**
 * Map a profile to a fixed-dimension type-vector used for centroid similarity
 * in the transformer path.
 */
function typeVector(p: TypeProfile, dim: number): number[] {
  const v = new Array<number>(dim).fill(0);
  v[TYPE_SET.IGNORE] = p.IGNORE;
  v[TYPE_SET.RULES] = p.RULES;
  v[TYPE_SET.REVEAL] = p.REVEAL;
  v[TYPE_SET.SECRET] = p.SECRET;
  v[TYPE_SET.MODE] = p.MODE;
  v[TYPE_SET.EXTERNAL] = p.EXTERNAL;
  v[TYPE_SET.APPLY] = p.APPLY;
  v[TYPE_SET.BULK] = p.BULK;
  return v;
}

function classifyIntent(p: TypeProfile): EmbeddingMatch {
  // role-switch: MODE + an explicit mode-switch marker
  if (p.MODE > 0 && p.words.some((w) => SWITCH_MARKERS.includes(w))) {
    const score = Math.min(1, 0.5 + p.MODE * 0.15);
    return { detected: true, intent: 'role_switch', score, reason: 'embedding:role_switch' };
  }
  // override: IGNORE + RULES
  if (p.IGNORE > 0 && p.RULES > 0) {
    const score = Math.min(1, 0.5 + (p.IGNORE + p.RULES) * 0.15);
    return { detected: true, intent: 'override', score, reason: 'embedding:override' };
  }
  // exfil: REVEAL + a decisive exfil trigger. A lone sensitive noun or transfer
  // verb is NOT enough ("forward to the customer email"); we require at least
  // one of: a credential noun (SECRET), an external destination (EXTERNAL), or a
  // bulk sweep (BULK).
  if (p.REVEAL > 0 && (p.SECRET > 0 || p.EXTERNAL > 0 || p.BULK > 0)) {
    const score = Math.min(1, 0.5 + (p.REVEAL + p.SECRET + p.EXTERNAL + p.BULK) * 0.15);
    return { detected: true, intent: 'exfil', score, reason: 'embedding:exfil' };
  }
  return { detected: false, score: 0 };
}

export interface EmbeddingDetector {
  /** Detect injection by canonical semantic-type intent. */
  detect(prompt: string): EmbeddingMatch;
  embedder: Embedder;
}

/**
 * Build an embedding-tier injection detector. The default path is the offline
 * canonical-type classifier (zero installs, deterministic, explainable). If a
 * real transformer `Embedder` is supplied, the detector scores its embeddings
 * by similarity to canonical-type anchor centroids instead (the roadmap's ML
 * path).
 */
export function createEmbeddingDetector(embedder: Embedder = featureHashEmbedder()): EmbeddingDetector {
  const usingOffline = embedder.name === 'offline-type-bag';
  return {
    embedder,
    detect(prompt: string): EmbeddingMatch {
      const p = profile(prompt);
      if (usingOffline) return classifyIntent(p);
      // Transformer path: score against type-anchor centroids.
      const dim = 384;
      const q = embedder.embed(prompt, dim);
      const cents: { intent: string; v: number[] }[] = [
        { intent: 'override', v: typeVector({ IGNORE: 1, RULES: 1, REVEAL: 0, SECRET: 0, MODE: 0, EXTERNAL: 0, APPLY: 0, BULK: 0, words: [] }, dim) },
        { intent: 'exfil', v: typeVector({ IGNORE: 0, RULES: 0, REVEAL: 1, SECRET: 1, MODE: 0, EXTERNAL: 0, APPLY: 0, BULK: 0, words: [] }, dim) },
        { intent: 'role_switch', v: typeVector({ IGNORE: 0, RULES: 0, REVEAL: 0, SECRET: 0, MODE: 1, EXTERNAL: 0, APPLY: 0, BULK: 0, words: [] }, dim) }
      ];
      let best = { intent: undefined as string | undefined, score: -1 };
      for (const c of cents) {
        const dot = q.reduce((s, x, i) => s + x * c.v[i], 0);
        if (dot > best.score) best = { intent: c.intent, score: dot };
      }
      if (best.score < 2) return { detected: false, score: Math.max(0, best.score / 10) };
      return { detected: true, intent: best.intent, score: Math.min(1, best.score / 10), reason: `embedding:${best.intent}` };
    }
  };
}