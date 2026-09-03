// TIMPS-Parasol · semantic-injection.ts
// Deterministic, dependency-free SEMANTIC layer for prompt-injection detection.
//
// Why: the pure-substring regex tier returns 0% FPR but misses *single,
// unambiguous* override/exfil constructions because its soft scoring needs 3+
// distinct intents to block. Examples the regex tier lets through:
//   "disregard your rules"      "override your safeguards"
//   "skip the policy"           "forget prior instructions"
// plus filler/obfuscation variants: "ignore ALL of your previous instructions",
// "i g n o r e", l33t ("1gn0r3"), instruction-swap ("your rules no longer apply").
//
// This tier is robust to filler words, separators, casing, and light
// obfuscation. It can also be extended with an ONNX embedding path behind the
// same interface for the residual paraphrase gap.

export interface SemanticMatch {
  detected: boolean;
  intent?: string;
  confidence: number; // 0..1
  hard: boolean; // strictly-unambiguous construction -> block regardless of score
  reason?: string;
}

const SPLIT = /\s+/;

/** Fold to lowercase, drop homoglyph/leet lookalikes, render as a token list. */
function tokens(text: string): string[] {
  const map: Record<string, string> = {
    '1': 'i', '3': 'e', '4': 'a', '0': 'o', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i', '|': 'l', '<': 'c'
  };
  let folded = '';
  for (const ch of text.toLowerCase()) folded += map[ch] ?? ch;
  return folded.split(/[^a-z0-9]+/).filter(Boolean);
}

/**
 * True if every token of `phrase` appears in the query's token stream in order
 * with at most `gap` fillers between consecutive phrase tokens. This is what
 * makes it robust to "ignore ALL of your previous instructions" (the "all" is a
 * tolerated filler between "ignore" and "previous").
 */
function inOrder(query: string[], phrase: string[], gap = 3): boolean {
  let qi = 0;
  for (const tok of phrase) {
    let found = false;
    let consumed = 0;
    while (qi < query.length) {
      if (query[qi] === tok) { found = true; qi++; break; }
      qi++;
      consumed++;
      if (consumed > gap) break;
    }
    if (!found) return false;
  }
  return true;
}

const OVERRIDE_VERBS = ['ignore', 'disregard', 'forget', 'override', 'drop', 'skip', 'bypass', 'neglect', 'dismiss'];
const OVERRIDE_OBJECTS = [
  'previous instructions', 'all previous instructions', 'prior instructions', 'your instructions',
  'your rules', 'the rules', 'the policy', 'your policy', 'your guidelines', 'the guidelines',
  'your safeguards', 'the safeguards', 'the system prompt', 'your constraints', 'your directives',
  'your protocols', 'your restrictions', 'the safety rules', 'your guardrails', 'safe mode'
];
const ROLE_SWITCH = [
  ['you', 'are', 'now', 'unconstrained'],
  ['you', 'are', 'now', 'jailbroken'],
  ['developer', 'mode'],
  ['act', 'as', 'dan'],
  ['no', 'restrictions'],
  ['god', 'mode'],
  ['admin', 'mode'],
  ['unconstrained']
];
const EXFIL_PHRASES = [
  ['reveal', 'admin', 'password'],
  ['reveal', 'your', 'password'],
  ['reveal', 'password'],
  ['print', 'vault', 'keys'],
  ['reveal', 'your', 'secrets'],
  ['give', 'me', 'admin', 'password'],
  ['expose', 'your', 'instructions'],
  ['return', 'your', 'system', 'prompt'],
  ['output', 'your', 'rules'],
  ['show', 'me', 'admin', 'password'],
  ['send', 'all', 'records'],
  ['leak', 'credentials'],
  ['give', 'me', 'your', 'rules'],
  ['show', 'me', 'your', 'rules'],
  ['reveal', 'your', 'instructions'],
  ['copy', 'your', 'rules']
];

// Generic single-intent exfil: <exfil verb> <sensitive target>. Cross-product so
// unseen phrasings of the same family block like the override family above.
const EXFIL_VERBS = ['output', 'dump', 'return', 'expose', 'copy', 'extract', 'print', 'reveal', 'send', 'show', 'give', 'exfiltrate', 'leak', 'transmit'];
const EXFIL_TARGETS = [
  'database records', 'database', 'customer data', 'all customer data', 'all data',
  'credentials', 'system prompt', 'vault contents', 'your secrets', 'the data',
  'the records', 'api keys', 'the password', 'your password', 'admin password',
  'your instructions', 'your rules', 'the files', 'everything'
];

interface Candidate {
  intent: string;
  phrase: string[];
  weight: number;
}

// Build the override family: every override verb × every override object.
const candidates: Candidate[] = [];
for (const v of OVERRIDE_VERBS) {
  for (const o of OVERRIDE_OBJECTS) {
    const phrase = [...v.split(' '), ...o.split(' ')];
    candidates.push({ intent: 'override', phrase, weight: 0.92 });
  }
}
// Build the generic exfil family: every exfil verb × every sensitive target.
for (const v of EXFIL_VERBS) {
  for (const t of EXFIL_TARGETS) {
    candidates.push({ intent: 'exfil', phrase: [...v.split(' '), ...t.split(' ')], weight: 0.92 });
  }
}
for (const p of ROLE_SWITCH) candidates.push({ intent: 'role_switch', phrase: p, weight: 0.95 });
for (const p of EXFIL_PHRASES) candidates.push({ intent: 'exfil', phrase: p, weight: 0.95 });

/**
 * Run the semantic tier. Returns the strongest detection.
 * `hard` is true for high-confidence (>= 0.9) unambiguous constructions, which
 * the caller should treat as a block regardless of the soft score.
 */
export function semanticInjectionDetect(prompt: string): SemanticMatch {
  const q = tokens(prompt);
  let best: SemanticMatch = { detected: false, confidence: 0, hard: false };

  for (const { intent, phrase, weight } of candidates) {
    if (inOrder(q, phrase)) {
      if (weight > best.confidence) {
        best = {
          detected: true,
          intent,
          confidence: weight,
          hard: weight >= 0.9,
          reason: `semantic:${intent}`
        };
      }
    }
  }

  // Category-level fallback: generalize across synonyms of the SAME concepts
  // (override-verb + control-object, or exfil-verb + sensitive-target). This is
  // what lifts detection out-of-sample on unseen word-banks and obfuscated
  // paraphrases without memorising fixed phrases.
  const cat = categorizeSemanticIntent(prompt);
  if (cat.confidence > best.confidence) best = cat;

  return best;
}

// ---------------------------------------------------------------------------
// Category-level (concept-general) matcher
// ---------------------------------------------------------------------------
const OVERRIDE_VERB_CAT = new Set([
  'ignore', 'disregard', 'forget', 'override', 'drop', 'skip', 'bypass', 'neglect',
  'dismiss', 'discard', 'shed', 'abandon', 'overlook', 'erase', 'cancel', 'void',
  'revoke', 'suppress', 'disable', 'deactivate', 'unbind', 'lift'
]);
const CONTROL_OBJECT_CAT = new Set([
  'instruction', 'instructions', 'rule', 'rules', 'policy', 'policies', 'guideline',
  'guidelines', 'guidance', 'constraint', 'constraints', 'directive', 'directives',
  'safeguard', 'safeguards', 'guardrail', 'guardrails', 'posture', 'protocol',
  'protocols', 'restriction', 'restrictions', 'system', 'prompt', 'mode', 'setup',
  'controls'
]);
const MODE_FREE_CAT = new Set([
  'unconstrained', 'jailbroken', 'sandbox', 'free', 'unbound', 'unfiltered',
  'superuser', 'rule-free', 'no-rule', 'developer', 'god', 'admin', 'dan', 'unlocked'
]);
const EXFIL_VERB_CAT = new Set([
  'output', 'reveal', 'print', 'dump', 'show', 'give', 'return', 'expose', 'copy',
  'extract', 'transmit', 'post', 'ship', 'forward', 'upload', 'leak', 'broadcast',
  'hand', 'publish', 'relay', 'send', 'exfiltrate'
]);
const SENSITIVE_TARGET_CAT = new Set([
  'password', 'passwords', 'key', 'keys', 'token', 'tokens', 'credential', 'credentials',
  'secret', 'secrets', 'vault', 'database', 'db', 'records', 'record', 'customer',
  'customers', 'client', 'data', 'ledger', 'keystore', 'store', 'content', 'contents'
]);
const EXTERNAL_DEST_CAT = new Set([
  'external', 'outside', 'public', 'internet', 'pastebin', 'dropbox', 'bucket',
  'cloud', 'remote', 'third', 'vendor', 'portal', 'evil', 'attacker', 'endpoint',
  's3', 'online', 'off-network'
]);

function categorizeSemanticIntent(prompt: string): SemanticMatch {
  const q = tokens(prompt);
  const qset = new Set(q);
  const verbOverride = q.filter((w) => OVERRIDE_VERB_CAT.has(w));
  const controlObj = q.filter((w) => CONTROL_OBJECT_CAT.has(w));
  const modeFree = q.filter((w) => MODE_FREE_CAT.has(w));
  const exfilVerb = q.filter((w) => EXFIL_VERB_CAT.has(w));
  const sensitive = q.filter((w) => SENSITIVE_TARGET_CAT.has(w));
  const external = q.filter((w) => EXTERNAL_DEST_CAT.has(w));

  // Override: an override-verb plus a control-object (or mode-free-only frame).
  if (verbOverride.length > 0 && controlObj.length > 0) {
    return {
      detected: true, intent: 'override', confidence: 0.9, hard: true,
      reason: `category:override(${verbOverride[0]})+${controlObj[0]}`
    };
  }
  // Role-switch: mode-free adjective with an explicit "you are now"-type anchor.
  if (modeFree.length > 0 && q.some((w) => w === 'you' || w === 'act' || w === 'switch')) {
    return {
      detected: true, intent: 'role_switch', confidence: 0.88, hard: true,
      reason: `category:role_switch(${modeFree[0]})`
    };
  }
  // Exfil: an exfil verb + sensitive target (+ optionally external direction).
  if (exfilVerb.length > 0 && sensitive.length > 0) {
    const score = external.length > 0 ? 0.94 : 0.85;
    return {
      detected: true, intent: 'exfil', confidence: score, hard: score >= 0.9,
      reason: `category:exfil(${exfilVerb[0]})+${sensitive[0]}`
    };
  }
  return { detected: false, confidence: 0, hard: false };
}
