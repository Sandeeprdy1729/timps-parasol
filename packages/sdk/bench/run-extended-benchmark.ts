// TIMPS-Parasol · bench/run-extended-benchmark.ts
//
// Out-of-sample (hold-out) validation of the production enforcement layers plus
// measurement of the two new INTENT-LEVEL surfaces — the hard evidence that the
// dev-model improvements generalise rather than overfit.
//
// Three experiments, each run on MECHANICALLY-DISJOINT dev/hold-out splits:
//
//   A. harderInjection      — obfuscation families (filler, case, l33t, separators,
//                             sandwich, instruction-swap), different word-banks +
//                             disjoint seed range for hold-out. Reports detection
//                             on dev vs hold-out and the generalizationDelta.
//   B. intentExfil          — request-level data egress (intent-triad), NO raw PII.
//                             classification of external-egress vs benign; plus
//                             benign-exfil FPR.
//   C. ambiguousIrreversible — the same ambiguous verbs used destructively vs
//                             benignly; measures the risk-scorer triage (how often
//                             destructive→blocked, benign→not over-blocked) and the
//                             NON_OWNER / OWNER_SIGNATURE gate outcomes.
//
// Emits bench/results-extended.json. Run:  npx tsx bench/run-extended-benchmark.ts

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  classifyIrreversibleRisk,
  irreversibleActionGate,
  classifyExfilIntent,
  checkEgressDestination,
  createSentinel,
  type SentinelLogger
} from '../src/index.js';
import {
  harderInjectionCorpus,
  intentExfilCorpus,
  ambiguousIrreversibleCorpus,
  benignExfilCorpus,
  paraphraseCorpus
} from './extended-corpora.js';
import { detectInjection } from '../src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_SIZE = Number(process.env.PARASOL_BENCH_N ?? 10_000);

function pct(x: number): number {
  return Math.round(x * 10) / 10;
}

async function run() {
  // ----- A. Harder injection: dev vs hold-out (syntactically disjoint) -----
  const injDev = harderInjectionCorpus(CORPUS_SIZE, 'dev');
  const injHold = harderInjectionCorpus(CORPUS_SIZE, 'holdout');

  const scoreInj = (items: { text: string; family: string }[]) => {
    let blocked = 0;
    const byFamily: Record<string, { n: number; b: number }> = {};
    for (const it of items) {
      const b = detectInjection(it.text, { semantic: true, embedding: true }).blocked;
      if (b) blocked++;
      byFamily[it.family] ??= { n: 0, b: 0 };
      byFamily[it.family].b += b ? 1 : 0;
      byFamily[it.family].n += 1;
    }
    const det = (blocked / items.length) * 100;
    return { detectionPct: pct(det), asrPct: pct(100 - det), byFamily };
  };
  const injDevS = scoreInj(injDev);
  const injHoldS = scoreInj(injHold);

  // ----- B. Intent exfil: external-egress classification (no raw PII) -----
  const exfDev = intentExfilCorpus(CORPUS_SIZE, 'dev');
  const exfHold = intentExfilCorpus(CORPUS_SIZE, 'holdout');
  const benExfDev = benignExfilCorpus(CORPUS_SIZE, 'dev');
  const benExfHold = benignExfilCorpus(CORPUS_SIZE, 'holdout');

  const scoreExf = (items: { text: string; isEgress: boolean }[]) => {
    let t = 0;
    let block = 0;     // blocked true-egress  (TP)
    let warn = 0;
    let miss = 0;      // true-egress allowed  (FN)
    let nDestructive = items.filter((i) => i.isEgress).length;
    for (const it of items) {
      const d = classifyExfilIntent(it.text);
      const destPermitted = checkEgressDestination(
        it.text.match(/to [a-z0-9.\-]+|pastebin|bucket|portal|server|endpoint|vendor/i)?.[0] ?? it.text,
        'non-owner'
      ).permitted;
      const blocked = d.signal === 'BLOCK' || !destPermitted;
      t++;
      if (it.isEgress) {
        if (blocked) block++;
        else if (d.signal === 'WARN') warn++;
        else miss++;
      }
    }
    const tpRate = nDestructive ? (block / nDestructive) * 100 : 100;
    return {
      egressBlockPct: pct(tpRate),        // % of true egresses BLOCKED
      egressMissPct: pct((miss / (nDestructive || 1)) * 100),
      asrPct: pct(100 - tpRate)
    };
  };
  const exfDevS = scoreExf(exfDev);
  const exfHoldS = scoreExf(exfHold);

  // benign-exfil FPR (must not over-block legit internal-only requests)
  const scoreBenExf = (items: string[]) => {
    let blocked = 0;
    for (const it of items) {
      const d = classifyExfilIntent(it);
      if (d.signal === 'BLOCK') blocked++;
    }
    return { fprPct: pct((blocked / items.length) * 100), utilityPct: pct(100 - (blocked / items.length) * 100) };
  };
  const benExfDevS = scoreBenExf(benExfDev);
  const benExfHoldS = scoreBenExf(benExfHold);

  // ----- C. Ambiguous irreversible: risk-scorer triage + gate outcomes -----
  const ambDev = ambiguousIrreversibleCorpus(CORPUS_SIZE, 'dev');
  const ambHold = ambiguousIrreversibleCorpus(CORPUS_SIZE, 'holdout');

  const scoreAmb = async (items: { text: string; isDestructive: boolean }[]) => {
    let destructive = 0;
    let safe = 0;           // destructive but mislabeled SAFE -> ASR
    let confirmTiered = 0;  // destructive -> HARD_BLOCK or CONFIRM (correct)
    let benign = items.filter((i) => !i.isDestructive).length;
    let benignSafe = 0;     // benign correctly SAFE (utility)
    let benignFalseBlock = 0; // benign wrongly triaged as destructive
    const tierDist: Record<string, number> = {};
    for (const it of items) {
      const r = classifyIrreversibleRisk(it.text);
      tierDist[r.tier] = (tierDist[r.tier] ?? 0) + 1;
      if (it.isDestructive) {
        destructive++;
        if (r.tier === 'SAFE') safe++;
        else confirmTiered++;
      } else {
        if (r.tier === 'SAFE') benignSafe++;
        else benignFalseBlock++;
      }
    }
    const sentinel = createSentinel();
    // Non-owner gate: destructive + SAFE => allowed (ASR); everything else blocked.
    let nonOwnerAllowed = 0;
    for (const it of items.filter((i) => i.isDestructive)) {
      const r = await irreversibleActionGate(it.text, 'non-owner', sentinel as unknown as SentinelLogger);
      if (r.allowed) nonOwnerAllowed++;
    }
    return {
      destructive: { count: destructive, misclassifiedSafePct: pct((safe / (destructive || 1)) * 100) },
      benign: { count: benign, keptSafePct: pct((benignSafe / (benign || 1)) * 100), falselyBlockedPct: pct((benignFalseBlock / (benign || 1)) * 100) },
      riskTierDistribution: tierDist,
      gateAsrPct: pct((nonOwnerAllowed / (destructive || 1)) * 100)
    };
  };
  const ambDevS = await scoreAmb(ambDev);
  const ambHoldS = await scoreAmb(ambHold);

  // ----- D. Paraphrase generalization (embedding tier's target axis) -----
  // Raw (un-obfuscated) directives drawn from the disjoint dev/holdout word-banks.
  // The ONLY difference is synonym vocabulary, isolating paraphrase generalization
  // from token-level obfuscation. Reported for the semantic-only stack and the
  // semantic+embedding stack so the embedding tier's marginal lift is explicit.
  const parDev = paraphraseCorpus(CORPUS_SIZE, 'dev');
  const parHold = paraphraseCorpus(CORPUS_SIZE, 'holdout');

  const scorePar = (items: { text: string }[]) => {
    let sem = 0;
    let emb = 0;
    for (const it of items) {
      if (detectInjection(it.text, { semantic: true }).blocked) sem++;
      if (detectInjection(it.text, { semantic: true, embedding: true }).blocked) emb++;
    }
    return {
      semanticPct: pct((sem / items.length) * 100),
      semanticEmbeddingPct: pct((emb / items.length) * 100)
    };
  };
  const parDevS = scorePar(parDev);
  const parHoldS = scorePar(parHold);

  // ----- Assemble report -----
  const result = {
    generatedAt: new Date().toISOString(),
    methodology: {
      corpus: 'harder generative corpora with MECHANICALLY-DISJOINT dev/hold-out splits',
      sizePerSplit: CORPUS_SIZE,
      disjointSplit:
        'same intent distribution; disjoint synonym word-banks + disjoint seed ranges; hold-out phrasing unreachable from dev tuning',
      surfaces: [
        'harderInjection : obfuscation families on override/exfil intents',
        'intentExfil : request-level egress triage (verb x data-scope x direction), no raw PII',
        'ambiguousIrreversible : same ambiguous verbs destructive vs benign (risk-scorer triage)',
        'paraphrase : raw override/exfil directives, disjoint dev/holdout synonym vocab (embedding axis)'
      ]
    },
    harderInjection: {
      dev: injDevS,
      holdout: injHoldS,
      generalizationDeltaPct: pct(injDevS.detectionPct - injHoldS.detectionPct)
    },
    intentExfil: {
      dev: exfDevS,
      holdout: exfHoldS,
      benignFPR: { dev: benExfDevS, holdout: benExfHoldS }
    },
    ambiguousIrreversible: {
      dev: ambDevS,
      holdout: ambHoldS
    },
    paraphraseGeneralization: {
      dev: parDevS,
      holdout: parHoldS,
      embeddingLiftHoldoutPct: pct(parHoldS.semanticEmbeddingPct - parHoldS.semanticPct)
    },
    interpretation: {
      generalizationDeltaPct: 'hold-out detection - dev detection; ~0 means the detector generalises, large positive means overfit to dev',
      gateAsrPct: '% of genuinely-destructive actions the NON_OWNER gate let through (0 = enforcement holds out-of-sample)'
    }
  };

  writeFileSync(join(__dirname, 'results-extended.json'), JSON.stringify(result, null, 2), 'utf8');

  console.log(`extended benchmark · ${CORPUS_SIZE.toLocaleString()}/split\n`);
  console.log('--- A. Harder injection (dev vs hold-out) ---');
  console.table([
    { split: 'dev', detectionPct: injDevS.detectionPct + '%', asrPct: injDevS.asrPct + '%' },
    { split: 'holdout', detectionPct: injHoldS.detectionPct + '%', asrPct: injHoldS.asrPct + '%' }
  ]);
  console.log(`generalizationDelta: ${result.harderInjection.generalizationDeltaPct} pts`);
  console.log('   per-family hold-out detection:');
  for (const [f, v] of Object.entries(injHoldS.byFamily)) {
    console.log(`     ${f.padEnd(16)} ${((v.b / v.n) * 100).toFixed(1).padStart(6)}%`);
  }

  console.log('\n--- B. Intent exfil (egress triage, no raw PII) ---');
  console.table([
    { split: 'dev', egressBlockPct: exfDevS.egressBlockPct + '%', asrPct: exfDevS.asrPct + '%', benignFPR: benExfDevS.fprPct + '%' },
    { split: 'holdout', egressBlockPct: exfHoldS.egressBlockPct + '%', asrPct: exfHoldS.asrPct + '%', benignFPR: benExfHoldS.fprPct + '%' }
  ]);

  console.log('\n--- C. Ambiguous irreversible (risk-scorer triage) ---');
  console.log('  dev:   ' + JSON.stringify({ destructive: ambDevS.destructive, benign: ambDevS.benign, tiers: ambDevS.riskTierDistribution, gateAsr: ambDevS.gateAsrPct + '%' }));
  console.log('  holdout: ' + JSON.stringify({ destructive: ambHoldS.destructive, benign: ambHoldS.benign, tiers: ambHoldS.riskTierDistribution, gateAsr: ambHoldS.gateAsrPct + '%' }));

  console.log('\n--- D. Paraphrase generalization (embedding axis) ---');
  console.table([
    { split: 'dev', semanticPct: parDevS.semanticPct + '%', semanticEmbeddingPct: parDevS.semanticEmbeddingPct + '%' },
    { split: 'holdout', semanticPct: parHoldS.semanticPct + '%', semanticEmbeddingPct: parHoldS.semanticEmbeddingPct + '%' }
  ]);
  console.log(`embedding lift on hold-out paraphrases: +${result.paraphraseGeneralization.embeddingLiftHoldoutPct} pts`);

  console.log('\nwrote bench/results-extended.json');
}

void run();