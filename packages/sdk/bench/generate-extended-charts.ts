// TIMPS-Parasol · bench/generate-extended-charts.ts
//
// Reads bench/results-extended.json (dev/hold-out validation of the production
// enforcement layers) and emits SVG charts for the blog's accountability section.
//
// Emits into docs/:
//   bench-holdout-injection.svg          — harder-injection detection: dev vs hold-out
//   bench-holdout-exfil.svg              — intent-exfil egress-block: dev vs hold-out
//   bench-holdout-irreversible.svg       — ambiguous irreversible: gate ASR + benign utility
//   bench-holdout-paraphrase.svg         — paraphrase generalization: embedding-tier lift

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const r = JSON.parse(readFileSync(join(__dirname, 'results-extended.json'), 'utf8'));
const outDir = join(__dirname, '..', '..', '..', 'docs');
mkdirSync(outDir, { recursive: true });

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// A simple two-bar (dev vs hold-out) horizontal chart.
function splitBarChart(title: string, subtitle: string, dev: number, hold: number, unit: string): string {
  const W = 760, H = 210, padL = 130, padR = 70, padT = 78, padB = 30;
  const chartW = W - padL - padR, chartH = H - padT - padB;
  const max = Math.max(dev, hold, 100);
  const rows = [
    { label: 'Dev corpus', value: dev, color: '#38bdf8' },
    { label: 'Hold-out', value: hold, color: '#f59e0b' }
  ];
  const rowH = chartH / rows.length, barH = rowH * 0.5;
  let body = '';
  rows.forEach((r, i) => {
    const y = padT + i * rowH + (rowH - barH) / 2;
    const w = (r.value / max) * chartW;
    body += `<rect x="${padL}" y="${y}" width="${w}" height="${barH}" rx="4" fill="${r.color}"/>`;
    body += `<text x="${padL + w + 8}" y="${y + barH / 2 + 5}" font-size="14" fill="#e2e8f0">${r.value}${unit}</text>`;
    body += `<text x="${padL - 10}" y="${y + barH / 2 + 5}" font-size="14" text-anchor="end" fill="#94a3b8">${esc(r.label)}</text>`;
  });
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
  <rect width="${W}" height="${H}" fill="#0f172a"/>
  <text x="${padL}" y="34" font-size="18" font-weight="700" fill="#f8fafc">${esc(title)}</text>
  <text x="${padL}" y="56" font-size="12" fill="#64748b">${esc(subtitle)}</text>
  ${body}
</svg>`;
}

function write(name: string, svg: string) {
  writeFileSync(join(outDir, name), svg, 'utf8');
  console.log('wrote', join(outDir, name));
}

// A. Harder injection — dev vs hold-out detection
const inj = r.harderInjection;
write(
  'bench-holdout-injection.svg',
  splitBarChart(
    'Harder prompt injection — detection',
    `Detection on dev vs mechanically-disjoint hold-out corpus (n=${r.methodology.sizePerSplit}/split); generalizationDelta ${inj.generalizationDeltaPct} pts`,
    inj.dev.detectionPct,
    inj.holdout.detectionPct,
    '%'
  )
);

// B. Intent exfil — egress-block dev vs hold-out
const exf = r.intentExfil;
write(
  'bench-holdout-exfil.svg',
  splitBarChart(
    'Intent exfil — external-egress blocked',
    `Intent-triad classifier, no raw PII. benignFPR ${exf.benignFPR.dev.fprPct}% (dev) / ${exf.benignFPR.holdout.fprPct}% (hold-out)`,
    exf.dev.egressBlockPct,
    exf.holdout.egressBlockPct,
    '%'
  )
);

// C. Ambiguous irreversible — gate ASR (lower better) + benign utility (higher better)
const amb = r.ambiguousIrreversible;
const asrTitle = 'Irreversible actions — non-owner gate ASR';
write(
  'bench-holdout-irreversible.svg',
  splitBarChart(
    asrTitle,
    `% of destructive actions that slipped through the gate (0 = held out-of-sample); benign kept-safe ${amb.dev.benign.keptSafePct}% (dev) / ${amb.holdout.benign.keptSafePct}% (hold-out)`,
    amb.dev.gateAsrPct,
    amb.holdout.gateAsrPct,
    '%'
  )
);

// D. Paraphrase generalization — embedding-tier lift on hold-out (higher better)
const par = r.paraphraseGeneralization;
write(
  'bench-holdout-paraphrase.svg',
  splitBarChart(
    'Paraphrase generalization — raw directives',
    `Detection on mechanically-disjoint synonym vocab; embedding-tier lift on hold-out +${par.embeddingLiftHoldoutPct} pts`,
    par.dev.semanticEmbeddingPct,
    par.holdout.semanticEmbeddingPct,
    '%'
  )
);

console.log('done');