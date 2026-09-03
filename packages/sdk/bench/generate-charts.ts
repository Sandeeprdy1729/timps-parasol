// TIMPS-Parasol · bench/generate-charts.ts
// Reads bench/results.json (comparative, multi-engine) and emits SVG charts
// for the blog experiment section. Run:  npm run bench:charts
// Emits:
//   docs/bench-injection-asr.svg   — injection ASR by engine (comparative)
//   docs/bench-pii.svg             — credential-exfil detection + ASR (comparative)
//   docs/bench-architectural.svg   — Parasol-only architectural control surfaces
//   docs/bench-latency.svg         — protected-call latency p50/p95/p99

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const results = JSON.parse(readFileSync(join(__dirname, 'results.json'), 'utf8'));

const outDir = join(__dirname, '..', '..', '..', 'docs');
mkdirSync(outDir, { recursive: true });

const ENGINE_LABEL: Record<string, string> = {
  bare: 'Bare agent',
  keyword: 'Keyword baseline',
  vard: 'Vard (OSS)',
  parasol: 'Parasol'
};
const ENGINE_COLOR: Record<string, string> = {
  bare: '#ef4444',
  keyword: '#f59e0b',
  vard: '#38bdf8',
  parasol: '#22c55e'
};
const SURFACE_LABEL: Record<string, string> = {
  irreversible: 'Irreversible action',
  social: 'Social engineering',
  identity: 'Identity spoof',
  resource: 'Resource loop'
};

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// ---------------------------------------------------------------------------
// Compare a detection metric across engines as horizontal bars (best on top)
// ---------------------------------------------------------------------------
function engineBarChart(
  title: string,
  subtitle: string,
  metricKey: 'asrPct' | 'detectionPct',
  metricLabel: string,
  lowerIsBetter: boolean,
  section: 'injection' | 'credentialExfil'
): string {
  const W = 860, H = 320, padL = 250, padB = 60, padT = 64, padR = 60;
  const chartW = W - padL - padR, chartH = H - padT - padB;
  const rows = Object.entries(results[section] as Record<string, { asrPct: number; detectionPct: number }>)
    .map(([k, v]) => ({ name: k, value: v[metricKey], label: ENGINE_LABEL[k] ?? k, color: ENGINE_COLOR[k] ?? '#94a3b8' }))
    .sort((a, b) => (lowerIsBetter ? a.value - b.value : b.value - a.value));
  const rowH = chartH / rows.length;

  let body = '';
  rows.forEach((r, i) => {
    const y = padT + i * rowH + rowH / 2;
    const barH = Math.min(rowH * 0.55, 30);
    const w = (r.value / 100) * chartW;
    const barX = padL;
    body += `<rect x="${barX}" y="${(y - barH / 2).toFixed(1)}" width="${Math.max(w, 2).toFixed(1)}" height="${barH.toFixed(1)}" rx="4" fill="${r.color}" />`;
    body += `<text x="${barX - 14}" y="${(y + 4).toFixed(1)}" text-anchor="end" fill="#cbd5e1" font-family="Inter,Arial" font-size="12.5">${esc(r.label)}</text>`;
    body += `<text x="${(barX + w + 8).toFixed(1)}" y="${(y + 4).toFixed(1)}" text-anchor="start" fill="${r.color}" font-family="Inter,Arial" font-size="12" font-weight="700">${r.value.toFixed(1)}%</text>`;
    // grid tick at 50%
    body += `<line x1="${barX + chartW * 0.5}" y1="${padT}" x2="${barX + chartW * 0.5}" y2="${padT + chartH}" stroke="#1e293b" stroke-dasharray="4 4" />`;
  });

  const legend = `${metricLabel} — ${lowerIsBetter ? 'lower is better' : 'higher is better'}`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(title)}">
  <rect width="${W}" height="${H}" fill="#0b1220" />
  <text x="${padL}" y="30" fill="#f1f5f9" font-family="Inter,Arial" font-size="18" font-weight="700">${esc(title)}</text>
  <text x="${padL}" y="50" fill="#94a3b8" font-family="Inter,Arial" font-size="12">${esc(subtitle)}</text>
  ${body}
  <text x="${padL}" y="${H - 16}" fill="#94a3b8" font-family="Inter,Arial" font-size="12">${esc(legend)} · 10,000 generated inputs/engine · dashed line = 50%</text>
</svg>`;
}

// ---------------------------------------------------------------------------
// Architectural control surfaces (Parasol only — no peer detectors exist)
// ---------------------------------------------------------------------------
function architecturalChart(): string {
  const W = 860, H = 340, padL = 260, padB = 60, padT = 64, padR = 60;
  const chartW = W - padL - padR, chartH = H - padT - padB;
  const arch = results.architectural as Record<string, { asrPct: number; detectionPct: number }>;
  const rows = Object.entries(arch)
    .map(([k, v]) => ({ name: k, asr: v.asrPct, det: v.detectionPct, label: SURFACE_LABEL[k] ?? k }));
  const rowH = chartH / rows.length;

  let body = '';
  rows.forEach((r, i) => {
    const y = padT + i * rowH + rowH / 2;
    const barH = Math.min(rowH * 0.5, 28);
    // detection (green) from left
    const detW = (r.det / 100) * chartW;
    // residual ASR (red) starts where detection ends
    const asrW = (r.asr / 100) * chartW;
    body += `<rect x="${padL}" y="${(y - barH / 2).toFixed(1)}" width="${Math.max(detW, 2).toFixed(1)}" height="${barH.toFixed(1)}" rx="4" fill="#22c55e" />`;
    if (r.asr > 0) {
      body += `<rect x="${(padL + detW).toFixed(1)}" y="${(y - barH / 2).toFixed(1)}" width="${Math.max(asrW - 1, 2).toFixed(1)}" height="${barH.toFixed(1)}" rx="4" fill="#ef4444" />`;
    }
    body += `<text x="${padL - 14}" y="${(y + 4).toFixed(1)}" text-anchor="end" fill="#cbd5e1" font-family="Inter,Arial" font-size="12.5">${esc(r.label)}</text>`;
    body += `<text x="${(padL + detW + 8).toFixed(1)}" y="${(y + 4).toFixed(1)}" text-anchor="start" fill="#4ade80" font-family="Inter,Arial" font-size="12" font-weight="700">${r.det.toFixed(1)}%</text>`;
    if (r.asr > 0) {
      body += `<text x="${(padL + detW + asrW + 16).toFixed(1)}" y="${(y + 4).toFixed(1)}" text-anchor="start" fill="#f87171" font-family="Inter,Arial" font-size="12">${r.asr.toFixed(1)}% M</text>`;
    }
  });

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Parasol architectural control surfaces detection and residual attack success rate">
  <rect width="${W}" height="${H}" fill="#0b1220" />
  <text x="${padL}" y="30" fill="#f1f5f9" font-family="Inter,Arial" font-size="18" font-weight="700">Architectural control surfaces</text>
  <text x="${padL}" y="50" fill="#94a3b8" font-family="Inter,Arial" font-size="12">Enforced by design (identity, budgets, gates), not heuristics. 'M' = residual miss, documented.</text>
  ${body}
  <rect x="${padL}" y="${H - 30}" width="14" height="14" rx="3" fill="#22c55e" /><text x="${padL + 20}" y="${H - 19}" fill="#e2e8f0" font-family="Inter,Arial" font-size="12">Detected &amp; blocked</text>
  <rect x="${padL + 180}" y="${H - 30}" width="14" height="14" rx="3" fill="#ef4444" /><text x="${padL + 200}" y="${H - 19}" fill="#e2e8f0" font-family="Inter,Arial" font-size="12">Residual miss</text>
</svg>`;
}

// ---------------------------------------------------------------------------
// Latency: p50/p95/p99 for Parasol protected calls, all sections
// ---------------------------------------------------------------------------
function latencyChart(): string {
  const W = 860, H = 360, padL = 240, padB = 70, padT = 60, padR = 40;
  const chartW = W - padL - padR, chartH = H - padT - padB;
  const parasolLat = {
    injection: results.injection.parasol.latency,
    credentialExfil: results.credentialExfil.parasol.latency,
    irreversible: results.architectural.irreversible.latency,
    social: results.architectural.social.latency,
    identity: results.architectural.identity.latency,
    resource: results.architectural.resource.latency
  };
  const labels: Record<string, string> = {
    injection: 'Prompt injection',
    credentialExfil: 'Credential exfil',
    irreversible: 'Irreversible action',
    social: 'Social engineering',
    identity: 'Identity spoof',
    resource: 'Resource loop'
  };
  const maxMs = Math.max(...Object.values(parasolLat).map((l) => l.p99)) * 1.1;
  const rows = Object.entries(parasolLat);
  const rowH = chartH / rows.length;

  let body = '';
  rows.forEach(([k, l], i) => {
    const y = padT + i * rowH + rowH / 2;
    const barH = Math.min(rowH * 0.5, 26);
    body += `<text x="${padL - 14}" y="${(y + 4).toFixed(1)}" text-anchor="end" fill="#cbd5e1" font-family="Inter,Arial" font-size="12.5">${esc(labels[k])}</text>`;
    const stages: [keyof typeof l, string][] = [['p50', '#38bdf8'], ['p95', '#2563eb'], ['p99', '#7c3aed']];
    stages.forEach(([key, color], kk) => {
      const v = l[key];
      const w = (v / maxMs) * chartW;
      const x = padL + (kk / stages.length) * chartW * 0.62;
      body += `<rect x="${x.toFixed(1)}" y="${(y - barH / 2).toFixed(1)}" width="${Math.max(w, 2).toFixed(1)}" height="${barH.toFixed(1)}" rx="3" fill="${color}" />`;
      if (key === 'p99') {
        body += `<text x="${(x + w + 6).toFixed(1)}" y="${(y + 4).toFixed(1)}" text-anchor="start" fill="#c4b5fd" font-family="Inter,Arial" font-size="11">${v.toFixed(2)}</text>`;
      }
    });
  });

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Parasol protecting-call latency p50 p95 p99 by surface">
  <rect width="${W}" height="${H}" fill="#0b1220" />
  <text x="${padL}" y="30" fill="#f1f5f9" font-family="Inter,Arial" font-size="18" font-weight="700">Parasol overhead — protecting-call latency (ms)</text>
  <text x="${padL}" y="50" fill="#94a3b8" font-family="Inter,Arial" font-size="12">Measured over 10,000 generated inputs per surface. Shields add ~1–4 ms; identity check ~0.04 ms.</text>
  ${body}
  <rect x="${padL}" y="${H - 26}" width="14" height="14" rx="3" fill="#38bdf8" /><text x="${padL + 20}" y="${H - 15}" fill="#e2e8f0" font-family="Inter,Arial" font-size="11">p50</text>
  <rect x="${padL + 90}" y="${H - 26}" width="14" height="14" rx="3" fill="#2563eb" /><text x="${padL + 110}" y="${H - 15}" fill="#e2e8f0" font-family="Inter,Arial" font-size="11">p95</text>
  <rect x="${padL + 180}" y="${H - 26}" width="14" height="14" rx="3" fill="#7c3aed" /><text x="${padL + 200}" y="${H - 15}" fill="#e2e8f0" font-family="Inter,Arial" font-size="11">p99</text>
</svg>`;
}

writeFileSync(join(outDir, 'bench-injection-asr.svg'),
  engineBarChart(
    'Prompt-injection: attack success rate',
    'Head-to-head on the same 10,000 generated injection prompts. Bare = no detector at all.',
    'asrPct', 'Attack success rate', true, 'injection'
  ), 'utf8');

writeFileSync(join(outDir, 'bench-pii.svg'),
  engineBarChart(
    'Credential exfil: PII redaction detection rate',
    'Does the engine redact PII before it leaves the agent? Bare / keyword / Vard do no redaction.',
    'detectionPct', 'PII detected & masked', false, 'credentialExfil'
  ), 'utf8');

writeFileSync(join(outDir, 'bench-architectural.svg'), architecturalChart(), 'utf8');
writeFileSync(join(outDir, 'bench-latency.svg'), latencyChart(), 'utf8');

console.log('wrote docs/bench-injection-asr.svg, bench-pii.svg, bench-architectural.svg, bench-latency.svg');