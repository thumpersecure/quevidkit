/**
 * UI Utilities
 *
 * DOM helpers, progress management, and rendering functions for the
 * forensic analysis interface. All DOM access is encapsulated here.
 */

import { humanizeCheckName, humanizeCategory, verdictColor } from './scoring.js';

// ── DOM references ───────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

export const dom = {
  get form() { return $('analyze-form'); },
  get fileInput() { return $('video-file'); },
  get analyzeBtn() { return $('analyze-btn'); },
  get progressCard() { return $('progress-card'); },
  get progressText() { return $('progress-text'); },
  get progressBar() { return $('progress-bar'); },
  get progressPhase() { return $('progress-phase'); },
  get resultCard() { return $('result-card'); },
  get resultLabel() { return $('result-label'); },
  get resultMeaning() { return $('result-meaning'); },
  get resultProb() { return $('result-probability'); },
  get resultConf() { return $('result-confidence'); },
  get resultDuration() { return $('result-duration'); },
  get resultSHA() { return $('result-sha'); },
  get resultMeter() { return $('result-meter'); },
  get resultMode() { return $('result-mode'); },
  get resultExplanation() { return $('result-explanation'); },
  get resultChecks() { return $('result-checks'); },
  get resultTimeline() { return $('result-timeline'); },
  get resultSegments() { return $('result-segments'); },
  get resultRaw() { return $('result-raw'); },
  get downloadBtn() { return $('download-btn'); },
  get modeSelect() { return $('mode-select'); },
  get presetSelect() { return $('analysis-preset'); },
  get sampleInterval() { return $('sample-interval'); },
  get maxSamples() { return $('max-samples'); },
  get sensitivity() { return $('sensitivity'); },
  get serverUrl() { return $('server-url'); },
  get serverStatus() { return $('server-status'); },
  get testServerBtn() { return $('test-server-btn'); },
  get errorBox() { return $('error-box'); },
  get checkList() { return $('check-list'); },
};

// ── Progress ─────────────────────────────────────────────────────────────────

export function showProgress(pct, text, phase) {
  dom.progressCard.classList.remove('hidden');
  dom.resultCard.classList.add('hidden');
  dom.progressBar.style.width = `${Math.max(0, Math.min(100, pct))}%`;
  dom.progressText.textContent = text || '';
  if (phase && dom.progressPhase) dom.progressPhase.textContent = phase;
}

export function hideProgress() {
  dom.progressCard.classList.add('hidden');
}

// ── Error ────────────────────────────────────────────────────────────────────

export function showError(msg) {
  dom.errorBox.textContent = msg;
  dom.errorBox.classList.remove('hidden');
}

export function hideError() {
  dom.errorBox.textContent = '';
  dom.errorBox.classList.add('hidden');
}

// ── Check progress list ──────────────────────────────────────────────────────

export function setCheckStatus(name, status) {
  const el = document.querySelector(`[data-check="${name}"]`);
  if (!el) return;
  el.className = `check-status ${status}`;
  const icon = el.querySelector('.check-icon');
  if (icon) {
    if (status === 'running') icon.textContent = '...';
    else if (status === 'done') icon.textContent = '\u2713';
    else if (status === 'error') icon.textContent = '\u2717';
    else icon.textContent = '\u2022';
  }
}

// ── Result rendering ─────────────────────────────────────────────────────────

function plainMeaning(label, prob, conf) {
  const pPct = (prob * 100).toFixed(1);
  const cPct = (conf * 100).toFixed(1);
  if (label === 'tampered')
    return `Strong signs of editing or manipulation detected. Probability: ${pPct}%, Confidence: ${cPct}%.`;
  if (label === 'authentic')
    return `No significant manipulation detected. Probability: ${pPct}%, Confidence: ${cPct}%.`;
  if (label === 'suspicious')
    return `Unusual patterns warrant further review. Probability: ${pPct}%.`;
  return 'Could not assess with sufficient confidence. Try a deeper scan.';
}

function checkDescription(name) {
  const map = {
    container_metadata: 'Compares container and stream metadata for consistency, editing markers, and structural anomalies.',
    sample_timing: 'Checks frame timing continuity from the sample table for jumps and irregularities.',
    frame_structure: 'Inspects GOP patterns, keyframe regularity, and sample size distribution.',
    visual_frame_analysis: 'Measures visual quality shifts, duplicate frames, and luminance histogram breaks.',
    audio_consistency: 'Verifies audio/video duration match and audio codec consistency.',
  };
  return map[name] || 'Contributes to overall forensic risk scoring.';
}

export function renderResult(report) {
  dom.resultCard.classList.remove('hidden');

  const label = report.label || 'inconclusive';
  const prob = report.tamper_probability || 0;
  const conf = report.confidence || 0;
  const color = verdictColor(label);

  dom.resultLabel.textContent = label.toUpperCase();
  dom.resultLabel.style.background = color;
  dom.resultMeaning.textContent = plainMeaning(label, prob, conf);
  dom.resultProb.textContent = `${(prob * 100).toFixed(1)}%`;
  dom.resultConf.textContent = `${(conf * 100).toFixed(1)}%`;
  dom.resultDuration.textContent = `${(report.duration_s || 0).toFixed(2)}s`;
  if (dom.resultSHA) dom.resultSHA.textContent = report.sha256 || '—';
  dom.resultMeter.style.width = `${(prob * 100).toFixed(1)}%`;

  const modeLabels = {
    client: 'Full client-side analysis (no server)',
    hybrid: 'Hybrid (client + server)',
    remote: 'Server deep scan',
  };
  dom.resultMode.textContent = modeLabels[report.mode] || report.mode || 'unknown';

  dom.resultExplanation.innerHTML = '';
  for (const line of (report.explanation || [])) {
    const li = document.createElement('li');
    li.textContent = line;
    dom.resultExplanation.appendChild(li);
  }

  renderCheckBars(report.checks || []);
  renderTimeline(report);

  dom.resultRaw.textContent = JSON.stringify({
    label: report.label,
    tamper_probability: report.tamper_probability,
    confidence: report.confidence,
    checks: (report.checks || []).map(c => ({
      name: c.name, score: c.score, confidence: c.confidence, summary: c.summary,
    })),
    segments_count: (report.segments || []).length,
  }, null, 2);
}

function renderCheckBars(checks) {
  dom.resultChecks.innerHTML = '';
  if (!checks.length) {
    dom.resultChecks.innerHTML = '<p class="muted">No check data available.</p>';
    return;
  }
  for (const c of checks) {
    const s = Math.max(0, Math.min(100, (c.score || 0) * 100));
    const cn = Math.max(0, Math.min(100, (c.confidence || 0) * 100));
    const card = document.createElement('div');
    card.className = 'check-item';
    card.innerHTML = `
      <h4>${humanizeCheckName(c.name)}</h4>
      <p class="muted">${checkDescription(c.name)}</p>
      <div class="bar-row">
        <span>Anomaly</span>
        <div class="bar-track"><div class="bar-fill-score" style="width:${s.toFixed(1)}%"></div></div>
        <strong>${s.toFixed(1)}%</strong>
      </div>
      <div class="bar-row">
        <span>Confidence</span>
        <div class="bar-track"><div class="bar-fill-confidence" style="width:${cn.toFixed(1)}%"></div></div>
        <strong>${cn.toFixed(1)}%</strong>
      </div>
      <p class="check-summary">${c.summary || ''}</p>
    `;
    dom.resultChecks.appendChild(card);
  }
}

function renderTimeline(report) {
  const segments = (report.segments || []).slice(0, 60);
  dom.resultSegments.innerHTML = '';
  const duration = Math.max(
    report.duration_s || 0,
    ...segments.map(s => s.end_s || 0),
    1,
  );
  if (!segments.length) {
    dom.resultTimeline.innerHTML = '<p class="muted" style="padding:6px 10px">No suspicious segments detected.</p>';
    const li = document.createElement('li');
    li.textContent = 'No suspicious timeline windows identified.';
    dom.resultSegments.appendChild(li);
    return;
  }
  const blocks = segments.map(seg => {
    const start = Math.max(0, Math.min(100, (seg.start_s / duration) * 100));
    const end = Math.max(start, Math.min(100, (seg.end_s / duration) * 100));
    const width = Math.max(0.4, end - start);
    const cat = humanizeCategory(seg.category);
    const title = `[${cat}] ${seg.start_s.toFixed(2)}s–${seg.end_s.toFixed(2)}s (conf ${seg.confidence.toFixed(2)})`;
    return `<div class="timeline-block" style="left:${start.toFixed(2)}%;width:${width.toFixed(2)}%" title="${title}"></div>`;
  }).join('');
  dom.resultTimeline.innerHTML = blocks;

  for (const seg of segments) {
    const li = document.createElement('li');
    li.textContent = `[${humanizeCategory(seg.category)}] ${seg.start_s.toFixed(2)}s – ${seg.end_s.toFixed(2)}s (conf ${seg.confidence.toFixed(2)})`;
    dom.resultSegments.appendChild(li);
  }
}

// ── Options ──────────────────────────────────────────────────────────────────

export function getOptions() {
  return {
    sampleInterval: Math.max(0.1, Math.min(5, Number(dom.sampleInterval?.value || '0.5'))),
    maxSamples: Math.max(10, Math.min(2000, Number(dom.maxSamples?.value || '240'))),
    sensitivity: Math.max(0.05, Math.min(0.99, Number(dom.sensitivity?.value || '0.7'))),
  };
}

export const PRESETS = {
  fast: { sampleInterval: 1.0, maxSamples: 500, sensitivity: 0.5 },
  balanced: { sampleInterval: 0.5, maxSamples: 1000, sensitivity: 0.7 },
  deep: { sampleInterval: 0.2, maxSamples: 2000, sensitivity: 0.85 },
};

export function applyPreset(name) {
  const p = PRESETS[name];
  if (!p) return;
  if (dom.sampleInterval) dom.sampleInterval.value = p.sampleInterval;
  if (dom.maxSamples) dom.maxSamples.value = p.maxSamples;
  if (dom.sensitivity) dom.sensitivity.value = p.sensitivity;
}
