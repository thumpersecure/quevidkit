/**
 * UI Utilities
 *
 * DOM helpers, progress management, and rendering functions for the
 * forensic analysis interface. All DOM access is encapsulated here.
 */

import { humanizeCheckName, humanizeCategory, verdictColor } from './scoring.js';

// Escape any string before it goes into innerHTML. Result fields (check names,
// summaries, segment categories) can come from a remote backend in remote/hybrid
// mode, so they must never be trusted as HTML.
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}

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
  get progressPct() { return $('progress-pct'); },
  get gaugeFill() { return $('gauge-fill'); },
};

// ── Progress-stage definitions ────────────────────────────────────────────────
// The per-check progress list is rendered from this array (never hardcoded in
// HTML) so the panel stays correct as checks are added or removed. Each stage's
// `id` matches the name passed to setCheckStatus() from the analysis pipeline.
export const STAGES = [
  { id: 'container',   label: 'Container & metadata' },
  { id: 'timing',      label: 'Sample timing' },
  { id: 'structure',   label: 'Frame structure' },
  { id: 'audio',       label: 'Audio consistency' },
  { id: 'provenance',  label: 'Provenance manifest' },
  { id: 'edittrace',   label: 'Container edit-trace' },
  { id: 'visual',      label: 'Visual frame analysis' },
];

/** Build the progress check-list from STAGES. Safe: labels are our own strings. */
export function renderCheckList(stages = STAGES) {
  const host = dom.checkList;
  if (!host) return;
  host.innerHTML = '';
  for (const s of stages) {
    const row = document.createElement('div');
    row.className = 'check-status pending';
    row.setAttribute('data-check', s.id);

    const icon = document.createElement('span');
    icon.className = 'check-icon';
    icon.textContent = '•';

    const name = document.createElement('span');
    name.className = 'check-name';
    name.textContent = s.label;

    const skel = document.createElement('span');
    skel.className = 'check-bar-skel';

    row.appendChild(icon);
    row.appendChild(name);
    row.appendChild(skel);
    host.appendChild(row);
  }
}

// ── Progress ─────────────────────────────────────────────────────────────────

export function showProgress(pct, text, phase) {
  const clamped = Math.max(0, Math.min(100, pct));
  if (dom.progressCard.classList.contains('hidden')) {
    dom.progressCard.classList.remove('hidden');
    dom.progressCard.classList.add('reveal');
  }
  dom.resultCard.classList.add('hidden');
  dom.progressBar.style.width = `${clamped}%`;
  if (dom.progressPct) dom.progressPct.textContent = `${Math.round(clamped)}%`;
  dom.progressText.textContent = text || '';
  if (phase && dom.progressPhase) dom.progressPhase.textContent = phase;
}

export function hideProgress() {
  dom.progressCard.classList.add('hidden');
}

// ── Error ────────────────────────────────────────────────────────────────────

// ── Debug log ────────────────────────────────────────────────────────────────
let _logCount = 0;
function _ts() {
  const d = new Date();
  return d.toTimeString().slice(0, 8) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}
/** Append a line to the on-page debug log. level: info|ok|warn|err */
export function qvkLog(msg, level = 'info') {
  const box = $('debug-log');
  if (box) {
    const cls = level === 'err' ? 'lg-err' : level === 'ok' ? 'lg-ok' : level === 'warn' ? 'lg-warn' : '';
    const line = document.createElement('div');
    const t = document.createElement('span');
    t.className = 'lg-t';
    t.textContent = _ts() + '  ';
    const m = document.createElement('span');
    if (cls) m.className = cls;
    m.textContent = String(msg);
    line.appendChild(t); line.appendChild(m);
    box.appendChild(line);
    box.scrollTop = box.scrollHeight;
    _logCount++;
    const c = $('debug-count'); if (c) c.textContent = String(_logCount);
    if (level === 'err') {
      const panel = $('debug-panel');
      const auto = $('debug-autoopen');
      if (panel && auto && auto.checked) panel.open = true;
    }
  }
  const fn = level === 'err' ? 'error' : level === 'warn' ? 'warn' : 'log';
  try { console[fn]('[qvk]', msg); } catch (_) {}
}

export function initDebugPanel() {
  const clear = $('debug-clear');
  if (clear) clear.addEventListener('click', () => {
    const box = $('debug-log'); if (box) box.textContent = '';
    _logCount = 0; const c = $('debug-count'); if (c) c.textContent = '0';
  });
  const copy = $('debug-copy');
  if (copy) copy.addEventListener('click', async () => {
    const box = $('debug-log'); if (!box) return;
    try { await navigator.clipboard.writeText(box.innerText); copy.textContent = 'Copied'; setTimeout(() => copy.textContent = 'Copy', 1200); }
    catch (_) { copy.textContent = 'Copy failed'; }
  });
  // capture uncaught errors so nothing is lost
  window.addEventListener('error', e => qvkLog('window error: ' + (e.message || e), 'err'));
  window.addEventListener('unhandledrejection', e => qvkLog('unhandled rejection: ' + ((e.reason && e.reason.message) || e.reason), 'err'));
}

export function showError(msg) {
  dom.errorBox.textContent = msg;
  dom.errorBox.classList.remove('hidden');
  qvkLog('ERROR shown to user: ' + msg, 'err');
}

export function hideError() {
  dom.errorBox.textContent = '';
  dom.errorBox.classList.add('hidden');
}

// ── Check progress list ──────────────────────────────────────────────────────

export function setCheckStatus(name, status) {
  const el = document.querySelector(`[data-check="${name}"]`);
  if (!el) return; // unknown stage: no-op, keeps the panel forgiving as checks change
  el.className = `check-status ${status}`;
  const icon = el.querySelector('.check-icon');
  if (icon) {
    // The running spinner is drawn in CSS, so leave the glyph empty while running.
    if (status === 'running') icon.textContent = '';
    else if (status === 'done') icon.textContent = '\u2713';
    else if (status === 'error') icon.textContent = '\u2717';
    else icon.textContent = '\u2022';
  }
}

// ── Result rendering ─────────────────────────────────────────────────────────

// Inline verdict icons (our own markup — not from untrusted data).
const VERDICT_ICON = {
  authentic:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
  tampered:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>',
  suspicious:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>',
  inconclusive:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 0 1 4.5 1.5c0 1.5-2 2-2 3M12 17h.01"/></svg>',
};

const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 52; // r=52 in the SVG

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

// One-line plain-English description per check. Kept generous so any check the
// backend emits — including checks added later — renders with real context
// rather than a bare fallback. Unknown names still degrade gracefully.
function checkDescription(name) {
  const map = {
    container_metadata: 'Compares container and stream metadata for consistency, editing markers, and structural anomalies.',
    metadata_codec_consistency: 'Compares container metadata against stream data for durations, bitrates, and format tags.',
    sample_timing: 'Checks frame timing continuity from the sample table for jumps and irregularities.',
    packet_timing_anomalies: 'Inspects packet timestamps for gaps or non-monotonic sequences at possible splice points.',
    frame_structure: 'Inspects GOP patterns, keyframe regularity, and sample size distribution.',
    frame_structure_anomalies: 'Analyzes GOP regularity, resolution consistency, and color-profile stability.',
    visual_frame_analysis: 'Measures visual quality shifts, duplicate frames, and luminance histogram breaks.',
    frame_quality_shift: 'Measures frame-to-frame quality changes: blur, blockiness, and duplicate or missing frames.',
    audio_consistency: 'Verifies audio/video duration match and audio codec consistency.',
    browser_temporal_continuity: 'Analyzes frame-to-frame pixel continuity for abrupt visual breaks.',
    compression_consistency: 'Compares packet-size distributions across the timeline per frame type.',
    scene_cut_forensics: 'Correlates scene transitions with the natural keyframe cadence.',
    audio_spectral_continuity: 'Detects abrupt audio spectral breaks between recording environments.',
    temporal_noise_consistency: 'Measures per-frame noise to detect source changes across the timeline.',
    double_compression_detection: 'Detects re-encoding over previously compressed video via I-frame periodicity.',
    ela_frame_analysis: 'Error-level analysis: re-compresses frames and measures residual differences.',
    bitstream_structure: 'Checks for mid-stream codec parameter changes across the bitstream.',
    qp_consistency: 'Analyzes GOP frame-type patterns for consistency across the timeline.',
    thumbnail_mismatch: 'Compares the embedded thumbnail against the actual first frame.',
    av_sync_drift: 'Measures audio-video timing offset at checkpoints across the timeline.',
    bitrate_distribution: 'Tests whether packet sizes form one distribution (single source) or two (merged sources).',
    provenance_manifest: 'Verifies C2PA / Content Credentials provenance manifests and signatures.',
    c2pa_manifest: 'Verifies C2PA / Content Credentials provenance manifests and signatures.',
    container_edit_trace: 'Looks for container-level edit traces left by editing and re-muxing tools.',
    edit_trace: 'Looks for container-level edit traces left by editing and re-muxing tools.',
  };
  return map[name] || 'Contributes to the overall forensic risk score.';
}

export function renderResult(report) {
  dom.progressCard.classList.add('hidden');
  dom.resultCard.classList.remove('hidden');
  dom.resultCard.classList.remove('reveal');
  // reflow so the reveal animation replays on each new result
  void dom.resultCard.offsetWidth;
  dom.resultCard.classList.add('reveal');

  const label = report.label || 'inconclusive';
  const prob = report.tamper_probability || 0;
  const conf = report.confidence || 0;
  const color = verdictColor(label);
  const probPct = `${(prob * 100).toFixed(1)}%`;

  // Verdict badge: icon (safe, our markup) + label (safe, our textContent).
  dom.resultLabel.innerHTML = VERDICT_ICON[label] || VERDICT_ICON.inconclusive;
  dom.resultLabel.appendChild(document.createTextNode(label.toUpperCase()));
  dom.resultLabel.style.background = color;
  dom.resultMeaning.textContent = plainMeaning(label, prob, conf);

  // Radial gauge: fill the arc to the tamper probability, tint to verdict color.
  if (dom.resultProb) dom.resultProb.textContent = `${(prob * 100).toFixed(0)}%`;
  if (dom.gaugeFill) {
    dom.gaugeFill.style.stroke = color;
    // start from empty, then animate to target on the next frame
    dom.gaugeFill.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;
    requestAnimationFrame(() => {
      dom.gaugeFill.style.strokeDashoffset = GAUGE_CIRCUMFERENCE * (1 - Math.max(0, Math.min(1, prob)));
    });
  }

  const probCard = document.getElementById('result-probability-2');
  if (probCard) probCard.textContent = probPct;
  dom.resultConf.textContent = `${(conf * 100).toFixed(1)}%`;
  dom.resultDuration.textContent = `${(report.duration_s || 0).toFixed(2)}s`;
  if (dom.resultSHA) dom.resultSHA.textContent = report.sha256 || '—';

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
  const hint = document.getElementById('swipe-hint');
  if (!checks.length) {
    dom.resultChecks.innerHTML = '<p class="muted">No check data available.</p>';
    if (hint) hint.style.display = 'none';
    return;
  }
  // Only offer the swipe affordance when there's actually more than one card.
  if (hint) hint.style.removeProperty('display');
  for (const c of checks) {
    const s = Math.max(0, Math.min(100, (c.score || 0) * 100));
    const cn = Math.max(0, Math.min(100, (c.confidence || 0) * 100));
    const card = document.createElement('div');
    card.className = 'check-item';
    card.innerHTML = `
      <h4>${esc(humanizeCheckName(c.name))}</h4>
      <p class="muted">${esc(checkDescription(c.name))}</p>
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
      <p class="check-summary">${esc(c.summary || '')}</p>
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
    return `<div class="timeline-block" style="left:${start.toFixed(2)}%;width:${width.toFixed(2)}%" title="${esc(title)}"></div>`;
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
