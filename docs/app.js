/**
 * quevidkit – Mobile Forensic Analysis Orchestrator
 *
 * Three analysis modes:
 *   1. Client-only  – full forensic analysis runs entirely in the browser
 *   2. Server       – sends video to a running quevidkit backend
 *   3. Hybrid       – client-side analysis first, then optional server enhancement
 */

import { parseMP4, computeSHA256 } from './lib/mp4-parser.js';
import {
  containerMetadataCheck,
  timingCheck,
  structureCheck,
  visualFrameCheck,
  audioConsistencyCheck,
} from './lib/checks.js';
import { fuseScores, buildExplanation, clamp01 } from './lib/scoring.js';
import { downloadReport } from './lib/report.js';
import {
  dom, showProgress, hideProgress, showError, hideError,
  renderResult, setCheckStatus, getOptions, applyPreset, PRESETS,
} from './lib/ui.js';

// ── State ────────────────────────────────────────────────────────────────────

let latestReport = null;
let isAnalyzing = false;

// ── Remote API helpers ───────────────────────────────────────────────────────

const SESSION_KEY = 'qvk.remote.session';
const BASE_URL_KEY = 'qvk.remote.baseUrl';
const FALLBACK_LIMIT = 10;

function parseBaseUrl(raw) {
  const v = (raw || '').trim();
  if (!v) return { baseUrl: '', error: 'Enter a server URL.' };
  let u;
  try { u = new URL(v); } catch { return { baseUrl: '', error: 'Invalid URL.' }; }
  if (!['http:', 'https:'].includes(u.protocol)) return { baseUrl: '', error: 'Use http:// or https://.' };
  let path = u.pathname.replace(/\/+$/, '');
  if (path.endsWith('/api/v1')) path = path.slice(0, -7);
  else if (path.endsWith('/api')) path = path.slice(0, -4);
  const baseUrl = `${u.origin}${path}`;
  if (location.protocol === 'https:' && u.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(u.hostname)) {
    return { baseUrl, error: 'Mixed content blocked. Use HTTPS or localhost.' };
  }
  return { baseUrl, error: '' };
}

function loadSession(baseUrl) {
  try { return JSON.parse(sessionStorage.getItem(`${SESSION_KEY}.${baseUrl}`) || 'null'); }
  catch { return null; }
}
function saveSession(baseUrl, s) { sessionStorage.setItem(`${SESSION_KEY}.${baseUrl}`, JSON.stringify(s)); }
function clearSession(baseUrl) { sessionStorage.removeItem(`${SESSION_KEY}.${baseUrl}`); }
function isExpired(s) { return !s?.expiresAtMs || Date.now() >= s.expiresAtMs; }

async function ensureSession(baseUrl) {
  const s = loadSession(baseUrl);
  if (s && !isExpired(s)) return s;
  const resp = await fetch(`${baseUrl}/api/v1/session-key`, { method: 'POST' });
  if (!resp.ok) throw new Error(`Server error ${resp.status}`);
  const data = await resp.json();
  const record = {
    key: data.session_key,
    expiresAtMs: new Date(data.expires_at_utc).getTime() || (Date.now() + 30 * 60000),
    quota: data.job_quota || { limit: FALLBACK_LIMIT, remaining: FALLBACK_LIMIT },
  };
  saveSession(baseUrl, record);
  return record;
}

async function remoteFetch(baseUrl, path, init = {}) {
  const session = await ensureSession(baseUrl);
  const headers = new Headers(init.headers || {});
  headers.set('X-Session-Key', session.key);
  let resp = await fetch(`${baseUrl}${path}`, { ...init, headers });
  if (resp.status === 401) {
    clearSession(baseUrl);
    const refreshed = await ensureSession(baseUrl);
    const h2 = new Headers(init.headers || {});
    h2.set('X-Session-Key', refreshed.key);
    resp = await fetch(`${baseUrl}${path}`, { ...init, headers: h2 });
  }
  return resp;
}

// ── Client-side analysis pipeline ────────────────────────────────────────────

async function runClientAnalysis(file, options) {
  const checks = [];
  const startTime = Date.now();

  showProgress(2, 'Reading file...', 'Binary parsing');

  let buffer;
  try {
    buffer = await file.arrayBuffer();
  } catch (e) {
    throw new Error(`Cannot read file: ${e.message}`);
  }

  showProgress(8, 'Computing file hash...', 'Integrity check');
  let sha256 = '';
  try {
    sha256 = await computeSHA256(buffer);
  } catch { /* crypto.subtle might be unavailable in insecure contexts */ }

  showProgress(12, 'Parsing MP4 container...', 'Container analysis');
  let parsed = null;
  try {
    parsed = parseMP4(buffer);
  } catch (e) {
    showProgress(12, 'Container parsing failed, continuing with visual analysis...', 'Fallback');
  }

  if (parsed) {
    setCheckStatus('container', 'running');
    showProgress(18, 'Analyzing container metadata...', 'Container forensics');
    try {
      const c1 = containerMetadataCheck(parsed);
      checks.push(c1);
      setCheckStatus('container', 'done');
    } catch {
      setCheckStatus('container', 'error');
    }

    setCheckStatus('timing', 'running');
    showProgress(28, 'Analyzing sample timing...', 'Timing forensics');
    try {
      const c2 = timingCheck(parsed);
      checks.push(c2);
      setCheckStatus('timing', 'done');
    } catch {
      setCheckStatus('timing', 'error');
    }

    setCheckStatus('structure', 'running');
    showProgress(36, 'Analyzing frame structure...', 'Structure forensics');
    try {
      const c3 = structureCheck(parsed);
      checks.push(c3);
      setCheckStatus('structure', 'done');
    } catch {
      setCheckStatus('structure', 'error');
    }

    setCheckStatus('audio', 'running');
    showProgress(42, 'Checking audio consistency...', 'Audio forensics');
    try {
      const c4 = audioConsistencyCheck(parsed);
      checks.push(c4);
      setCheckStatus('audio', 'done');
    } catch {
      setCheckStatus('audio', 'error');
    }
  }

  buffer = null;

  setCheckStatus('visual', 'running');
  showProgress(48, 'Extracting and analyzing frames...', 'Visual forensics');
  try {
    const visualResult = await visualFrameCheck(file, options, (i, total) => {
      const pct = 48 + Math.round((i / total) * 45);
      showProgress(pct, `Analyzing frame ${i + 1}/${total}...`, 'Visual forensics');
    });
    checks.push(visualResult);
    setCheckStatus('visual', 'done');
  } catch (e) {
    setCheckStatus('visual', 'error');
    checks.push({
      name: 'visual_frame_analysis', category: 'quality',
      score: 0, confidence: 0.05,
      summary: `Visual analysis failed: ${e.message}`,
      details: {}, segments: [],
    });
  }

  showProgress(96, 'Computing final verdict...', 'Score fusion');

  const { probability, confidence, label } = fuseScores(checks, options.sensitivity);
  const explanation = buildExplanation(checks, label);

  const allSegments = [];
  for (const c of checks) allSegments.push(...(c.segments || []));
  allSegments.sort((a, b) => a.start_s - b.start_s);

  const duration = parsed?.mvhd?.durationSeconds
    || parsed?.videoTrack?.mdhd?.durationSeconds
    || (checks.find(c => c.details?.videoDurationS)?.details?.videoDurationS)
    || 0;

  showProgress(100, 'Analysis complete', 'Done');

  return {
    mode: 'client',
    label,
    tamper_probability: Number(probability.toFixed(4)),
    confidence: Number(confidence.toFixed(4)),
    duration_s: duration,
    explanation,
    checks,
    segments: allSegments.slice(0, 200),
    sha256,
    fileName: file.name,
    fileSize: file.size,
    analysisTimeMs: Date.now() - startTime,
  };
}

// ── Remote (server) analysis ─────────────────────────────────────────────────

async function runRemoteAnalysis(file, options, baseUrl) {
  showProgress(5, 'Connecting to server...', 'Authentication');
  await ensureSession(baseUrl);

  showProgress(15, 'Uploading video...', 'Upload');
  const fd = new FormData();
  fd.append('file', file);
  fd.append('options', JSON.stringify({
    preset: dom.presetSelect?.value || 'balanced',
    sample_fps: Number((1 / options.sampleInterval).toFixed(3)),
    max_frames: options.maxSamples,
    sensitivity: options.sensitivity,
  }));
  const jobResp = await remoteFetch(baseUrl, '/api/v1/jobs', { method: 'POST', body: fd });
  if (!jobResp.ok) throw new Error(`Upload failed (${jobResp.status})`);
  const job = await jobResp.json();

  let attempts = 0;
  while (attempts < 900) {
    attempts++;
    const sr = await remoteFetch(baseUrl, `/api/v1/jobs/${job.job_id}`, { method: 'GET' });
    if (!sr.ok) throw new Error(`Status poll failed (${sr.status})`);
    const st = await sr.json();
    const phaseLabels = {
      queued: 'Waiting...', extracting_metadata: 'Reading metadata...',
      forensic_analysis: 'Running analysis...', done: 'Complete!',
      completed: 'Complete!', failed: 'Failed',
    };
    showProgress(st.progress_percent || 0, phaseLabels[st.phase] || 'Processing...', st.phase);
    if (st.status === 'completed') {
      const rr = await remoteFetch(baseUrl, `/api/v1/jobs/${job.job_id}/result`, { method: 'GET' });
      if (!rr.ok) throw new Error('Could not fetch result');
      const payload = await rr.json();
      const r = payload.result || {};
      return {
        mode: 'remote',
        label: r.label,
        tamper_probability: r.tamper_probability,
        confidence: r.confidence,
        duration_s: r.duration_s || 0,
        explanation: r.explanation || [],
        checks: r.checks || [],
        segments: r.suspicious_segments || [],
        sha256: r.file_sha256 || '',
        fileName: file.name,
        fileSize: file.size,
      };
    }
    if (st.status === 'failed') throw new Error('Server analysis failed.');
    await new Promise(r => setTimeout(r, 1200));
  }
  throw new Error('Analysis timed out.');
}

// ── Hybrid analysis ──────────────────────────────────────────────────────────

async function runHybridAnalysis(file, options, baseUrl) {
  const clientReport = await runClientAnalysis(file, options);

  if (!baseUrl) return clientReport;

  showProgress(96, 'Enhancing with server analysis...', 'Hybrid');
  try {
    const serverReport = await runRemoteAnalysis(file, options, baseUrl);
    const merged = mergeReports(clientReport, serverReport);
    merged.mode = 'hybrid';
    return merged;
  } catch {
    clientReport.explanation.push('Server enhancement was unavailable; results are client-only.');
    return clientReport;
  }
}

function mergeReports(client, server) {
  const serverCheckNames = new Set((server.checks || []).map(c => c.name));
  const mergedChecks = [...(server.checks || [])];
  for (const c of (client.checks || [])) {
    if (!serverCheckNames.has(c.name)) mergedChecks.push(c);
  }
  const allSegs = [...(client.segments || []), ...(server.segments || [])]
    .sort((a, b) => a.start_s - b.start_s);

  const { probability, confidence, label } = fuseScores(mergedChecks, getOptions().sensitivity);
  const explanation = buildExplanation(mergedChecks, label);

  return {
    ...server,
    mode: 'hybrid',
    label,
    tamper_probability: Number(probability.toFixed(4)),
    confidence: Number(confidence.toFixed(4)),
    explanation,
    checks: mergedChecks,
    segments: allSegs.slice(0, 200),
    sha256: client.sha256 || server.sha256,
    fileName: client.fileName || server.fileName,
    fileSize: client.fileSize || server.fileSize,
    duration_s: server.duration_s || client.duration_s,
  };
}

// ── Event wiring ─────────────────────────────────────────────────────────────

function init() {
  if (dom.presetSelect) {
    dom.presetSelect.addEventListener('change', () => applyPreset(dom.presetSelect.value));
  }

  if (dom.testServerBtn) {
    dom.testServerBtn.addEventListener('click', async () => {
      hideError();
      const { baseUrl, error } = parseBaseUrl(dom.serverUrl?.value);
      if (error) { showError(error); return; }
      dom.testServerBtn.disabled = true;
      try {
        await ensureSession(baseUrl);
        if (dom.serverStatus) {
          dom.serverStatus.textContent = 'Connected';
          dom.serverStatus.className = 'status-pill online';
        }
        localStorage.setItem(BASE_URL_KEY, baseUrl);
      } catch (e) {
        showError(`Cannot reach server: ${e.message}`);
        if (dom.serverStatus) {
          dom.serverStatus.textContent = 'Disconnected';
          dom.serverStatus.className = 'status-pill attention';
        }
      } finally {
        dom.testServerBtn.disabled = false;
      }
    });
  }

  if (dom.serverUrl) {
    const saved = localStorage.getItem(BASE_URL_KEY);
    if (saved) dom.serverUrl.value = saved;
  }

  if (dom.downloadBtn) {
    dom.downloadBtn.addEventListener('click', () => {
      if (!latestReport) { showError('Run an analysis first.'); return; }
      downloadReport(latestReport);
    });
  }

  if (dom.form) {
    dom.form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (isAnalyzing) return;
      hideError();

      const file = dom.fileInput?.files?.[0];
      if (!file) { showError('Select a video file.'); return; }

      isAnalyzing = true;
      if (dom.analyzeBtn) dom.analyzeBtn.disabled = true;
      dom.resultCard.classList.add('hidden');

      try {
        const options = getOptions();
        const mode = dom.modeSelect?.value || 'client';
        let report;

        resetCheckStatuses();

        if (mode === 'remote') {
          const { baseUrl, error } = parseBaseUrl(dom.serverUrl?.value);
          if (!baseUrl || error) throw new Error(error || 'Enter a server URL for remote mode.');
          report = await runRemoteAnalysis(file, options, baseUrl);
        } else if (mode === 'hybrid') {
          const { baseUrl } = parseBaseUrl(dom.serverUrl?.value);
          report = await runHybridAnalysis(file, options, baseUrl);
        } else {
          report = await runClientAnalysis(file, options);
        }

        latestReport = report;
        renderResult(report);
      } catch (err) {
        showError(err.message);
      } finally {
        isAnalyzing = false;
        if (dom.analyzeBtn) dom.analyzeBtn.disabled = false;
        hideProgress();
      }
    });
  }

  const params = new URLSearchParams(location.search);
  if (params.get('api') && dom.serverUrl) {
    dom.serverUrl.value = params.get('api');
  }
  if (params.get('mode') && dom.modeSelect) {
    dom.modeSelect.value = params.get('mode');
  }
}

function resetCheckStatuses() {
  for (const name of ['container', 'timing', 'structure', 'audio', 'visual']) {
    setCheckStatus(name, 'pending');
  }
}

init();
