const form = document.getElementById("analyze-form");
const analyzeBtn = document.getElementById("analyze-btn");
const progressCard = document.getElementById("progress-card");
const progressText = document.getElementById("progress-text");
const progressBar = document.getElementById("progress-bar");
const resultCard = document.getElementById("result-card");
const resultMode = document.getElementById("result-mode");
const resultLabel = document.getElementById("result-label");
const resultMeaning = document.getElementById("result-meaning");
const resultProbability = document.getElementById("result-probability");
const resultConfidence = document.getElementById("result-confidence");
const resultDuration = document.getElementById("result-duration");
const resultMeter = document.getElementById("result-meter");
const resultExplanation = document.getElementById("result-explanation");
const resultCheckBars = document.getElementById("result-check-bars");
const resultTimeline = document.getElementById("result-timeline");
const resultSegments = document.getElementById("result-segments");
const resultSignals = document.getElementById("result-signals");
const downloadReportBtn = document.getElementById("download-report-btn");
const remoteApiUrlInput = document.getElementById("remote-api-url");
const useRemoteApiInput = document.getElementById("use-remote-api");
const generateSessionBtn = document.getElementById("generate-session-btn");
const clearSessionBtn = document.getElementById("clear-session-btn");
const sessionKeyDisplay = document.getElementById("session-key-display");
const sessionKeyStatus = document.getElementById("session-key-status");
const sessionQuotaStatus = document.getElementById("session-quota-status");
const remoteError = document.getElementById("remote-error");

const REMOTE_SESSION_PREFIX = "qvk.remote.session.";
const FALLBACK_LIMIT = 10;
let latestReport = null;

function setProgress(percent, text) {
  progressCard.classList.remove("hidden");
  progressBar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
  progressText.textContent = text;
}

function setRemoteError(message) {
  if (!message) {
    remoteError.textContent = "";
    remoteError.classList.add("hidden");
    return;
  }
  remoteError.textContent = message;
  remoteError.classList.remove("hidden");
}

function verdictColor(label) {
  if (label === "tampered") return "#b00020";
  if (label === "suspicious") return "#cc6600";
  if (label === "authentic") return "#1f7a1f";
  return "#555";
}

function plainMeaning(label, probability, confidence) {
  if (label === "tampered") {
    return `Strong manipulation indicators were detected (${(probability * 100).toFixed(1)}% probability, ${(confidence * 100).toFixed(1)}% confidence).`;
  }
  if (label === "suspicious") {
    return `Some forensic signals are unusual (${(probability * 100).toFixed(1)}% probability). Manual review recommended.`;
  }
  if (label === "authentic") {
    return `No strong manipulation pattern was detected (${(probability * 100).toFixed(1)}% probability).`;
  }
  return "The evidence quality was not high enough for a definitive conclusion.";
}

function explainCheck(check) {
  const map = {
    metadata_codec_consistency: "Compares metadata and stream declarations for consistency.",
    packet_timing_anomalies: "Checks packet timeline continuity for jumps and timestamp inconsistencies.",
    frame_structure_anomalies: "Checks frame/GOP structure for unusual transitions across the clip.",
    frame_quality_shift: "Measures abrupt visual quality changes and continuity behavior."
  };
  return map[check.name] || "This detector contributes to overall forensic risk scoring.";
}

function normalizeChecks(report) {
  if (report?.signals?.checks && Array.isArray(report.signals.checks) && report.signals.checks.length) {
    return report.signals.checks;
  }
  const signals = report.signals || {};
  const derived = [];
  const duplicateCount = (signals.duplicate_events || []).length;
  const missingCount = (signals.missing_frame_events || []).length;
  const qualityCount = (signals.quality_shift_events || []).length;
  if (duplicateCount || missingCount || qualityCount) {
    derived.push({
      name: "browser_temporal_continuity",
      score: Math.max(0, Math.min(1, (duplicateCount + missingCount + qualityCount) / Math.max(1, signals.sampled_points || 1) * 8)),
      confidence: report.confidence || 0.5,
      summary: "Derived from duplicate/missing/quality events in browser analysis."
    });
  }
  return derived;
}

function normalizeSegments(report) {
  if (report?.signals?.suspicious_segments && Array.isArray(report.signals.suspicious_segments)) {
    return report.signals.suspicious_segments;
  }
  const signals = report.signals || {};
  const merge = (arr, category) => (arr || []).map((item) => ({
    category,
    start_s: Number(item.start || 0),
    end_s: Number(item.end || item.start || 0),
    confidence: Number(item.confidence || 0.5)
  }));
  return [
    ...merge(signals.duplicate_events, "duplicate_frames"),
    ...merge(signals.missing_frame_events, "missing_frames"),
    ...merge(signals.quality_shift_events, "quality_shift")
  ];
}

function renderCheckBars(report) {
  resultCheckBars.innerHTML = "";
  const checks = normalizeChecks(report);
  if (!checks.length) {
    resultCheckBars.innerHTML = "<p class='muted'>No check-level details available.</p>";
    return;
  }
  checks.forEach((check) => {
    const score = Math.max(0, Math.min(100, (check.score || 0) * 100));
    const conf = Math.max(0, Math.min(100, (check.confidence || 0) * 100));
    const card = document.createElement("div");
    card.className = "check-item";
    card.innerHTML = `
      <h4>${check.name}</h4>
      <p class="muted">${explainCheck(check)}</p>
      <div class="bar-row">
        <span>Anomaly score</span>
        <div class="bar-track"><div class="bar-fill-score" style="width:${score.toFixed(1)}%"></div></div>
        <strong>${score.toFixed(1)}%</strong>
      </div>
      <div class="bar-row">
        <span>Confidence</span>
        <div class="bar-track"><div class="bar-fill-confidence" style="width:${conf.toFixed(1)}%"></div></div>
        <strong>${conf.toFixed(1)}%</strong>
      </div>
      <p>${check.summary || ""}</p>
    `;
    resultCheckBars.appendChild(card);
  });
}

function renderTimeline(report) {
  const segments = normalizeSegments(report).slice(0, 60);
  resultSegments.innerHTML = "";
  const duration = Math.max(
    Number(report?.signals?.video_duration_s || 0),
    ...segments.map((segment) => Number(segment.end_s || 0)),
    1
  );
  if (!segments.length) {
    resultTimeline.innerHTML = "<p class='muted' style='padding:6px 10px;'>No suspicious segments detected.</p>";
    const li = document.createElement("li");
    li.textContent = "No suspicious timeline windows were identified in this analysis mode.";
    resultSegments.appendChild(li);
    return;
  }
  const blocks = segments.map((segment) => {
    const start = Math.max(0, Math.min(100, (segment.start_s / duration) * 100));
    const end = Math.max(start, Math.min(100, (segment.end_s / duration) * 100));
    const width = Math.max(0.4, end - start);
    const title = `[${segment.category}] ${segment.start_s.toFixed(2)}s-${segment.end_s.toFixed(2)}s (confidence ${segment.confidence.toFixed(2)})`;
    return `<div class="timeline-block" style="left:${start.toFixed(2)}%;width:${width.toFixed(2)}%" title="${title}"></div>`;
  }).join("");
  resultTimeline.innerHTML = blocks;

  segments.forEach((segment) => {
    const li = document.createElement("li");
    li.textContent = `[${segment.category}] ${segment.start_s.toFixed(2)}s - ${segment.end_s.toFixed(2)}s (confidence ${segment.confidence.toFixed(2)}).`;
    resultSegments.appendChild(li);
  });
}

function buildGraphicalReportHtml(report) {
  const checks = normalizeChecks(report);
  const segments = normalizeSegments(report);
  const checksHtml = checks.map((check) => {
    const score = Math.max(0, Math.min(100, (check.score || 0) * 100));
    const conf = Math.max(0, Math.min(100, (check.confidence || 0) * 100));
    return `
      <div class="check">
        <h3>${check.name}</h3>
        <p>${explainCheck(check)}</p>
        <div class="bar"><div class="fill score" style="width:${score.toFixed(1)}%"></div></div>
        <p><strong>Anomaly score:</strong> ${score.toFixed(1)}%</p>
        <div class="bar"><div class="fill conf" style="width:${conf.toFixed(1)}%"></div></div>
        <p><strong>Confidence:</strong> ${conf.toFixed(1)}%</p>
        <p>${check.summary || ""}</p>
      </div>`;
  }).join("");
  const explanation = (report.explanation || []).map((line) => `<li>${line}</li>`).join("");
  const segmentsHtml = segments.slice(0, 30).map(
    (segment) => `<li>[${segment.category}] ${segment.start_s.toFixed(2)}s - ${segment.end_s.toFixed(2)}s (confidence ${segment.confidence.toFixed(2)})</li>`
  ).join("");
  const probability = Math.max(0, Math.min(100, (report.tamper_probability || 0) * 100));
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>quevidkit graphical report</title>
<style>
body{font-family:Arial,sans-serif;background:#f5f6fa;color:#111;margin:20px}
.card{background:#fff;border:1px solid #e2e2e8;border-radius:8px;padding:14px;margin-bottom:12px}
.badge{display:inline-block;padding:6px 12px;border-radius:16px;color:#fff;background:${verdictColor(report.label)};font-weight:700}
.meter{height:14px;border-radius:20px;background:#e8ebf3;overflow:hidden;margin-top:8px}
.meter>div{height:14px;width:${probability.toFixed(1)}%;background:linear-gradient(90deg,#1f7a1f 0%,#cc6600 60%,#b00020 100%)}
.checks{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}
.check{border:1px solid #e4e6ee;border-radius:8px;padding:10px}
.bar{height:10px;border-radius:20px;background:#eceff6;overflow:hidden}
.fill{height:10px}.score{background:#b00020}.conf{background:#1a4fd8}
</style></head><body>
<h1>quevidkit graphical forensic report</h1>
<div class="card">
  <p><strong>Mode:</strong> ${report.mode || "unknown"}</p>
  <span class="badge">${String(report.label || "inconclusive").toUpperCase()}</span>
  <p>${plainMeaning(report.label, report.tamper_probability || 0, report.confidence || 0)}</p>
  <p><strong>Tamper probability:</strong> ${probability.toFixed(1)}%</p>
  <p><strong>Confidence:</strong> ${((report.confidence || 0) * 100).toFixed(1)}%</p>
  <div class="meter"><div></div></div>
</div>
<div class="card"><h2>Plain-language explanation</h2><ul>${explanation || "<li>No explanation available.</li>"}</ul></div>
<div class="card"><h2>Evidence checks</h2><div class="checks">${checksHtml || "<p>No check data.</p>"}</div></div>
<div class="card"><h2>Suspicious segments</h2><ul>${segmentsHtml || "<li>None</li>"}</ul></div>
</body></html>`;
}

function normalizeBaseUrl(raw) {
  return (raw || "").trim().replace(/\/+$/, "");
}

function sessionStorageKey(baseUrl) {
  return `${REMOTE_SESSION_PREFIX}${baseUrl}`;
}

function loadRemoteSession(baseUrl) {
  if (!baseUrl) return null;
  try {
    const raw = sessionStorage.getItem(sessionStorageKey(baseUrl));
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function saveRemoteSession(baseUrl, payload) {
  if (!baseUrl) return;
  sessionStorage.setItem(sessionStorageKey(baseUrl), JSON.stringify(payload));
}

function clearRemoteSession(baseUrl) {
  if (!baseUrl) return;
  sessionStorage.removeItem(sessionStorageKey(baseUrl));
}

function maskSessionKey(key) {
  if (!key) return "";
  if (key.length <= 14) return key;
  return `${key.slice(0, 8)}...${key.slice(-6)}`;
}

function isSessionExpired(session) {
  if (!session || !session.expiresAtMs) return true;
  return Date.now() >= session.expiresAtMs;
}

function renderRemoteSessionState() {
  const baseUrl = normalizeBaseUrl(remoteApiUrlInput.value);
  const session = loadRemoteSession(baseUrl);
  if (!session) {
    sessionKeyDisplay.value = "";
    sessionKeyStatus.textContent = "No active key. Click Generate Session Key.";
    sessionQuotaStatus.textContent = "Generation limit: 10 keys per window.";
    return;
  }
  const expired = isSessionExpired(session);
  sessionKeyDisplay.value = maskSessionKey(session.sessionKey);
  if (expired) {
    sessionKeyStatus.textContent = "Session key expired. Generate a new one.";
  } else {
    sessionKeyStatus.textContent = `Active key expires at ${new Date(session.expiresAtMs).toLocaleString()}.`;
  }
  const quota = session.rateLimit || {};
  const qLimit = quota.limit ?? FALLBACK_LIMIT;
  const qRemaining = quota.remaining ?? "unknown";
  const jobQuota = session.jobQuota || {};
  const jobLimit = jobQuota.limit ?? FALLBACK_LIMIT;
  const jobRemaining = jobQuota.remaining ?? "unknown";
  sessionQuotaStatus.textContent = `Key generation: ${qRemaining}/${qLimit} remaining. Job quota on key: ${jobRemaining}/${jobLimit}.`;
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function generateRemoteSessionKey() {
  setRemoteError("");
  const baseUrl = normalizeBaseUrl(remoteApiUrlInput.value);
  if (!baseUrl) throw new Error("Provide Remote API URL first.");
  const response = await fetch(`${baseUrl}/api/v1/session-key`, { method: "POST" });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Session key generation failed: ${body}`);
  }
  const payload = await response.json();
  const expiresMs = new Date(payload.expires_at_utc).getTime();
  const record = {
    sessionKey: payload.session_key,
    expiresAtMs: Number.isFinite(expiresMs) ? expiresMs : Date.now() + 30 * 60 * 1000,
    rateLimit: payload.rate_limit || { limit: FALLBACK_LIMIT, remaining: FALLBACK_LIMIT },
    jobQuota: payload.job_quota || { limit: FALLBACK_LIMIT, remaining: FALLBACK_LIMIT }
  };
  saveRemoteSession(baseUrl, record);
  renderRemoteSessionState();
}

function requireActiveRemoteSession(baseUrl) {
  const session = loadRemoteSession(baseUrl);
  if (!session || isSessionExpired(session)) {
    throw new Error("Generate a new session key first.");
  }
  return session;
}

async function remoteFetch(baseUrl, path, init = {}) {
  const session = requireActiveRemoteSession(baseUrl);
  const headers = new Headers(init.headers || {});
  headers.set("X-Session-Key", session.sessionKey);
  const response = await fetch(`${baseUrl}${path}`, { ...init, headers });
  if (response.status === 401) {
    clearRemoteSession(baseUrl);
    renderRemoteSessionState();
    throw new Error("Session key invalid/expired. Generate a new one.");
  }
  if (response.status === 429) {
    const body = await response.text();
    throw new Error(`Rate limited: ${body}`);
  }
  return response;
}

function averageHash(gray, width, height) {
  const targetW = 8;
  const targetH = 8;
  const cellW = width / targetW;
  const cellH = height / targetH;
  const sample = [];
  for (let y = 0; y < targetH; y++) {
    for (let x = 0; x < targetW; x++) {
      const px = Math.min(width - 1, Math.floor((x + 0.5) * cellW));
      const py = Math.min(height - 1, Math.floor((y + 0.5) * cellH));
      sample.push(gray[py * width + px]);
    }
  }
  const mean = sample.reduce((a, b) => a + b, 0) / sample.length;
  return sample.map((v) => (v >= mean ? 1 : 0));
}

function hammingBits(a, b) {
  let d = 0;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) d += 1;
  }
  return d;
}

function getGrayFromImageData(imageData) {
  const { data, width, height } = imageData;
  const gray = new Uint8Array(width * height);
  let idx = 0;
  for (let i = 0; i < data.length; i += 4) {
    gray[idx] = Math.round(0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]);
    idx += 1;
  }
  return { gray, width, height };
}

function meanAbsDiff(a, b) {
  const len = Math.min(a.length, b.length);
  let sum = 0;
  for (let i = 0; i < len; i++) {
    sum += Math.abs(a[i] - b[i]);
  }
  return sum / Math.max(1, len);
}

function laplacianVariance(gray, width, height) {
  if (width < 3 || height < 3) return 0;
  let mean = 0;
  let sq = 0;
  let count = 0;
  for (let y = 1; y < height - 1; y++) {
    for (let x = 1; x < width - 1; x++) {
      const c = gray[y * width + x];
      const up = gray[(y - 1) * width + x];
      const down = gray[(y + 1) * width + x];
      const left = gray[y * width + (x - 1)];
      const right = gray[y * width + (x + 1)];
      const lap = 4 * c - up - down - left - right;
      mean += lap;
      sq += lap * lap;
      count += 1;
    }
  }
  if (!count) return 0;
  mean /= count;
  return sq / count - mean * mean;
}

function blockiness(gray, width, height) {
  if (width < 17 || height < 17) return 0;
  let edge = 0;
  let edgeCount = 0;
  let inner = 0;
  let innerCount = 0;
  for (let x = 8; x < width; x += 8) {
    for (let y = 0; y < height; y++) {
      edge += Math.abs(gray[y * width + x] - gray[y * width + (x - 1)]);
      edgeCount += 1;
    }
  }
  for (let y = 8; y < height; y += 8) {
    for (let x = 0; x < width; x++) {
      edge += Math.abs(gray[y * width + x] - gray[(y - 1) * width + x]);
      edgeCount += 1;
    }
  }
  for (let x = 4; x < width; x += 8) {
    for (let y = 0; y < height; y++) {
      inner += Math.abs(gray[y * width + x] - gray[y * width + (x - 1)]);
      innerCount += 1;
    }
  }
  for (let y = 4; y < height; y += 8) {
    for (let x = 0; x < width; x++) {
      inner += Math.abs(gray[y * width + x] - gray[(y - 1) * width + x]);
      innerCount += 1;
    }
  }
  const e = edge / Math.max(1, edgeCount);
  const i = inner / Math.max(1, innerCount);
  return Math.max(0, e - i);
}

function median(values) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const m = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[m] : (sorted[m - 1] + sorted[m]) / 2;
}

function mad(values, center) {
  if (!values.length) return 1;
  const dev = values.map((v) => Math.abs(v - center));
  const spread = median(dev);
  return spread > 1e-9 ? spread : 1;
}

function sigmoid(x) {
  return 1 / (1 + Math.exp(-x));
}

function waitSeek(video, t) {
  return new Promise((resolve, reject) => {
    const onSeeked = () => {
      video.removeEventListener("seeked", onSeeked);
      resolve();
    };
    const onError = () => {
      video.removeEventListener("error", onError);
      reject(new Error("Video seek failed"));
    };
    video.addEventListener("seeked", onSeeked, { once: true });
    video.addEventListener("error", onError, { once: true });
    video.currentTime = t;
  });
}

function loadVideoMetadata(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const video = document.createElement("video");
    video.preload = "metadata";
    video.muted = true;
    video.src = url;
    video.onloadedmetadata = () => {
      resolve({ video, url, duration: video.duration, width: video.videoWidth, height: video.videoHeight });
    };
    video.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("Could not read video metadata in browser."));
    };
  });
}

async function analyzeInBrowser(file, options) {
  const meta = await loadVideoMetadata(file);
  const canvas = document.createElement("canvas");
  canvas.width = 320;
  canvas.height = 180;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) throw new Error("Canvas context unavailable.");

  const sampleTimes = [];
  for (let t = 0; t < meta.duration; t += options.sampleInterval) {
    sampleTimes.push(t);
    if (sampleTimes.length >= options.maxSamples) break;
  }
  if (!sampleTimes.length) sampleTimes.push(0);

  const blurs = [];
  const blockinessValues = [];
  const duplicateSegments = [];
  let duplicateRunStart = null;

  let prevGray = null;
  let prevHash = null;
  let prevTime = 0;
  const missingSignals = [];

  for (let i = 0; i < sampleTimes.length; i++) {
    const t = sampleTimes[i];
    await waitSeek(meta.video, t);
    ctx.drawImage(meta.video, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const { gray, width, height } = getGrayFromImageData(imageData);
    const h = averageHash(gray, width, height);
    const blur = laplacianVariance(gray, width, height);
    const block = blockiness(gray, width, height);

    blurs.push(blur);
    blockinessValues.push(block);
    if (prevGray && prevHash) {
      const diff = meanAbsDiff(gray, prevGray);
      const hd = hammingBits(h, prevHash) / 64;
      if (hd < 0.06 && diff < 3.2) {
        if (duplicateRunStart === null) duplicateRunStart = sampleTimes[i - 1];
      } else if (duplicateRunStart !== null) {
        duplicateSegments.push({ start: duplicateRunStart, end: t, confidence: 0.86 });
        duplicateRunStart = null;
      }
      const observedDelta = t - prevTime;
      if (observedDelta > options.sampleInterval * 1.8) {
        missingSignals.push({
          start: prevTime,
          end: t,
          confidence: Math.min(0.96, 0.55 + (observedDelta / options.sampleInterval) * 0.08)
        });
      }
    }

    prevGray = gray;
    prevHash = h;
    prevTime = t;

    const p = 10 + Math.round((i / sampleTimes.length) * 80);
    setProgress(p, `Browser analysis (${i + 1}/${sampleTimes.length})`);
    await sleep(0);
  }
  if (duplicateRunStart !== null && sampleTimes.length > 1) {
    duplicateSegments.push({ start: duplicateRunStart, end: sampleTimes[sampleTimes.length - 1], confidence: 0.84 });
  }

  URL.revokeObjectURL(meta.url);

  const qualityShifts = [];
  const shifts = [];
  for (let i = 1; i < blurs.length; i++) {
    const shift = Math.abs(blurs[i] - blurs[i - 1]) * 0.7 + Math.abs(blockinessValues[i] - blockinessValues[i - 1]) * 0.3;
    shifts.push(shift);
  }
  const center = median(shifts);
  const spread = mad(shifts, center);
  for (let i = 0; i < shifts.length; i++) {
    const z = (shifts[i] - center) / (1.4826 * spread + 1e-9);
    if (z > 4) {
      qualityShifts.push({
        start: sampleTimes[i],
        end: sampleTimes[Math.min(sampleTimes.length - 1, i + 1)],
        confidence: Math.min(0.98, 0.55 + z / 10),
        z
      });
    }
  }

  const duplicateRate = duplicateSegments.length / Math.max(1, sampleTimes.length);
  const missingRate = missingSignals.length / Math.max(1, sampleTimes.length);
  const qualityRate = qualityShifts.length / Math.max(1, sampleTimes.length);

  const anomalyScore = Math.max(0, Math.min(1, duplicateRate * 8 + missingRate * 6 + qualityRate * 10));
  const bias = -2.6 + options.sensitivity * 1.6;
  const probability = sigmoid(bias + anomalyScore * 5.2 + 0.25);
  const confidence = Math.max(0.2, Math.min(0.95, 0.35 + sampleTimes.length / options.maxSamples));

  let label = "authentic";
  if (confidence < 0.35) label = "inconclusive";
  else if (probability >= 0.6) label = "tampered";
  else if (probability >= 0.35) label = "suspicious";

  return {
    mode: "browser",
    label,
    tamper_probability: Number(probability.toFixed(4)),
    confidence: Number(confidence.toFixed(4)),
    explanation: [
      "Browser mode detected frame-level continuity and quality signals.",
      "Comprehensive metadata/packet/codec forensics require Remote API mode with a generated session key."
    ],
    signals: {
      file_name: file.name,
      file_size_bytes: file.size,
      video_duration_s: Number(meta.duration.toFixed(3)),
      video_resolution: `${meta.width}x${meta.height}`,
      sampled_points: sampleTimes.length,
      duplicate_events: duplicateSegments,
      missing_frame_events: missingSignals,
      quality_shift_events: qualityShifts
    }
  };
}

async function createRemoteJob(baseUrl, file, options) {
  const payload = {
    preset: "balanced",
    sample_fps: Number((1 / options.sampleInterval).toFixed(3)),
    max_frames: options.maxSamples,
    sensitivity: options.sensitivity
  };
  const formData = new FormData();
  formData.append("file", file);
  formData.append("options", JSON.stringify(payload));
  const resp = await remoteFetch(baseUrl, "/api/v1/jobs", { method: "POST", body: formData });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Remote job creation failed: ${body}`);
  }
  const job = await resp.json();
  const session = loadRemoteSession(baseUrl);
  if (session && typeof job.session_key_remaining_jobs === "number") {
    session.jobQuota = session.jobQuota || { limit: FALLBACK_LIMIT, remaining: FALLBACK_LIMIT };
    session.jobQuota.remaining = job.session_key_remaining_jobs;
    saveRemoteSession(baseUrl, session);
    renderRemoteSessionState();
  }
  return job;
}

async function pollRemoteResult(baseUrl, jobId) {
  let attempts = 0;
  while (attempts < 900) {
    attempts += 1;
    const statusResp = await remoteFetch(baseUrl, `/api/v1/jobs/${jobId}`, { method: "GET" });
    if (!statusResp.ok) throw new Error("Remote status request failed.");
    const status = await statusResp.json();
    setProgress(status.progress_percent || 0, `Remote API: ${status.phase || status.status}`);
    if (status.status === "completed") {
      const resultResp = await remoteFetch(baseUrl, `/api/v1/jobs/${jobId}/result`, { method: "GET" });
      if (!resultResp.ok) throw new Error("Remote result request failed.");
      const resultPayload = await resultResp.json();
      const result = resultPayload.result || {};
      return {
        mode: "remote_api",
        label: result.label,
        tamper_probability: result.tamper_probability,
        confidence: result.confidence,
        explanation: result.explanation || ["Remote analysis completed."],
        signals: {
          checks: result.checks || [],
          suspicious_segments: result.suspicious_segments || []
        }
      };
    }
    if (status.status === "failed") throw new Error(status.message || "Remote analysis failed.");
    await sleep(1200);
  }
  throw new Error("Remote analysis timed out.");
}

function renderResult(report) {
  latestReport = report;
  resultCard.classList.remove("hidden");
  resultMode.textContent = report.mode;
  const label = report.label || "inconclusive";
  const probability = report.tamper_probability || 0;
  const confidence = report.confidence || 0;
  const segments = normalizeSegments(report);
  const duration = Math.max(Number(report?.signals?.video_duration_s || 0), ...segments.map((segment) => Number(segment.end_s || 0)), 0);
  resultLabel.textContent = label.toUpperCase();
  resultLabel.style.background = verdictColor(label);
  resultMeaning.textContent = plainMeaning(label, probability, confidence);
  resultProbability.textContent = `${(probability * 100).toFixed(1)}%`;
  resultConfidence.textContent = `${(confidence * 100).toFixed(1)}%`;
  resultDuration.textContent = `${duration.toFixed(2)}s`;
  resultMeter.style.width = `${(probability * 100).toFixed(1)}%`;
  resultExplanation.innerHTML = "";
  (report.explanation || []).forEach((line) => {
    const li = document.createElement("li");
    li.textContent = line;
    resultExplanation.appendChild(li);
  });
  renderCheckBars(report);
  renderTimeline(report);
  resultSignals.textContent = JSON.stringify(report.signals || {}, null, 2);
}

function getOptions() {
  return {
    sampleInterval: Math.max(0.1, Math.min(5, Number(document.getElementById("sample-interval").value || "0.5"))),
    maxSamples: Math.max(10, Math.min(2000, Number(document.getElementById("max-samples").value || "240"))),
    sensitivity: Math.max(0.05, Math.min(0.99, Number(document.getElementById("sensitivity").value || "0.7"))),
    useRemoteApi: useRemoteApiInput.checked
  };
}

generateSessionBtn.addEventListener("click", async () => {
  generateSessionBtn.disabled = true;
  setRemoteError("");
  try {
    await generateRemoteSessionKey();
  } catch (error) {
    setRemoteError(error.message);
  } finally {
    generateSessionBtn.disabled = false;
  }
});

clearSessionBtn.addEventListener("click", () => {
  const baseUrl = normalizeBaseUrl(remoteApiUrlInput.value);
  clearRemoteSession(baseUrl);
  renderRemoteSessionState();
});

remoteApiUrlInput.addEventListener("change", () => {
  setRemoteError("");
  renderRemoteSessionState();
});

useRemoteApiInput.addEventListener("change", () => {
  setRemoteError("");
  renderRemoteSessionState();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setRemoteError("");
  const fileInput = document.getElementById("video-file");
  const file = fileInput.files && fileInput.files[0];
  if (!file) {
    alert("Select a video file first.");
    return;
  }
  analyzeBtn.disabled = true;
  resultCard.classList.add("hidden");
  setProgress(5, "Preparing analysis");

  try {
    const options = getOptions();
    let report;
    if (options.useRemoteApi) {
      const baseUrl = normalizeBaseUrl(remoteApiUrlInput.value);
      if (!baseUrl) throw new Error("Provide Remote API URL first.");
      requireActiveRemoteSession(baseUrl);
      setProgress(10, "Creating remote job");
      const job = await createRemoteJob(baseUrl, file, options);
      report = await pollRemoteResult(baseUrl, job.job_id);
    } else {
      report = await analyzeInBrowser(file, options);
      setProgress(100, "Browser analysis complete");
    }
    renderResult(report);
  } catch (error) {
    setRemoteError(error.message);
    alert(`Error: ${error.message}`);
  } finally {
    analyzeBtn.disabled = false;
  }
});

downloadReportBtn.addEventListener("click", () => {
  if (!latestReport) {
    alert("Run an analysis first.");
    return;
  }
  const htmlReport = buildGraphicalReportHtml(latestReport);
  const blob = new Blob([htmlReport], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `quevidkit_graphical_report_${Date.now()}.html`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
});

renderRemoteSessionState();
