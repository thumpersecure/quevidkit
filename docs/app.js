const form = document.getElementById("analyze-form");
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
const analyzeBrowserBtn = document.getElementById("analyze-browser-btn");
const analyzeRemoteBtn = document.getElementById("analyze-remote-btn");
const remoteApiUrlInput = document.getElementById("remote-api-url");
const useLocalFastapiBtn = document.getElementById("use-local-fastapi-btn");
const generateSessionBtn = document.getElementById("generate-session-btn");
const copySessionBtn = document.getElementById("copy-session-btn");
const revealSessionBtn = document.getElementById("reveal-session-btn");
const clearSessionBtn = document.getElementById("clear-session-btn");
const sessionKeyDisplay = document.getElementById("session-key-display");
const sessionKeyStatus = document.getElementById("session-key-status");
const sessionQuotaStatus = document.getElementById("session-quota-status");
const remoteError = document.getElementById("remote-error");
const remoteEndpointPreview = document.getElementById("remote-endpoint-preview");
const remoteModePill = document.getElementById("remote-mode-pill");

const analysisPreset = document.getElementById("analysis-preset");
const demoVideoBtn = document.getElementById("demo-video-btn");

const REMOTE_SESSION_PREFIX = "qvk.remote.session.";
const REMOTE_BASE_URL_STORAGE_KEY = "qvk.remote.baseUrl";
const FALLBACK_LIMIT = 10;
let latestReport = null;
let preferredAnalyzeMode = "browser";
let revealSessionKey = false;

// ── UI utilities ────────────────────────────────────────────────────────────

function setAnalyzeButtonsDisabled(disabled) {
  analyzeBrowserBtn.disabled = disabled;
  analyzeRemoteBtn.disabled = disabled;
}

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

const RISK_GRADIENT = "linear-gradient(90deg, #3dd68c 0%, #f6b73c 55%, #ff5a6b 100%)";

function verdictColor(label) {
  if (label === "tampered") return "#ff5a6b";
  if (label === "suspicious") return "#f6b73c";
  if (label === "authentic") return "#3dd68c";
  return "#6f7d97";
}

function isCorsLikeError(error, url) {
  if (!(error instanceof TypeError)) return false;
  if (!url) return false;
  const msg = error.message || "";
  return msg.includes("fetch") || msg.includes("network") || msg.includes("Failed");
}

// ── Humanization helpers ────────────────────────────────────────────────────

function humanizeCheckName(name) {
  const map = {
    metadata_codec_consistency: "Metadata consistency",
    packet_timing_anomalies: "Packet timing",
    frame_structure_anomalies: "Frame structure",
    frame_quality_shift: "Visual quality shifts",
    browser_temporal_continuity: "Frame continuity (browser)"
  };
  return map[name] || (name || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function humanizeCategory(cat) {
  const map = {
    duplicate_frames: "Duplicate frames",
    missing_frames: "Missing frames",
    quality_shift: "Quality shift"
  };
  return map[cat] || (cat || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function humanizePhase(phase) {
  const map = {
    queued: "Waiting for server...",
    extracting_metadata: "Reading video metadata...",
    forensic_analysis: "Running forensic analysis...",
    done: "Analysis complete!",
    completed: "Analysis complete!",
    failed: "Analysis failed"
  };
  return map[phase] || (phase ? phase.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()) : "Processing...");
}

function humanizeMode(mode) {
  if (mode === "browser") return "Browser (quick check)";
  if (mode === "remote_api") return "Server (deep scan)";
  return mode || "unknown";
}

// ── Result text helpers ─────────────────────────────────────────────────────

function plainMeaning(label, probability, confidence) {
  const probPct = (probability * 100).toFixed(1);
  const confPct = (confidence * 100).toFixed(1);
  if (label === "tampered") {
    return `Our analysis found strong signs that this video may have been edited or manipulated. Probability: ${probPct}%, Confidence: ${confPct}%.`;
  }
  if (label === "authentic") {
    return `No significant manipulation was detected in this video. Probability: ${probPct}%, Confidence: ${confPct}%.`;
  }
  if (label === "suspicious") {
    return `Some unusual patterns were detected that warrant further review. Probability: ${probPct}%.`;
  }
  return "The video could not be assessed with sufficient confidence. Try using the deep server scan for more detailed analysis.";
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

// ── Render functions ────────────────────────────────────────────────────────

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
      <h4>${humanizeCheckName(check.name)}</h4>
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
    const catLabel = humanizeCategory(segment.category);
    const title = `[${catLabel}] ${segment.start_s.toFixed(2)}s-${segment.end_s.toFixed(2)}s (confidence ${segment.confidence.toFixed(2)})`;
    return `<div class="timeline-block" style="left:${start.toFixed(2)}%;width:${width.toFixed(2)}%" title="${title}"></div>`;
  }).join("");
  resultTimeline.innerHTML = blocks;

  segments.forEach((segment) => {
    const li = document.createElement("li");
    li.textContent = `[${humanizeCategory(segment.category)}] ${segment.start_s.toFixed(2)}s - ${segment.end_s.toFixed(2)}s (confidence ${segment.confidence.toFixed(2)}).`;
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
        <h3>${humanizeCheckName(check.name)}</h3>
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
    (segment) => `<li>[${humanizeCategory(segment.category)}] ${segment.start_s.toFixed(2)}s - ${segment.end_s.toFixed(2)}s (confidence ${segment.confidence.toFixed(2)})</li>`
  ).join("");
  const probability = Math.max(0, Math.min(100, (report.tamper_probability || 0) * 100));
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>quevidkit graphical report</title>
<style>
body{font-family:Arial,sans-serif;background:radial-gradient(circle at top,#18253e 0%,#08111f 62%,#050914 100%);color:#edf4ff;margin:0;padding:24px}
.shell{max-width:1100px;margin:0 auto}
.card{background:rgba(16,24,39,0.94);border:1px solid #2d3c5a;border-radius:14px;padding:16px;margin-bottom:14px;box-shadow:0 18px 44px rgba(0,0,0,0.28)}
.eyebrow{text-transform:uppercase;letter-spacing:0.18em;color:#8bd4ff;font-size:0.75rem;margin:0 0 10px}
.badge{display:inline-block;padding:7px 14px;border-radius:999px;color:#06111c;background:${verdictColor(report.label)};font-weight:700;letter-spacing:0.08em}
.meter{height:14px;border-radius:999px;background:#0a1527;overflow:hidden;margin-top:10px;border:1px solid #263653}
.meter>div{height:14px;width:${probability.toFixed(1)}%;background:${RISK_GRADIENT}}
.checks{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}
.check{border:1px solid #2d3c5a;border-radius:12px;padding:12px;background:rgba(8,17,31,0.78)}
.bar{height:10px;border-radius:999px;background:#0a1527;overflow:hidden;border:1px solid #22314d}
.fill{height:10px}.score{background:#ff5a6b}.conf{background:#5aa9ff}
p,li{color:#c4d3ea;line-height:1.55}
h1,h2,h3,strong{color:#edf4ff}
ul{padding-left:20px}
</style></head><body>
<div class="shell">
<div class="card">
  <p class="eyebrow">Case file / graphical forensic report</p>
  <h1>quevidkit investigation summary</h1>
  <p><strong>Mode:</strong> ${humanizeMode(report.mode)}</p>
  <span class="badge">${String(report.label || "inconclusive").toUpperCase()}</span>
  <p>${plainMeaning(report.label, report.tamper_probability || 0, report.confidence || 0)}</p>
  <p><strong>Tamper probability:</strong> ${probability.toFixed(1)}%</p>
  <p><strong>Confidence:</strong> ${((report.confidence || 0) * 100).toFixed(1)}%</p>
  <div class="meter"><div></div></div>
</div>
<div class="card"><h2>Plain-language explanation</h2><ul>${explanation || "<li>No explanation available.</li>"}</ul></div>
<div class="card"><h2>Evidence checks</h2><div class="checks">${checksHtml || "<p>No check data.</p>"}</div></div>
<div class="card"><h2>Suspicious segments</h2><ul>${segmentsHtml || "<li>None</li>"}</ul></div>
</div>
</body></html>`;
}

// ── URL parsing ─────────────────────────────────────────────────────────────

function parseRemoteBaseUrl(raw) {
  const value = (raw || "").trim();
  if (!value) {
    return { baseUrl: "", error: "Enter your server base URL." };
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return { baseUrl: "", error: "Invalid URL format. Use http://... or https://..." };
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { baseUrl: "", error: "URL must start with http:// or https://." };
  }
  if (parsed.search || parsed.hash) {
    return { baseUrl: "", error: "Remove query parameters/hash from the base URL." };
  }
  let path = parsed.pathname.replace(/\/+$/, "");
  if (path.endsWith("/api/v1")) path = path.slice(0, -7);
  else if (path.endsWith("/api")) path = path.slice(0, -4);
  const baseUrl = `${parsed.origin}${path}`;
  if (window.location.protocol === "https:" && parsed.protocol === "http:" && parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1") {
    return { baseUrl, error: "HTTPS pages cannot call non-local HTTP APIs (mixed content blocked)." };
  }
  return { baseUrl, error: "" };
}

function normalizeBaseUrl(raw) {
  return parseRemoteBaseUrl(raw).baseUrl;
}

function sessionKeyEndpoint(baseUrl) {
  return `${baseUrl}/api/v1/session-key`;
}

function inferLocalFastapiUrl() {
  if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
    return "http://127.0.0.1:8000";
  }
  return "";
}

// ── Mode and UI state ───────────────────────────────────────────────────────

function setAnalyzeMode(mode) {
  preferredAnalyzeMode = mode === "remote" ? "remote" : "browser";
  analyzeBrowserBtn.classList.toggle("is-selected", preferredAnalyzeMode === "browser");
  analyzeRemoteBtn.classList.toggle("is-selected", preferredAnalyzeMode === "remote");
}

function setRemoteModePill(text, tone = "") {
  remoteModePill.className = `status-pill${tone ? ` ${tone}` : ""}`;
  remoteModePill.textContent = text;
}

function updateRemoteUrlHelper() {
  const { baseUrl, error } = parseRemoteBaseUrl(remoteApiUrlInput.value);
  if (!baseUrl) {
    remoteEndpointPreview.textContent = "";
  } else {
    remoteEndpointPreview.textContent = `Will connect to: ${sessionKeyEndpoint(baseUrl)}`;
  }
  if (baseUrl && !error) {
    localStorage.setItem(REMOTE_BASE_URL_STORAGE_KEY, baseUrl);
  }
  generateSessionBtn.disabled = !baseUrl || !!error;
  if (error && preferredAnalyzeMode === "remote") {
    setRemoteError(error);
  } else if (!error) {
    setRemoteError("");
  }
}

// ── Session management ──────────────────────────────────────────────────────

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
  const { baseUrl, error } = parseRemoteBaseUrl(remoteApiUrlInput.value);
  if (!baseUrl) {
    sessionKeyDisplay.value = "";
    sessionKeyStatus.textContent = "Not connected. Enter a server URL to enable deep scan mode.";
    sessionQuotaStatus.textContent = `Up to ${FALLBACK_LIMIT} scans available per session.`;
    generateSessionBtn.textContent = "Connect";
    copySessionBtn.disabled = true;
    revealSessionBtn.disabled = true;
    revealSessionBtn.textContent = "Reveal Key";
    if (preferredAnalyzeMode === "remote") {
      setRemoteModePill("Enter server address", "attention");
    } else {
      setRemoteModePill("Browser mode");
    }
    return;
  }
  const session = loadRemoteSession(baseUrl);
  if (!session) {
    sessionKeyDisplay.value = "";
    sessionKeyStatus.textContent = "Not connected. Click 'Server scan' to connect automatically.";
    sessionQuotaStatus.textContent = `Up to ${FALLBACK_LIMIT} scans available per session.`;
    generateSessionBtn.textContent = "Connect";
    copySessionBtn.disabled = true;
    revealSessionBtn.disabled = true;
    revealSessionBtn.textContent = "Reveal Key";
    setRemoteModePill(preferredAnalyzeMode === "remote" ? "Will connect on demand" : "Server ready");
    return;
  }
  const expired = isSessionExpired(session);
  sessionKeyDisplay.value = revealSessionKey ? session.sessionKey : maskSessionKey(session.sessionKey);
  generateSessionBtn.textContent = expired ? "Reconnect" : "Refresh Connection";
  revealSessionBtn.disabled = false;
  revealSessionBtn.textContent = revealSessionKey ? "Hide Key" : "Reveal Key";
  if (expired) {
    sessionKeyStatus.textContent = "Connection expired. Will reconnect automatically on next scan.";
    copySessionBtn.disabled = true;
    setRemoteModePill("Connection expired", "attention");
  } else {
    sessionKeyStatus.textContent = "Connected.";
    copySessionBtn.disabled = false;
    setRemoteModePill("Server connected", "online");
  }
  const jobQuota = session.jobQuota || {};
  const jobLimit = jobQuota.limit ?? FALLBACK_LIMIT;
  const jobRemaining = jobQuota.remaining ?? jobLimit;
  sessionQuotaStatus.textContent = `${jobRemaining} scan${jobRemaining === 1 ? "" : "s"} remaining.`;
}

// ── Async helpers ───────────────────────────────────────────────────────────

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Remote API session ──────────────────────────────────────────────────────

async function generateRemoteSessionKey(baseUrlOverride = "") {
  setRemoteError("");
  const parsed = baseUrlOverride
    ? { baseUrl: normalizeBaseUrl(baseUrlOverride), error: "" }
    : parseRemoteBaseUrl(remoteApiUrlInput.value);
  const baseUrl = parsed.baseUrl;
  if (!baseUrl) throw new Error(parsed.error || "Enter the server address first.");
  if (parsed.error) throw new Error(parsed.error);
  let response;
  try {
    response = await fetch(sessionKeyEndpoint(baseUrl), { method: "POST" });
  } catch (err) {
    let msg = `Cannot reach the analysis server at ${baseUrl}. Make sure the server is running and accessible from this browser. If running locally, start it with: \`qvk serve\``;
    if (isCorsLikeError(err, baseUrl)) {
      try {
        const urlObj = new URL(baseUrl);
        const isNonLocal = !["localhost", "127.0.0.1"].includes(urlObj.hostname);
        if (window.location.protocol === "https:" && isNonLocal) {
          msg += ` The server may also need CORS configured to allow requests from ${window.location.origin}.`;
        }
      } catch {}
    }
    throw new Error(msg);
  }
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(
        `Analysis server found at ${baseUrl} but the expected API path was not found. Make sure you're using the correct server address (just the base URL, e.g. http://127.0.0.1:8000).`
      );
    }
    if (response.status === 429) {
      throw new Error("Too many requests. Please wait a moment and try again.");
    }
    throw new Error("Something went wrong connecting to the server. Please try again.");
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
  localStorage.setItem(REMOTE_BASE_URL_STORAGE_KEY, baseUrl);
  setAnalyzeMode("remote");
  renderRemoteSessionState();
  return record;
}

async function ensureRemoteSession(baseUrl, options = {}) {
  if (!baseUrl) {
    throw new Error("Enter the server address first.");
  }
  const session = loadRemoteSession(baseUrl);
  if (!options.forceRefresh && session && !isSessionExpired(session)) {
    return session;
  }
  return generateRemoteSessionKey(baseUrl);
}

async function remoteFetch(baseUrl, path, init = {}, allowRetry = true) {
  const session = await ensureRemoteSession(baseUrl);
  const headers = new Headers(init.headers || {});
  headers.set("X-Session-Key", session.sessionKey);
  let response;
  try {
    response = await fetch(`${baseUrl}${path}`, { ...init, headers });
  } catch (err) {
    let msg = `Cannot reach the analysis server at ${baseUrl}. Make sure the server is running and accessible from this browser. If running locally, start it with: \`qvk serve\``;
    if (isCorsLikeError(err, baseUrl)) {
      try {
        const urlObj = new URL(baseUrl);
        const isNonLocal = !["localhost", "127.0.0.1"].includes(urlObj.hostname);
        if (window.location.protocol === "https:" && isNonLocal) {
          msg += ` The server may also need CORS configured to allow requests from ${window.location.origin}.`;
        }
      } catch {}
    }
    throw new Error(msg);
  }
  if (response.status === 401) {
    clearRemoteSession(baseUrl);
    renderRemoteSessionState();
    if (!allowRetry) {
      throw new Error("Server connection expired. Reconnecting automatically...");
    }
    setProgress(0, "Server connection expired. Reconnecting automatically...");
    const refreshed = await ensureRemoteSession(baseUrl, { forceRefresh: true });
    const retryHeaders = new Headers(init.headers || {});
    retryHeaders.set("X-Session-Key", refreshed.sessionKey);
    response = await fetch(`${baseUrl}${path}`, { ...init, headers: retryHeaders });
    if (response.status === 401) {
      clearRemoteSession(baseUrl);
      renderRemoteSessionState();
      throw new Error("Server connection expired. Please try again.");
    }
  }
  if (response.status === 429) {
    throw new Error("Too many requests. Please wait a moment and try again.");
  }
  return response;
}

// ── Browser image/video analysis math ──────────────────────────────────────

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

// ── Browser video analysis ──────────────────────────────────────────────────

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

// ── Remote job ──────────────────────────────────────────────────────────────

async function createRemoteJob(baseUrl, file, options) {
  const payload = {
    preset: analysisPreset.value || "balanced",
    sample_fps: Number((1 / options.sampleInterval).toFixed(3)),
    max_frames: options.maxSamples,
    sensitivity: options.sensitivity
  };
  const formData = new FormData();
  formData.append("file", file);
  formData.append("options", JSON.stringify(payload));
  const resp = await remoteFetch(baseUrl, "/api/v1/jobs", { method: "POST", body: formData });
  if (!resp.ok) {
    throw new Error("Something went wrong during analysis. Please try again.");
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
    if (!statusResp.ok) throw new Error("Something went wrong during analysis. Please try again.");
    const status = await statusResp.json();
    setProgress(status.progress_percent || 0, humanizePhase(status.phase || status.status));
    if (status.status === "completed") {
      const resultResp = await remoteFetch(baseUrl, `/api/v1/jobs/${jobId}/result`, { method: "GET" });
      if (!resultResp.ok) throw new Error("Something went wrong during analysis. Please try again.");
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
    if (status.status === "failed") throw new Error("Something went wrong during analysis. Please try again.");
    await sleep(1200);
  }
  throw new Error("Remote analysis timed out.");
}

// ── Result rendering ────────────────────────────────────────────────────────

function renderResult(report) {
  latestReport = report;
  resultCard.classList.remove("hidden");
  resultMode.textContent = humanizeMode(report.mode);
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
    sensitivity: Math.max(0.05, Math.min(0.99, Number(document.getElementById("sensitivity").value || "0.7")))
  };
}

// ── Bootstrap ───────────────────────────────────────────────────────────────

function bootstrapRemoteApiUrl() {
  const params = new URLSearchParams(window.location.search);
  const queryApi = params.get("api");
  const savedApi = localStorage.getItem(REMOTE_BASE_URL_STORAGE_KEY);
  const inferred = inferLocalFastapiUrl();
  const initial = queryApi || savedApi || inferred || "";
  if (initial) {
    remoteApiUrlInput.value = initial;
  }
  if (params.get("remote") === "1") {
    setAnalyzeMode("remote");
  } else {
    setAnalyzeMode("browser");
  }
  updateRemoteUrlHelper();
}

// ── Event listeners ─────────────────────────────────────────────────────────

analyzeBrowserBtn.addEventListener("click", () => {
  setAnalyzeMode("browser");
  renderRemoteSessionState();
});

analyzeRemoteBtn.addEventListener("click", () => {
  setAnalyzeMode("remote");
  renderRemoteSessionState();
});

generateSessionBtn.addEventListener("click", async () => {
  generateSessionBtn.disabled = true;
  setRemoteError("");
  try {
    await generateRemoteSessionKey();
  } catch (error) {
    setRemoteError(error.message);
  } finally {
    updateRemoteUrlHelper();
  }
});

copySessionBtn.addEventListener("click", async () => {
  const baseUrl = parseRemoteBaseUrl(remoteApiUrlInput.value).baseUrl;
  const session = baseUrl ? loadRemoteSession(baseUrl) : null;
  if (!session || isSessionExpired(session)) {
    setRemoteError("Generate a fresh working key first.");
    renderRemoteSessionState();
    return;
  }
  try {
    await navigator.clipboard.writeText(session.sessionKey);
    setRemoteError("");
    sessionKeyStatus.textContent = "Key copied to clipboard.";
  } catch {
    setRemoteError("Clipboard access failed. Reveal the key and copy it manually.");
  }
});

revealSessionBtn.addEventListener("click", () => {
  const baseUrl = parseRemoteBaseUrl(remoteApiUrlInput.value).baseUrl;
  const session = baseUrl ? loadRemoteSession(baseUrl) : null;
  if (!session) {
    setRemoteError("No active session key to reveal.");
    return;
  }
  revealSessionKey = !revealSessionKey;
  renderRemoteSessionState();
});

useLocalFastapiBtn.addEventListener("click", () => {
  remoteApiUrlInput.value = "http://127.0.0.1:8000";
  setAnalyzeMode("remote");
  updateRemoteUrlHelper();
  renderRemoteSessionState();
});

clearSessionBtn.addEventListener("click", () => {
  const baseUrl = parseRemoteBaseUrl(remoteApiUrlInput.value).baseUrl;
  clearRemoteSession(baseUrl);
  revealSessionKey = false;
  renderRemoteSessionState();
});

remoteApiUrlInput.addEventListener("input", () => {
  updateRemoteUrlHelper();
  renderRemoteSessionState();
});

remoteApiUrlInput.addEventListener("change", () => {
  setRemoteError("");
  updateRemoteUrlHelper();
  renderRemoteSessionState();
});

// ── Analysis preset ─────────────────────────────────────────────────────────

const PRESET_DEFAULTS = {
  fast:     { sampleInterval: 1.0,  maxSamples: 500,  sensitivity: 0.5  },
  balanced: { sampleInterval: 0.5,  maxSamples: 1000, sensitivity: 0.7  },
  deep:     { sampleInterval: 0.2,  maxSamples: 2000, sensitivity: 0.85 }
};

analysisPreset.addEventListener("change", () => {
  const preset = PRESET_DEFAULTS[analysisPreset.value];
  if (!preset) return;
  document.getElementById("sample-interval").value = preset.sampleInterval;
  document.getElementById("max-samples").value = preset.maxSamples;
  document.getElementById("sensitivity").value = preset.sensitivity;
});

// ── Demo video ──────────────────────────────────────────────────────────────

demoVideoBtn.addEventListener("click", async () => {
  demoVideoBtn.disabled = true;
  demoVideoBtn.textContent = "Loading demo…";
  try {
    const resp = await fetch("./assets/demo.mp4");
    if (!resp.ok) throw new Error("Could not fetch demo video.");
    const blob = await resp.blob();
    const file = new File([blob], "demo.mp4", { type: "video/mp4" });
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(file);
    const fileInput = document.getElementById("video-file");
    fileInput.files = dataTransfer.files;
    fileInput.classList.add("has-file");
    fileInput.dispatchEvent(new Event("change", { bubbles: true }));
  } catch (err) {
    setRemoteError("Demo video could not be loaded. Make sure assets/demo.mp4 exists.");
  } finally {
    demoVideoBtn.disabled = false;
    demoVideoBtn.textContent = "Try demo video";
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setRemoteError("");
  const fileInput = document.getElementById("video-file");
  const file = fileInput.files && fileInput.files[0];
  if (!file) {
    setRemoteError("Select a video file first.");
    return;
  }
  setAnalyzeButtonsDisabled(true);
  resultCard.classList.add("hidden");
  setProgress(5, "Preparing analysis...");

  try {
    const options = getOptions();
    let report;
    const requestedMode = event.submitter?.dataset.mode || preferredAnalyzeMode;
    setAnalyzeMode(requestedMode);
    renderRemoteSessionState();
    if (requestedMode === "remote") {
      const parsed = parseRemoteBaseUrl(remoteApiUrlInput.value);
      const baseUrl = parsed.baseUrl;
      if (!baseUrl) throw new Error(parsed.error || "Enter the server address first.");
      if (parsed.error) throw new Error(parsed.error);
      setProgress(10, "Connecting to server...");
      await ensureRemoteSession(baseUrl);
      setProgress(18, "Uploading video for analysis...");
      const job = await createRemoteJob(baseUrl, file, options);
      report = await pollRemoteResult(baseUrl, job.job_id);
    } else {
      report = await analyzeInBrowser(file, options);
      setProgress(100, "Browser analysis complete");
    }
    renderResult(report);
  } catch (error) {
    setRemoteError(error.message);
  } finally {
    setAnalyzeButtonsDisabled(false);
  }
});

downloadReportBtn.addEventListener("click", () => {
  if (!latestReport) {
    setRemoteError("Run an analysis first before downloading a report.");
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

bootstrapRemoteApiUrl();
renderRemoteSessionState();
