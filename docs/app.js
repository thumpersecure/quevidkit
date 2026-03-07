const form = document.getElementById("analyze-form");
const analyzeBtn = document.getElementById("analyze-btn");
const progressCard = document.getElementById("progress-card");
const progressText = document.getElementById("progress-text");
const progressBar = document.getElementById("progress-bar");
const resultCard = document.getElementById("result-card");
const resultMode = document.getElementById("result-mode");
const resultLabel = document.getElementById("result-label");
const resultProbability = document.getElementById("result-probability");
const resultConfidence = document.getElementById("result-confidence");
const resultExplanation = document.getElementById("result-explanation");
const resultSignals = document.getElementById("result-signals");
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
  resultCard.classList.remove("hidden");
  resultMode.textContent = report.mode;
  resultLabel.textContent = (report.label || "inconclusive").toUpperCase();
  resultProbability.textContent = `${((report.tamper_probability || 0) * 100).toFixed(1)}%`;
  resultConfidence.textContent = `${((report.confidence || 0) * 100).toFixed(1)}%`;
  resultExplanation.innerHTML = "";
  (report.explanation || []).forEach((line) => {
    const li = document.createElement("li");
    li.textContent = line;
    resultExplanation.appendChild(li);
  });
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

renderRemoteSessionState();
