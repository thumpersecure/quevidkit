const form = document.getElementById("upload-form");
const progressCard = document.getElementById("progress-card");
const progressText = document.getElementById("progress-text");
const progressBar = document.getElementById("progress-bar");
const resultCard = document.getElementById("result-card");
const verdictEl = document.getElementById("verdict");
const plainMeaningEl = document.getElementById("plain-meaning");
const probabilityEl = document.getElementById("probability");
const confidenceEl = document.getElementById("confidence");
const durationEl = document.getElementById("duration");
const riskMeterEl = document.getElementById("risk-meter");
const explanationList = document.getElementById("explanation-list");
const segmentList = document.getElementById("segment-list");
const checkBars = document.getElementById("check-bars");
const checksJson = document.getElementById("checks-json");
const analyzeBtn = document.getElementById("analyze-btn");
const downloadReportBtn = document.getElementById("download-report-btn");
let sessionKeyRecord = null;
let latestResult = null;
const RISK_GRADIENT = "linear-gradient(90deg, #3dd68c 0%, #f6b73c 55%, #ff5a6b 100%)";

function advancedOptions() {
  return {
    preset: document.getElementById("preset").value,
    sample_fps: Number(document.getElementById("sample-fps").value),
    max_frames: Number(document.getElementById("max-frames").value),
    sensitivity: Number(document.getElementById("sensitivity").value),
    enable_metadata_scan: document.getElementById("metadata-scan").checked,
    enable_packet_scan: document.getElementById("packet-scan").checked,
    enable_frame_scan: document.getElementById("frame-scan").checked,
    enable_quality_scan: document.getElementById("quality-scan").checked,
    include_debug_payload: document.getElementById("debug-payload").checked
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function pollJob(jobId) {
  let attempts = 0;
  const maxAttempts = 900;
  while (true) {
    attempts += 1;
    if (attempts > maxAttempts) {
      throw new Error("Timed out waiting for analysis to finish.");
    }
    const statusResponse = await apiFetch(`/api/v1/jobs/${jobId}`, { method: "GET" });
    if (!statusResponse.ok) {
      throw new Error("Unable to get job status");
    }
    const status = await statusResponse.json();
    progressText.textContent = `${status.phase}: ${status.message}`;
    progressBar.style.width = `${status.progress_percent}%`;

    if (status.status === "completed") {
      const resultResponse = await apiFetch(`/api/v1/jobs/${jobId}/result`, { method: "GET" });
      if (!resultResponse.ok) {
        throw new Error("Unable to get completed analysis result");
      }
      const wrapped = await resultResponse.json();
      return wrapped.result;
    }
    if (status.status === "failed") {
      throw new Error(status.message || "Analysis failed");
    }
    await sleep(1200);
  }
}

async function generateSessionKey() {
  const response = await fetch("/api/v1/session-key", { method: "POST" });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Unable to generate session key: ${body}`);
  }
  const payload = await response.json();
  sessionKeyRecord = {
    key: payload.session_key,
    expiresAt: new Date(payload.expires_at_utc).getTime()
  };
}

async function ensureSessionKey() {
  if (sessionKeyRecord && Date.now() < sessionKeyRecord.expiresAt) {
    return sessionKeyRecord.key;
  }
  await generateSessionKey();
  return sessionKeyRecord.key;
}

async function apiFetch(path, init) {
  let key = await ensureSessionKey();
  const headers = new Headers(init.headers || {});
  headers.set("X-Session-Key", key);
  let response = await fetch(path, { ...init, headers });
  if (response.status === 401) {
    await generateSessionKey();
    key = sessionKeyRecord.key;
    const retryHeaders = new Headers(init.headers || {});
    retryHeaders.set("X-Session-Key", key);
    response = await fetch(path, { ...init, headers: retryHeaders });
  }
  return response;
}

function verdictColor(label) {
  if (label === "tampered") return "#ff5a6b";
  if (label === "suspicious") return "#f6b73c";
  if (label === "authentic") return "#3dd68c";
  return "#6f7d97";
}

function plainMeaning(label, probability, confidence) {
  if (label === "tampered") {
    return `The system found strong signs of manipulation (${(probability * 100).toFixed(1)}% tamper probability) with ${(confidence * 100).toFixed(1)}% evidence confidence.`;
  }
  if (label === "suspicious") {
    return `Some forensic signals are unusual (${(probability * 100).toFixed(1)}% tamper probability). Manual review is recommended.`;
  }
  if (label === "authentic") {
    return `No strong manipulation pattern was found (${(probability * 100).toFixed(1)}% tamper probability).`;
  }
  return "Evidence quality is not high enough for a fully reliable conclusion.";
}

function explainCheck(check) {
  const map = {
    metadata_codec_consistency: "Compares metadata, stream durations, codec declarations, and bitrate consistency.",
    packet_timing_anomalies: "Checks packet timestamps for timeline gaps, jumps, and timestamp continuity anomalies.",
    frame_structure_anomalies: "Looks for structural frame/GOP changes, including resolution and color-profile switches.",
    frame_quality_shift: "Looks for abrupt visual quality transitions and duplicate/missing frame behavior."
  };
  return map[check.name] || "This forensic detector contributes to overall risk estimation.";
}

function renderCheckBars(result) {
  checkBars.innerHTML = "";
  const checks = result.checks || [];
  if (checks.length === 0) {
    checkBars.innerHTML = "<p class='muted'>No check-level data available.</p>";
    return;
  }
  checks.forEach((check) => {
    const wrapper = document.createElement("div");
    wrapper.className = "check-item";
    const score = Math.max(0, Math.min(100, (check.score || 0) * 100));
    const conf = Math.max(0, Math.min(100, (check.confidence || 0) * 100));
    wrapper.innerHTML = `
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
    checkBars.appendChild(wrapper);
  });
}

function renderTimeline(result) {
  const segments = (result.suspicious_segments || []).slice(0, 60);
  segmentList.innerHTML = "";
  const duration = Math.max(
    Number(result.duration_s || 0),
    ...segments.map((segment) => Number(segment.end_s || 0)),
    1
  );

  if (segments.length === 0) {
    document.getElementById("timeline-track").innerHTML = "<p class='muted' style='padding:6px 10px;'>No suspicious segments detected.</p>";
    const li = document.createElement("li");
    li.textContent = "No suspicious time windows were flagged by enabled detectors.";
    segmentList.appendChild(li);
    return;
  }

  const blocks = segments
    .map((segment) => {
      const start = Math.max(0, Math.min(100, (segment.start_s / duration) * 100));
      const end = Math.max(start, Math.min(100, (segment.end_s / duration) * 100));
      const width = Math.max(0.4, end - start);
      const title = `[${segment.category}] ${segment.start_s.toFixed(2)}s-${segment.end_s.toFixed(2)}s (confidence ${segment.confidence.toFixed(2)})`;
      return `<div class="timeline-block" style="left:${start.toFixed(2)}%;width:${width.toFixed(2)}%" title="${title}"></div>`;
    })
    .join("");
  document.getElementById("timeline-track").innerHTML = blocks;

  segments.forEach((segment) => {
    const li = document.createElement("li");
    li.textContent = `[${segment.category}] ${segment.start_s.toFixed(2)}s - ${segment.end_s.toFixed(2)}s (confidence ${segment.confidence.toFixed(2)}).`;
    segmentList.appendChild(li);
  });
}

function buildGraphicalReportHtml(result) {
  const checks = (result.checks || [])
    .map((check) => {
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
    })
    .join("");
  const explanation = (result.explanation || []).map((line) => `<li>${line}</li>`).join("");
  const segments = (result.suspicious_segments || [])
    .slice(0, 30)
    .map((segment) => `<li>[${segment.category}] ${segment.start_s.toFixed(2)}s - ${segment.end_s.toFixed(2)}s (confidence ${segment.confidence.toFixed(2)})</li>`)
    .join("");
  const probability = Math.max(0, Math.min(100, (result.tamper_probability || 0) * 100));
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>quevidkit graphical report</title>
<style>
body{font-family:Arial,sans-serif;background:radial-gradient(circle at top,#18253e 0%,#08111f 62%,#050914 100%);color:#edf4ff;margin:0;padding:24px}
.shell{max-width:1100px;margin:0 auto}
.card{background:rgba(16,24,39,0.94);border:1px solid #2d3c5a;border-radius:14px;padding:16px;margin-bottom:14px;box-shadow:0 18px 44px rgba(0,0,0,0.28)}
.eyebrow{text-transform:uppercase;letter-spacing:0.18em;color:#8bd4ff;font-size:0.75rem;margin:0 0 10px}
.badge{display:inline-block;padding:7px 14px;border-radius:999px;color:#06111c;background:${verdictColor(result.label)};font-weight:700;letter-spacing:0.08em}
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
  <span class="badge">${String(result.label || "inconclusive").toUpperCase()}</span>
  <p>${plainMeaning(result.label, result.tamper_probability || 0, result.confidence || 0)}</p>
  <p><strong>Tamper probability:</strong> ${probability.toFixed(1)}%</p>
  <p><strong>Confidence:</strong> ${((result.confidence || 0) * 100).toFixed(1)}%</p>
  <div class="meter"><div></div></div>
</div>
<div class="card"><h2>Plain-language explanation</h2><ul>${explanation || "<li>No explanation available.</li>"}</ul></div>
<div class="card"><h2>Evidence checks</h2><div class="checks">${checks}</div></div>
<div class="card"><h2>Suspicious segments</h2><ul>${segments || "<li>None</li>"}</ul></div>
</div>
</body></html>`;
}

function renderResult(result) {
  latestResult = result;
  const label = result.label || "inconclusive";
  const probability = result.tamper_probability || 0;
  const confidence = result.confidence || 0;
  verdictEl.textContent = `${label.toUpperCase()}`;
  verdictEl.style.background = verdictColor(label);
  plainMeaningEl.textContent = plainMeaning(label, probability, confidence);
  probabilityEl.textContent = `${(probability * 100).toFixed(1)}%`;
  confidenceEl.textContent = `${(confidence * 100).toFixed(1)}%`;
  durationEl.textContent = `${Number(result.duration_s || 0).toFixed(2)}s`;
  riskMeterEl.style.width = `${(probability * 100).toFixed(1)}%`;

  explanationList.innerHTML = "";
  (result.explanation || []).forEach((line) => {
    const li = document.createElement("li");
    li.textContent = line;
    explanationList.appendChild(li);
  });

  renderCheckBars(result);
  renderTimeline(result);
  checksJson.textContent = JSON.stringify(result.checks, null, 2);
  resultCard.classList.remove("hidden");
}

downloadReportBtn.addEventListener("click", () => {
  if (!latestResult) {
    alert("Run an analysis first.");
    return;
  }
  const htmlReport = buildGraphicalReportHtml(latestResult);
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

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const fileInput = document.getElementById("video-file");
  const file = fileInput.files[0];
  if (!file) {
    alert("Select a video file first.");
    return;
  }

  analyzeBtn.disabled = true;
  resultCard.classList.add("hidden");
  progressCard.classList.remove("hidden");
  progressText.textContent = "Uploading...";
  progressBar.style.width = "5%";

  const data = new FormData();
  data.append("file", file);
  data.append("options", JSON.stringify(advancedOptions()));

  try {
    const response = await apiFetch("/api/v1/jobs", { method: "POST", body: data });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Upload failed: ${errorText}`);
    }
    const job = await response.json();
    const result = await pollJob(job.job_id);
    renderResult(result);
  } catch (error) {
    alert(`Error: ${error.message}`);
  } finally {
    analyzeBtn.disabled = false;
  }
});
