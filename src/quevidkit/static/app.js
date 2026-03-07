const form = document.getElementById("upload-form");
const progressCard = document.getElementById("progress-card");
const progressText = document.getElementById("progress-text");
const progressBar = document.getElementById("progress-bar");
const resultCard = document.getElementById("result-card");
const verdictEl = document.getElementById("verdict");
const probabilityEl = document.getElementById("probability");
const confidenceEl = document.getElementById("confidence");
const explanationList = document.getElementById("explanation-list");
const segmentList = document.getElementById("segment-list");
const checksJson = document.getElementById("checks-json");
const analyzeBtn = document.getElementById("analyze-btn");
let sessionKeyRecord = null;

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

function renderResult(result) {
  verdictEl.textContent = `${result.label.toUpperCase()}`;
  probabilityEl.textContent = `${(result.tamper_probability * 100).toFixed(1)}%`;
  confidenceEl.textContent = `${(result.confidence * 100).toFixed(1)}%`;

  explanationList.innerHTML = "";
  (result.explanation || []).forEach((line) => {
    const li = document.createElement("li");
    li.textContent = line;
    explanationList.appendChild(li);
  });

  segmentList.innerHTML = "";
  const segments = (result.suspicious_segments || []).slice(0, 20);
  if (segments.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No suspicious segments found.";
    segmentList.appendChild(li);
  } else {
    segments.forEach((segment) => {
      const li = document.createElement("li");
      li.textContent = `[${segment.category}] ${segment.start_s.toFixed(2)}s - ${segment.end_s.toFixed(2)}s (confidence ${segment.confidence.toFixed(2)})`;
      segmentList.appendChild(li);
    });
  }

  checksJson.textContent = JSON.stringify(result.checks, null, 2);
  resultCard.classList.remove("hidden");
}

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
