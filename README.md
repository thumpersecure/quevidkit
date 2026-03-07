# quevidkit

quevidkit is a forensic video tampering analysis toolkit with:

- A **Python analysis engine** (`qvk analyze`) for advanced users.
- A **simple web app** (`qvk serve`) for non-coders to upload a video and get a verdict.
- A multi-signal forensic pipeline that inspects:
  - metadata/container consistency
  - codec/structure anomalies
  - file-size/bitrate mismatches
  - packet timing discontinuities
  - missing/duplicated frame signals
  - abrupt quality changes (blur/blockiness shifts)

## Important forensic note

No automated detector can be perfectly comprehensive for every codec, platform, and editing workflow.  
quevidkit produces **evidence-backed probability + explanation**, not legal certainty.

---

## Quick start

1) Install:

```bash
python -m pip install -e .
```

2) Analyze from terminal:

```bash
qvk analyze /path/to/video.mp4 --preset balanced --json-out report.json --html-out report.html
```

3) Run web app:

```bash
qvk serve --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`.

---

## CLI usage

```bash
qvk analyze VIDEO_PATH \
  --preset fast|balanced|deep \
  --sample-fps 2.0 \
  --max-frames 2000 \
  --sensitivity 0.7 \
  --json-out report.json \
  --html-out report.html
```

Useful flags:

- `--no-metadata-scan`
- `--no-packet-scan`
- `--no-frame-scan`
- `--no-quality-scan`
- `--debug` (includes heavy raw ffprobe payload in output)

---

## Web app features

- One-click upload and analysis.
- Progress + status polling.
- Verdict + probability + confidence.
- Human-readable explanation.
- **Graphical report from JSON findings**:
  - risk meter
  - per-check evidence bars (score + confidence)
  - suspicious-segment timeline
  - plain-language explanations
  - downloadable HTML report for sharing
- Advanced section for coders:
  - preset
  - sample fps
  - max frames
  - sensitivity
  - per-check toggles
  - debug payload toggle

---

## GitHub Pages app (static)

A static GitHub Pages frontend is included in `docs/`.

- `docs/index.html`
- `docs/styles.css`
- `docs/app.js`

It supports:

- **Browser mode** (no backend): client-side frame continuity/quality checks.
- **Remote API mode** (optional): sends upload to your FastAPI backend for full forensic analysis.
- **Session key generation button**: creates per-user, per-session keys (no hardcoded API keys in repo).
- **Graphical non-JSON report view** for non-technical users, with downloadable HTML output.

To enable GitHub Pages:

1. Go to repository **Settings -> Pages**
2. Under **Build and deployment**, set:
   - Source: **Deploy from a branch**
   - Branch: your default branch
   - Folder: `/docs`
3. Save, then open the Pages URL GitHub provides.

Note: browser-only mode cannot run full ffprobe packet/container internals.  
For comprehensive analysis use Remote API mode against a deployed `qvk serve` backend.

---

## API key/session-key security model

- There are **no hardcoded API keys** in this repository.
- The backend issues **ephemeral session keys** via:
  - `POST /api/v1/session-key`
- Protected endpoints (`/api/v1/jobs*`) require:
  - `X-Session-Key: <generated_key>`
- Keys are client-bound and expire automatically.
- Generation is rate-limited by default to **10 keys per window**.
- Each generated key has a default **job quota of 10**.

### Configure security (server env vars)

```bash
# Required in production (do not commit secrets)
export QVK_SESSION_KEY_SECRET="replace-with-strong-random-secret"

# Optional security controls
export QVK_SESSION_KEY_TTL_SECONDS=3600
export QVK_SESSION_KEY_GEN_LIMIT=10
export QVK_SESSION_KEY_GEN_WINDOW_SECONDS=3600
export QVK_SESSION_KEY_JOB_LIMIT=10

# For GitHub Pages -> backend remote mode (CORS)
export QVK_CORS_ALLOW_ORIGINS="https://<your-user>.github.io"
```

### How users get a key in GitHub Pages UI

1. Open the GitHub Pages app.
2. Enable **Use Remote API**.
3. Set FastAPI base URL:
   - Enter manually (example: `https://api.example.com`), or
   - click **Use Local FastAPI URL** (`http://127.0.0.1:8000`) for local development.
4. Confirm the endpoint preview (`.../api/v1/session-key`) shown by the UI.
5. Click **Generate Session Key**.
6. Run analysis (the key is stored in `sessionStorage` for that browser session).

Tip: you can prefill the Pages app URL with query params:
- `?api=https://your-api.example.com`
- `?remote=1` to enable Remote API mode by default

### cURL example

```bash
API_BASE="https://your-api.example.com"

# Generate ephemeral key
SESSION_KEY=$(curl -sS -X POST "$API_BASE/api/v1/session-key" | python3 -c 'import sys,json;print(json.load(sys.stdin)["session_key"])')

# Submit analysis job
curl -sS -X POST "$API_BASE/api/v1/jobs" \
  -H "X-Session-Key: $SESSION_KEY" \
  -F "file=@/path/to/video.mp4" \
  -F 'options={"preset":"balanced","sample_fps":2.0,"max_frames":2000,"sensitivity":0.7}'
```

---

## Output model (high level)

Each report includes:

- `label`: `authentic`, `suspicious`, `tampered`, or `inconclusive`
- `tamper_probability`: 0 to 1
- `confidence`: evidence reliability estimate
- `checks`: per-detector score, confidence, summary
- `suspicious_segments`: timestamped events with category
- `explanation`: concise natural-language reasoning

---

## Requirements

- Python 3.10+
- `ffprobe` installed and available in PATH
- Python dependencies from `pyproject.toml`

---

## Running tests

```bash
python -m pytest
```
