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
