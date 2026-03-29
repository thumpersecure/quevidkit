# link to web app

https://thumpersecure.github.io/quevidkit/

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
  - **compression consistency** across video segments
  - **scene-cut / GOP alignment** forensics
  - **audio spectral continuity** (spectral centroid, energy, ZCR discontinuities)
  - **temporal noise floor** consistency
  - **double compression detection** (I-frame size periodicity / autocorrelation)
  - **Error Level Analysis (ELA)** on decoded frames
  - **bitstream structure** (mid-stream parameter changes, color profile shifts)
  - **QP / GOP pattern consistency** (encoding session fingerprinting)
  - **thumbnail vs first-frame mismatch** detection
  - **audio-video sync drift** (A/V timing offset at multiple checkpoints)
  - **bitrate distribution bimodality** (statistical test for merged encoding profiles)

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

## Web app presets and settings

The web UI (both the hosted GitHub Pages app and the self-hosted `qvk serve` version) includes an **Analysis preset** dropdown inside the *Analysis settings* panel:

| Preset | Sample interval | Max frames | Sensitivity | Description |
|---|---|---|---|---|
| **Fast** | 1.0 s | 500 | 0.50 | Quick scan with lowest accuracy — good for a first pass. |
| **Balanced** | 0.5 s | 1 000 | 0.70 | Default scan — recommended for most videos. |
| **Deep** | 0.2 s | 2 000 | 0.85 | Thorough scan with highest accuracy — runs 11 additional advanced forensic checks. |

Selecting a preset automatically fills in the three advanced numeric fields.  You can still override them manually after choosing a preset.

### Parameter reference

- **Sample interval** — time in seconds between sampled frames. Smaller values analyse more frames but increase processing time.
- **Maximum frames** — hard cap on the number of frames the engine will inspect.
- **Sensitivity** — detection threshold (0–1). Higher values flag more anomalies but may increase false positives.

### Advanced forensic checks (Deep preset)

The **Deep** preset enables `enable_advanced_forensics=True`, which activates 11 additional server-side forensic checks on top of the 4 base checks:

| # | Check | Category | What it detects |
|---|-------|----------|-----------------|
| 5 | **Compression Consistency** | codec | Splits the video into temporal windows and compares packet-size distributions per frame type (I/P/B). A re-encoded segment shifts the distribution, producing a detectable statistical anomaly. |
| 6 | **Scene Cut Forensics** | timing | Runs ffmpeg scene-change detection and correlates scene cuts with GOP (keyframe) boundaries. Legitimate cuts usually align with keyframes; spliced content often does not. Also detects suspicious scene-change clustering. |
| 7 | **Audio Spectral Continuity** | audio | Extracts audio as PCM, computes per-window spectral features (RMS energy, spectral centroid, zero-crossing rate), and flags abrupt discontinuities via z-score analysis. Also detects suspicious short silence gaps. |
| 8 | **Temporal Noise Consistency** | quality | Estimates per-frame noise floor via Laplacian std-dev and Sobel high-frequency energy. Different cameras/encoders produce different noise profiles, so a sudden shift indicates spliced source material. |
| 9 | **Double Compression Detection** | codec | Analyzes P-frame size autocorrelation to detect periodic patterns left by a prior encoding pass with a different GOP interval. Also flags unusually high I-frame size variation. |
| 10 | **Error Level Analysis (ELA)** | quality | Re-compresses sampled frames at a fixed JPEG quality and measures the residual. Tampered regions that were re-saved at a different quality show different error levels. Detects temporal ELA shifts via z-score. |
| 11 | **Bitstream Structure** | codec | Inspects mid-stream color-parameter changes, interlaced/progressive mode switches, frame-type size outlier rates, B-frame declaration consistency, and extradata integrity. |
| 12 | **QP / GOP Pattern Consistency** | codec | Analyzes the frame-type sequence (I/P/B pattern) within each GOP for consistency. Different encoders and settings produce different patterns, so mid-stream pattern changes indicate spliced encoding sessions. |
| 13 | **Thumbnail Mismatch** | metadata | Compares the embedded thumbnail image against the actual first frame. Editing tools often update content but leave the original thumbnail, creating a detectable mismatch. |
| 14 | **A/V Sync Drift** | timing | Measures audio-video timing offset at 20 checkpoints across the timeline. Splicing without adjusting audio timestamps causes sync jumps or progressive drift at edit points. |
| 15 | **Bitrate Distribution** | codec | Tests whether the statistical distribution of video packet sizes is unimodal (single encoding source) or bimodal (two merged encoding profiles) using the bimodality coefficient. |

These checks are automatically enabled when `preset=deep` and can also be explicitly enabled via the `enable_advanced_forensics` option.

### Demo video

The GitHub Pages app includes a **"Try demo video"** button next to the file input.  Clicking it fetches a short sample clip (`docs/assets/demo.mp4`) and loads it into the file picker automatically so you can test the analysis pipeline without providing your own video.

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
- `--advanced-forensics` (enable advanced checks without using the deep preset)
- `--debug` (includes heavy raw ffprobe payload in output)

---

## Web app features

- One-click upload and analysis.
- Progress + status polling.
- Verdict + probability + confidence.
- Human-readable explanation with **per-check detail**, **benign alternatives**, and **corroboration status**.
- **Graphical report from JSON findings**:
  - risk meter
  - per-check evidence bars (score + confidence)
  - suspicious-segment timeline
  - plain-language explanations with method descriptions and alternative interpretations
  - downloadable HTML report for sharing
- Advanced section for coders:
  - preset
  - sample fps
  - max frames
  - sensitivity
  - per-check toggles
  - debug payload toggle

---

## GitHub Pages app (mobile forensics)

A full-featured forensic analysis frontend is included in `docs/`. It runs entirely on GitHub Pages with **zero server requirements** for the primary analysis mode.

### Architecture

```
docs/
├── index.html          # Mobile-first responsive UI
├── styles.css          # Touch-optimized responsive styles
├── app.js              # ES module orchestrator
└── lib/
    ├── mp4-parser.js   # Binary MP4/MOV container parser (ISO 14496-12)
    ├── checks.js       # 5 forensic check modules
    ├── scoring.js      # Score fusion with corroboration & lone-wolf penalty (ported from Python)
    ├── report.js       # Downloadable HTML report generator
    └── ui.js           # DOM rendering and progress management
```

### Three analysis modes

| Mode | How it works | Requirements |
|------|-------------|--------------|
| **Client-Only** | Full forensic analysis runs entirely in the browser. Parses the MP4 binary container, inspects sample timing tables, GOP structure, frame quality, and audio consistency. | None — works offline after page load. |
| **Server Deep Scan** | Sends video to a quevidkit backend for ffprobe + OpenCV analysis with codec-level forensics. | Running `qvk serve` instance. |
| **Hybrid** | Client-side analysis first, then enhances results with server checks when a backend is available. | Optional `qvk serve` instance. |

### Client-side forensic checks (no server needed)

The client-only mode performs **5 independent forensic checks** by parsing the video file binary directly in the browser:

1. **Container & Metadata** — Parses MP4/MOV atoms (ftyp, moov, mvhd, tkhd, mdhd, stsd, etc.), checks duration consistency, bitrate validation, creation/modification date gaps, editing software markers (Adobe, CapCut, DaVinci, FFmpeg, etc.), edit list complexity, moov/mdat ordering, and free/skip box count.

2. **Sample Timing** — Reads the stts (time-to-sample) and ctts (composition time offset) tables directly from the binary container. Detects variable frame rates, timing anomalies, and timestamp discontinuities without ffprobe.

3. **Frame Structure (GOP)** — Analyzes the stss (sync sample) table for keyframe distribution, computes GOP interval coefficient of variation, checks sample size outliers via stsz, and detects multiple codec entries.

4. **Visual Frame Analysis** — Extracts frames via Canvas, computes dHash perceptual hashes, Laplacian blur variance, 8×8 blockiness metrics, and luminance histogram correlation. Detects duplicate frames, missing frames, quality shifts, and histogram breaks.

5. **Audio Consistency** — Cross-checks audio/video track durations, audio frame timing regularity, and audio edit list complexity.

All checks feed into the same score fusion engine used by the Python backend — now featuring **corroboration requirements** (multiple independent categories must agree), **lone-wolf penalty** (single high-scoring check with all others clean gets probability reduced), and **confidence-qualified explanations**.

### Mobile optimization

- Touch-friendly 48px minimum tap targets
- Safe area insets for notch/island phones
- 16px font inputs to prevent iOS zoom
- Progressive progress UI with per-check status indicators
- Memory-efficient: releases ArrayBuffer after container parsing
- Responsive from 320px to desktop widths

### Deploying to GitHub Pages

1. Go to repository **Settings → Pages**
2. Under **Build and deployment**, set:
   - Source: **Deploy from a branch**
   - Branch: your default branch
   - Folder: `/docs`
3. Save, then open the Pages URL GitHub provides.

URL parameters:
- `?mode=client|hybrid|remote` — set initial analysis mode
- `?api=https://your-api.example.com` — prefill server URL

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
- `checks`: per-detector score, confidence, summary, and detailed explanation
- `suspicious_segments`: timestamped events with category
- `explanation`: rich natural-language reasoning with per-check method descriptions, benign alternatives, and corroboration status

---

## Installing ffprobe / ffmpeg

quevidkit requires `ffprobe` (part of the FFmpeg suite) on your system PATH.

**Debian / Ubuntu:**

```bash
sudo apt update && sudo apt install -y ffmpeg
```

**macOS (Homebrew):**

```bash
brew install ffmpeg
```

**Windows (prebuilt binaries):**

Download from <https://ffmpeg.org/download.html> (or use `winget install ffmpeg`).  Make sure `ffmpeg.exe` and `ffprobe.exe` are in a directory listed in your `PATH`.

**Verify installation:**

```bash
ffprobe -version
```

> **Note:** `ffprobe` must be callable directly (i.e. available on your system PATH).  If you installed FFmpeg to a custom location, add that directory to your `PATH` environment variable.

---

## Requirements

- Python 3.10+
- `ffprobe` installed and available in PATH (see above)
- Python dependencies from `pyproject.toml`

---

## Running tests

```bash
python -m pytest
```

---

## The Science Behind Video Forensics

> [Download the full reference (PDF)](quesciences.pdf)

A plain-language guide to how digital video tampering detection works, why each forensic technique matters, and what quevidkit does under the hood.

---

### How Digital Video Works

Every video file has two layers: the **container** (`.mp4`, `.mkv`, `.mov` — the packaging) and the **codec** (`H.264`, `H.265`, `AV1` — the compression algorithm). Without compression, one minute of 1080p at 30fps would be ~10 GB.

Codecs use three frame types to achieve compression:

| Frame | Name | What It Stores |
|:---:|---|---|
| **I** | Intra | Complete standalone image — the largest, serves as an anchor point |
| **P** | Predicted | Only what changed since the previous frame |
| **B** | Bi-directional | Differences from both past and future frames — smallest |

Frames are organized into **GOPs** (Groups of Pictures):

```
I  B  B  P  B  B  P  B  B  P  B  B  I  ...
|<------------- one GOP ------------->|
```

> **Key forensic insight:** A legitimate recording has a **consistent, regular GOP pattern**. Editing almost always disrupts it.

---

### Types of Video Tampering

| Type | What It Is | What It Disrupts |
|---|---|---|
| **Splicing** | Combining footage from different sources | Metadata, compression, noise, GOP structure |
| **Frame Deletion** | Removing frames to erase moments | Timestamps jump, motion speeds up |
| **Frame Insertion** | Adding/duplicating frames | Zero-difference sequences, noise mismatches |
| **Re-encoding** | Decoding and re-encoding to hide edits | Double compression artifacts, metadata changes |
| **Deepfakes** | AI-generated face swaps or synthetic video | Blinking, lighting, texture, frequency artifacts |
| **Audio Replacement** | Swapping the audio track | Lip sync, spectral breaks, background noise shift |
| **Speed Manipulation** | Altering playback speed | Motion vectors, audio pitch, timestamp irregularities |

---

### The 15 quevidkit Forensic Checks

#### Standard Checks (all presets)

| # | Check | What It Catches |
|:---:|---|---|
| 1 | **Metadata & Codec Consistency** | Duration mismatches, bitrate discrepancies, editing software markers |
| 2 | **Packet Timing Anomalies** | Non-monotonic timestamps, frame gaps, timing spikes |
| 3 | **Frame Structure Anomalies** | Irregular GOP intervals, resolution switches, color profile changes |
| 4 | **Frame Quality Shift** | Duplicate frames, blur/blockiness shifts, missing frame gaps |

#### Advanced Checks (deep preset — `enable_advanced_forensics=True`)

| # | Check | What It Catches |
|:---:|---|---|
| 5 | **Compression Consistency** | Re-encoded segments via packet-size distribution shifts across temporal windows |
| 6 | **Scene Cut Forensics** | Splice points where scene cuts don't align with GOP/keyframe boundaries |
| 7 | **Audio Spectral Continuity** | Audio splices via energy, spectral centroid, and ZCR discontinuities |
| 8 | **Temporal Noise Consistency** | Source material changes via noise floor shifts (Laplacian + Sobel) |
| 9 | **Double Compression Detection** | Re-encoding fingerprints via P-frame autocorrelation periodicity |
| 10 | **Error Level Analysis (ELA)** | Mixed compression via JPEG re-compression residual shifts |
| 11 | **Bitstream Structure** | Mid-stream parameter changes, interlace switches, B-frame mismatches |
| 12 | **QP / GOP Pattern Consistency** | Encoding session changes via frame-type sequence analysis per GOP |
| 13 | **Thumbnail Mismatch** | Edits that update content but leave the original embedded thumbnail |
| 14 | **A/V Sync Drift** | Audio-video timing jumps and progressive drift at splice points |
| 15 | **Bitrate Distribution** | Merged encoding profiles detected via bimodality coefficient |

---

### How Scores Become Verdicts

```
15 checks  ->  Confidence-weighted mean  ->  Logistic function  ->  Label
                                               |
                               probability = 1 / (1 + e^(-logit))
                               logit = bias + (score * 5.2) + (gate * 0.4) + (corr * 1.0)
                               bias  = -3.0 + (sensitivity * 1.6)
```

**v0.3.0 scoring improvements:**

- **Corroboration factor** — Multiple independent forensic categories (metadata, codec, timing, quality, audio) must agree for high probability. Single-category findings are penalized.
- **Lone-wolf penalty** — If only one check scores high while 3+ others are clean, probability is reduced 30-45% to prevent false positives.
- **Raised thresholds** — Tampered threshold raised from 60% to 65%, suspicious from 35% to 38%.

| Condition | Verdict |
|---|---|
| Quality gate < 0.3 or confidence < 0.35 | **Inconclusive** |
| Probability >= 0.65 | **Tampered** |
| Probability >= 0.38 | **Suspicious** |
| Otherwise | **Authentic** |

> Each check is **independent** — spanning metadata, timing, codec, visual quality, audio, and noise domains. The corroboration requirement means multiple weak signals pointing the same direction compound into strong evidence, while isolated signals are treated with appropriate skepticism.

---

### Common False Positive Sources

| Source | Why It Triggers Checks |
|---|---|
| Transcoding | Re-encoding changes metadata + creates double compression artifacts |
| Social media upload | Platforms re-encode with their own settings — indistinguishable from tampering |
| Screen recording | Creates an entirely new recording with different everything |
| Multi-camera editing | Different cameras = different noise/color profiles at each cut |
| CCTV concatenation | Junction points create genuine timestamp resets |

> **"Suspicious" means the video has characteristics inconsistent with a single unmodified recording. It does NOT mean it was maliciously tampered with.** Expert interpretation is always required.

> **v0.3.0:** Every finding now includes a "benign alternative" explanation alongside the tampering interpretation, helping users distinguish legitimate processing from actual tampering.

---

### Chain of Custody

| Step | Purpose |
|---|---|
| **Acquisition** | Document how, when, and by whom the video was obtained |
| **SHA-256 Hash** | Mathematical fingerprint proving the file hasn't changed (quevidkit computes this automatically) |
| **Secure Storage** | Write-protected, access-controlled, with logging |
| **Analysis Docs** | Every tool, action, and result documented (quevidkit generates JSON + HTML reports) |
| **Transfer Docs** | Every handoff logged |

> *"If you did not write it down, it did not happen."* — The guiding principle of digital forensics.

---

### Further Reading

**Academic:**
- *An Overview of Video Tampering Detection Techniques* — IEEE, 2023
- *Deepfake Media Forensics: Status and Future Challenges* — PMC, 2025
- *Double Compression Detection for H.264 with Adaptive GOP* — Springer, 2019
- *SWGDE Best Practices for Digital Forensic Video Analysis* — SWGDE.org

**Accessible:**
- *How to Check Video Integrity by Detecting Double Encoding* — Forensic Focus
- *Error Level Analysis Tutorial* — FotoForensics.com
- *How to Make Digital Evidence Admissible in Court* — TrueScreen, 2026

> No automated tool can provide legal certainty. quevidkit produces **evidence-backed probability with explanation**, not proof.
