# The Science Behind Video Forensics

A plain-language guide to how digital video tampering detection works, why each technique matters, and what quevidkit does under the hood.

---

## Table of Contents

1. [How Digital Video Actually Works](#1-how-digital-video-actually-works)
2. [How People Tamper with Video](#2-how-people-tamper-with-video)
3. [How Forensic Detection Works](#3-how-forensic-detection-works)
4. [What Each quevidkit Check Does and Why](#4-what-each-quevidkit-check-does-and-why)
5. [When the Detector Gets It Wrong](#5-when-the-detector-gets-it-wrong)
6. [How Weak Signals Become Strong Evidence](#6-how-weak-signals-become-strong-evidence)
7. [Chain of Custody and Legal Use](#7-chain-of-custody-and-legal-use)
8. [The State of the Field in 2026](#8-the-state-of-the-field-in-2026)
9. [Further Reading](#9-further-reading)

---

## 1. How Digital Video Actually Works

### The Two Layers: Container and Codec

Every video file has two distinct layers, like a shipping box and the item packed inside it.

The **container** is the file format you see — `.mp4`, `.mkv`, `.mov`, `.avi`, `.webm`. It is the organizational wrapper that holds together the video stream, the audio stream, metadata (timestamps, titles, GPS), and sometimes subtitles or chapters. The container does not determine video quality — it is packaging.

The **codec** (coder-decoder) is the algorithm that compresses and decompresses the actual picture and sound data. Without compression, one minute of uncompressed 1080p video at 30 fps would be roughly **10 GB**. Codecs make this manageable by discarding information human eyes are unlikely to notice.

Common codecs:

| Codec | Notes |
|-------|-------|
| **H.264 (AVC)** | Dominant for 15+ years. Breaks frames into 16x16 pixel "macroblocks" and uses motion prediction. Universally supported. |
| **H.265 (HEVC)** | Successor to H.264. Uses flexible "Coding Tree Units" up to 64x64 pixels, achieving 25-50% better compression at the same quality. |
| **VP9 / AV1** | Open-source alternatives. AV1 is increasingly popular for web streaming. |

### Frame Types: I, P, and B

Not every frame stores a complete picture. To save space, codecs use three types:

- **I-frames (Intra)** — Complete, standalone images. Like a photograph. The largest frames because they contain everything needed to display themselves. They are "anchor points" in the video stream.

- **P-frames (Predicted)** — Store only what *changed* since the previous frame. If a person walks across a static background, the P-frame only encodes the person's new position. Much smaller than I-frames.

- **B-frames (Bi-directional)** — The most compressed. They reference *both* past and future frames, storing only the differences from both directions. Smallest frames, most processing to decode.

### GOP: Group of Pictures

Frames are organized into **GOPs** — Groups of Pictures. Each GOP starts with an I-frame and is followed by P and B frames until the next I-frame:

```
I  B  B  P  B  B  P  B  B  P  B  B  I  B  B  P ...
|←————————— one GOP ——————————————→|←— next GOP ...
```

The **GOP size** is the number of frames between I-frames (commonly 30, 60, 120, or 250). Longer GOPs mean better compression but less resilience — if data is corrupted, you lose more before the next I-frame can "reset" the picture.

**Forensic insight:** A legitimate, singly-encoded video has a **consistent, regular GOP pattern**. When someone edits or splices video, the GOP pattern almost always becomes irregular.

### How Compression Actually Works

Video compression exploits two kinds of redundancy:

**Spatial redundancy** (within one frame): Large areas of similar color (a blue sky, a white wall) can be described efficiently. The frame is divided into blocks, and a mathematical operation called the **Discrete Cosine Transform (DCT)** converts pixel values into frequency coefficients. High-frequency detail (subtle texture) is aggressively reduced. Low-frequency information (overall color and shape) is preserved. This is why heavily compressed video looks "blocky" — the block boundaries become visible.

**Temporal redundancy** (between frames): Most of what you see in frame 100 is identical to frame 99. Motion estimation algorithms find blocks of pixels that moved between frames and encode only the **motion vectors** (direction + distance) plus any leftover difference.

The **quantization parameter (QP)** controls how aggressively compression discards detail. Higher QP = smaller file, more artifacts. Lower QP = larger file, better quality. This is forensically critical: **re-encoding changes the QP, and double compression leaves detectable mathematical traces**.

---

## 2. How People Tamper with Video

### Splicing

Combining footage from different sources into one apparently continuous video. For example, inserting a clip of someone at a location they never visited into existing footage.

**What it disrupts:** Metadata consistency, compression characteristics, noise patterns, lighting, audio properties, and GOP structure at the edit points.

### Frame Deletion

Removing frames to make events happen faster or to erase critical moments (like the 3 seconds where something incriminating occurred).

**What it disrupts:** Timestamps jump, motion appears unnaturally fast, and the GOP structure breaks because frames are missing from their expected positions.

### Frame Insertion / Duplication

Adding frames — either duplicated from elsewhere in the video or synthesized — to make events appear longer or to insert content.

**What it disrupts:** Duplicate frames create zero-difference sequences that are statistically abnormal. Inserted frames from different sources have different noise and compression characteristics.

### Re-encoding (Transcoding)

Decoding a video and encoding it again with different settings. Often done *after* splicing to "smooth over" the edit points.

**What it disrupts:** Introduces double compression artifacts, changes metadata (encoder tag now shows re-encoding software), and always degrades quality slightly in mathematically predictable patterns.

### Deepfakes

AI-generated face swaps or entirely synthetic video produced by neural networks. Modern deepfakes can swap faces, alter lip movements, change expressions, or generate fictional people.

**What it disrupts:** Subtle inconsistencies in blinking patterns, lighting on face vs. background, skin texture, and frequency-domain artifacts from the generation process. Detection is an active arms race.

### Audio Replacement

Replacing the original audio with different audio while keeping the video. Common in fabricating "evidence" of what someone said.

**What it disrupts:** Audio-visual synchronization (lip movements vs. sound), spectral characteristics at edit points, background noise profiles, and metadata mismatches between audio and video streams.

### Speed Manipulation

Altering playback speed of portions to make events appear faster or slower than reality.

**What it disrupts:** Motion vectors become inconsistent, audio pitch shifts (unless separately processed), and timestamp analysis reveals irregularities.

---

## 3. How Forensic Detection Works

Each detection technique targets a different physical or mathematical property of video. Here is what they detect and *why* the technique works.

### Metadata Analysis

**Targets:** Inconsistencies between what the file *claims* to be and what it *actually* is.

When a camera records video, it writes consistent metadata throughout — encoder name, creation date, duration, bitrate. When someone edits, the editing software writes its *own* metadata. This creates mismatches:

- Container says 60 seconds, video stream says 58.5 seconds → container was not updated after editing
- Declared bitrate does not match (file size / duration) → file was modified after bitrate was calculated
- Audio is 0.4 seconds shorter than video → they were not recorded together
- Encoder tag shows "Adobe Premiere" or "HandBrake" → video passed through editing software

### Compression Artifact Analysis

**Targets:** Evidence of double (or multiple) compression.

When a video is compressed once, the encoder makes specific quantization decisions for each block, creating a mathematical "fingerprint." When re-encoded, the new encoder makes *different* decisions. The interaction between the old and new quantization grids creates detectable periodic patterns:

- **P-frame size periodicity:** Frames that were originally I-frames (high quality) still contain more recoverable detail, so they produce systematically different sizes when re-compressed. This creates a periodic pattern in P-frame sizes at the interval of the original GOP.
- **I-frame size variance:** In a singly-compressed video, all I-frames have roughly similar sizes. In a doubly-compressed video, some I-frames land on positions that were originally I-frames (lots of detail) while others land on positions that were P-frames (less detail), producing unusually high size variation.

### Error Level Analysis (ELA)

**Targets:** Regions or segments with different compression histories.

Re-compress a frame at a fixed quality level and measure the difference between the original and the re-compressed version. In uniformly compressed content, all regions show similar error levels. If a portion was tampered (pasted from a differently-compressed source), it shows a different error level — either higher or lower than surrounding content.

Think of it like this: if you photocopy a document twice, the twice-copied parts look different from the once-copied parts. ELA detects the "copy generation" of each part.

### Temporal Analysis (Timing)

**Targets:** Disruptions in the continuous flow of time.

Legitimate video has smoothly incrementing timestamps. Each packet's DTS (Decode Time Stamp) and PTS (Presentation Time Stamp) should increase at a regular rate (e.g., every ~33ms at 30fps).

- **Non-monotonic DTS:** Timestamps should always increase. If one goes *backward*, something disrupted the timeline — this happens at splice points.
- **Timestamp spikes:** A sudden 200ms gap followed by normal 33ms gaps → frames were removed. A cluster of very short intervals → frames were inserted.

### GOP Structure Analysis

**Targets:** Irregular keyframe patterns.

Encoders place keyframes at fixed intervals. A camera with a 30-frame GOP puts a keyframe every 30th frame, consistently, for the entire recording. The **coefficient of variation** of GOP intervals should be very low. Editing disrupts this regularity because the editor inserts its own keyframes at edit points.

### Scene Change + GOP Correlation

**Targets:** Unnatural placement of scene transitions relative to keyframes.

Most encoders detect scene changes and automatically insert keyframes at those points. In legitimate video, scene changes and keyframes align. In spliced video, scene changes often appear at non-keyframe positions — which is unnatural and indicates post-production manipulation.

### Noise Pattern Analysis

**Targets:** Changes in the video source (different camera, different encoder).

Every camera sensor has a unique noise fingerprint — a combination of quantum shot noise, electronic read noise, and fixed-pattern noise. Different encoding settings also produce different noise characteristics. When content from two different sources is spliced, the noise profile changes at the splice point.

Imagine recording in a quiet room and then in a noisy cafe — even if the visual content looks seamless, the "texture" of the image is different, and that difference is measurable.

### Audio Spectral Analysis

**Targets:** Audio splices and source changes.

The Fast Fourier Transform decomposes sound into frequencies, revealing characteristics invisible in the raw waveform:

- **Spectral centroid:** The "brightness" of sound — its frequency center of mass. An abrupt shift means the acoustic environment changed.
- **RMS energy:** The loudness over time. Splice points create energy discontinuities.
- **Zero-crossing rate:** How often the waveform crosses zero. Different environments produce different patterns.
- **Silence gaps:** Short silences (50-500ms) at non-natural pause points may indicate splice joints.

### Perceptual Hashing

**Targets:** Duplicate or near-duplicate frames.

A perceptual hash converts an image into a compact fingerprint that is similar for visually similar images. Unlike a cryptographic hash (which changes completely if one bit changes), a perceptual hash changes *proportionally* to the visual change.

By measuring the **Hamming distance** (number of differing bits) between consecutive frames, the system detects:

- **Duplicate frames:** Distance near zero for extended runs → freeze-frame or duplication
- **Copy-move:** Segments where hashes match despite being far apart temporally → content was copied

### Statistical Methods

**Targets:** Deviations from expected mathematical distributions.

- **Z-scores (MAD-based):** Measures how many "standard deviations" a value is from the median. quevidkit uses the Median Absolute Deviation (more robust to outliers than standard deviation). Values with z-scores above 4-5 are flagged as anomalous.

- **Autocorrelation:** Measures how similar a signal is to a time-shifted copy of itself. Used to detect the "ghost" of a prior encoding: P-frame sizes show periodic peaks at the original GOP interval, even after re-encoding.

- **Coefficient of Variation (CV):** Standard deviation / mean. Measures regularity. High CV in GOP intervals = inconsistent encoding = possible editing.

- **Distribution analysis:** Comparing frame-size distributions across temporal windows. Single-pass encoding produces stationary distributions. A shift of >40% in one window indicates that segment was encoded differently.

---

## 4. What Each quevidkit Check Does and Why

quevidkit runs up to **11 forensic checks** — 4 in standard mode, 7 additional in deep mode. Each check is independent, measuring a different physical or mathematical property.

### Standard Checks (all presets)

#### 1. Metadata & Codec Consistency

| | |
|---|---|
| **Function** | `metadata_codec_checks()` |
| **Category** | metadata |
| **What it does** | Compares container duration vs. stream duration, declared bitrate vs. observed bitrate, audio vs. video duration. Scans encoder tags for editing software markers (Adobe, Premiere, DaVinci, CapCut, HandBrake, FFmpeg). |
| **Science** | Genuine recordings have internally consistent metadata. Editing disrupts this consistency. |
| **Strength** | Fast, reliable first-pass indicator. |
| **Limitation** | Legitimate transcoding also changes metadata. |

#### 2. Packet Timing Anomalies

| | |
|---|---|
| **Function** | `packet_timing_checks()` |
| **Category** | timing |
| **What it does** | Examines DTS/PTS monotonicity and timestamp delta distribution. Flags non-monotonic DTS and timestamp spikes (deltas >3.5x or <0.25x the median). |
| **Science** | Legitimate video has smoothly incrementing timestamps. Splicing and frame deletion disrupt the timeline. |
| **Strength** | Directly detects frame removal/insertion. Very hard to fake smooth timestamps across a splice. |
| **Limitation** | Variable frame rate video can produce false positives. |

#### 3. Frame Structure Anomalies

| | |
|---|---|
| **Function** | `frame_structure_checks()` |
| **Category** | codec |
| **What it does** | Measures GOP interval coefficient of variation, detects resolution changes mid-stream, and counts color profile variants. |
| **Science** | Single-session recordings have regular GOP patterns and consistent encoding parameters. Editing disrupts both. |
| **Strength** | Catches editing that carefully preserved metadata but disrupted the codec structure. |
| **Limitation** | Adaptive GOP encoders (common in streaming) produce irregular patterns naturally. |

#### 4. Frame Quality Shift

| | |
|---|---|
| **Function** | `opencv_frame_quality_checks()` |
| **Category** | quality |
| **What it does** | Uses OpenCV to sample frames and compute: dHash perceptual hashes (duplicate detection), Laplacian blur variance, 8x8 blockiness metrics, and pixel differences. Detects duplicate frame runs, missing frame gaps, and abrupt quality shifts via z-score analysis. |
| **Science** | Visual quality should not change abruptly in a genuine recording. Duplicate frames are statistically improbable. Blur and blockiness characteristics should be consistent from a single source. |
| **Strength** | Catches visual-level tampering that codec-level checks miss. |
| **Limitation** | Scene changes in legitimate video can trigger quality shift detection. |

### Advanced Checks (deep preset)

#### 5. Compression Consistency

| | |
|---|---|
| **Function** | `compression_consistency_checks()` |
| **Category** | codec |
| **What it does** | Splits the video into 6 temporal windows. Within each window, computes the median packet size for each frame type (I, P, B). Compares each window's median against the global median. A shift of >40% flags that segment. |
| **Science** | Single-pass encoding produces stationary frame-size distributions. Re-encoding a portion shifts the distribution in that segment because the new encoder's quantization decisions differ from the original's. |
| **Analogy** | Like checking if different paragraphs in a document were printed by different printers — each printer produces slightly different ink density. |

#### 6. Scene Cut Forensics

| | |
|---|---|
| **Function** | `scene_cut_forensics_checks()` |
| **Category** | timing |
| **What it does** | Runs ffmpeg scene-change detection, then checks whether each scene change aligns with a nearby keyframe (within 15% of GOP interval + 1 frame). Also detects suspicious clustering of scene changes (<150ms apart). |
| **Science** | Encoders place keyframes at scene changes. Spliced content shows scene changes at non-keyframe positions. Rapid-fire scene changes suggest automated processing or corruption. |
| **Analogy** | Like checking whether chapter breaks in a book align with page breaks — a natural publisher puts chapter headings at the top of new pages; a cut-and-paste job has them mid-page. |

#### 7. Audio Spectral Continuity

| | |
|---|---|
| **Function** | `audio_spectral_checks()` |
| **Category** | audio |
| **What it does** | Extracts audio as 16kHz mono PCM. Computes RMS energy, spectral centroid, and zero-crossing rate over 100ms windows (50ms hop). Uses z-score analysis (threshold z>5) to detect discontinuities. Also flags suspicious short silence gaps (50-500ms). |
| **Science** | Genuine audio from a single recording session has continuous spectral characteristics. Splicing audio creates abrupt frequency-domain discontinuities at the edit points. |
| **Analogy** | Like noticing someone changed radio stations mid-sentence — even if both stations play music, the "color" of the sound is different. |

#### 8. Temporal Noise Consistency

| | |
|---|---|
| **Function** | `temporal_noise_consistency_checks()` |
| **Category** | quality |
| **What it does** | Samples frames at ~2 fps. For each frame, computes: Laplacian standard deviation (noise floor estimate) and Sobel magnitude (high-frequency energy). Detects abrupt shifts via z-score (threshold z>4.5). Also compares first-half vs. second-half noise distributions. |
| **Science** | Every camera and encoding pipeline has a unique noise fingerprint. Splicing content from a different source changes the noise profile. |
| **Analogy** | Like hearing a change in background hum when two phone recordings from different rooms are stitched together — the "room tone" is different. |

#### 9. Double Compression Detection

| | |
|---|---|
| **Function** | `double_compression_detection()` |
| **Category** | codec |
| **What it does** | Computes the autocorrelation of P-frame sizes and searches for periodic peaks at lags that don't align with the current GOP interval. Also checks if I-frame size coefficient of variation exceeds 0.45. |
| **Science** | When a video is re-encoded, the original GOP cadence leaves a periodic "ghost" in the re-encoded data. P-frames that originally fell on I-frame positions retain more detail and produce larger packets, creating a detectable periodic pattern in the autocorrelation function. |
| **Analogy** | Like seeing the faint lines of the original ruled paper showing through when someone photocopied a handwritten letter onto new paper — the old grid is still faintly visible under the new one. |

#### 10. Error Level Analysis (ELA)

| | |
|---|---|
| **Function** | `ela_frame_analysis()` |
| **Category** | quality |
| **What it does** | Re-compresses sampled frames at JPEG quality 75 and measures the residual (difference between original and re-compressed). Detects abrupt shifts in ELA mean/std via z-score (threshold z>4) and flags high temporal variance (CV>0.35). |
| **Science** | Uniformly compressed content produces uniform error levels when re-compressed. Mixed-compression content (where part was tampered and re-saved at a different quality) produces inconsistent residuals. |
| **Analogy** | Like testing whether all pages of a book were printed at the same time — photocopy every page and compare the copy quality. Pages from the original print run look the same; a replacement page inserted later looks different under the same copying process. |

#### 11. Bitstream Structure

| | |
|---|---|
| **Function** | `bitstream_structure_checks()` |
| **Category** | codec |
| **What it does** | Inspects mid-stream color parameter changes, interlaced/progressive mode switches, frame-type size outlier rates (IQR-based, >5% threshold), and B-frame declaration consistency (has_b_frames flag vs. actual B-frame count). |
| **Science** | A single encoding session produces constant codec parameters. Mid-stream changes in color space, interlacing mode, or picture type distributions indicate content was assembled from segments encoded with different settings. |
| **Analogy** | Like checking if all the bricks in a wall are the same type — if half are red clay and half are gray concrete, it tells you the wall was built in two separate phases, even if the mortar looks continuous. |

---

## 5. When the Detector Gets It Wrong

**No single forensic check is definitive.** Many completely legitimate processes produce artifacts that look like tampering. Understanding these is critical for responsible forensic analysis.

### Transcoding / Format Conversion

Converting MOV to MP4, or H.264 to H.265, re-encodes the entire video. This changes encoder metadata, introduces double compression artifacts, may alter GOP structure, and shifts frame-size distributions.

**This is the single most common source of false positives.** A video legitimately exported from iMovie for sharing will trigger metadata, compression, and potentially GOP checks.

### Social Media / Streaming Platforms

Uploading to YouTube, Facebook, TikTok, or Instagram re-encodes the video to multiple quality levels with platform-specific settings. The downloaded version has been re-encoded (double compression), carries platform metadata, and may have been cropped, padded, or frame-rate-converted. These artifacts are **indistinguishable from deliberate tampering** at the codec level.

### Screen Recording

Screen capture creates an entirely new recording with new metadata, potentially different frame rates (introducing duplicate frames), different compression, and different audio encoding. You cannot verify the integrity of the original by examining a screen recording.

### Variable Bitrate (VBR) Encoding

Most modern video uses VBR, allocating more bits to complex scenes and fewer to simple ones. This naturally creates variation in frame sizes that could be confused with compression inconsistency.

### Adaptive GOP / Scene-Based Keyframes

Some encoders use adaptive GOP sizes, inserting keyframes at scene changes rather than at fixed intervals. This produces irregular GOP patterns that look similar to editing artifacts.

### Multi-Camera Editing

Professional productions (news, interviews, sports) legitimately cut between cameras with slightly different color profiles, noise characteristics, and white balance. These cuts trigger scene change, noise consistency, and bitstream checks.

### Audio Processing

Legitimate noise reduction, normalization, or compression for broadcast changes spectral characteristics and can trigger audio spectral checks.

### Concatenated Security Recordings

Some CCTV systems create new files at intervals (every 30 minutes) and concatenate them. Junction points create genuine metadata discontinuities and timestamp resets.

### The Bottom Line

A forensic tool finding "suspicious" artifacts means: "this video has characteristics inconsistent with a single unmodified recording." It does **not** mean: "this video was maliciously tampered with." Expert interpretation is always required to distinguish tampering from legitimate processing.

---

## 6. How Weak Signals Become Strong Evidence

### Why Fusion Matters

No single check is reliable enough alone. Each has legitimate explanations for positive results. The power comes from **combining multiple independent signals**.

If metadata AND timing AND compression AND noise AND audio ALL show anomalies at the same timestamp, the probability of all those being coincidental false positives drops dramatically. This is the mathematical principle behind quevidkit's scoring system.

### How quevidkit Fuses Scores

```
Individual checks  →  Weighted combination  →  Logistic function  →  Verdict
(11 scores)           (confidence-weighted)     (probability curve)    (label)
```

**Step 1 — Each check produces two values:**
- A **score** (0 to 1): how anomalous the check found the video
- A **confidence** (0 to 1): how reliable that particular measurement was, based on data availability

**Step 2 — Confidence-weighted mean:**
Checks with higher confidence have more influence. A check that analyzed 5,000 frames matters more than one that only saw 50.

**Step 3 — Quality gate:**
A separate assessment reduces trust when quality-dependent checks show extreme anomalies (which may indicate the video is simply low-quality, not tampered).

**Step 4 — Logistic function:**
The combined signal is passed through a sigmoid curve:

```
probability = 1 / (1 + e^(-logit))

where logit = bias + (base_score * 5.2) + (quality_gate * 0.4)
and   bias  = -2.6 + (sensitivity * 1.6)
```

The logistic function maps the combined signal onto 0-1 in a way that is **moderate for ambiguous signals** (near 0.5) and **extreme only when evidence is strong** (near 0 or 1). The sensitivity parameter shifts the decision boundary — higher sensitivity catches more but risks more false positives.

**Step 5 — Confidence estimation:**

```
confidence = (coverage * 0.7) + (quality_gate * 0.2) + (agreement * 0.1)
```

- **Coverage** (70% weight): How many of the 11 possible checks ran. More checks = more confidence.
- **Quality gate** (20% weight): Evidence quality.
- **Agreement** (10% weight): How far the base score is from the ambiguous middle.

**Step 6 — Label assignment:**

| Condition | Label |
|-----------|-------|
| Quality gate < 0.3 or confidence < 0.35 | **inconclusive** |
| Probability >= 0.6 | **tampered** |
| Probability >= 0.35 | **suspicious** |
| Otherwise | **authentic** |

### The Bayesian Intuition

While quevidkit uses logistic fusion rather than formal Bayesian inference, the underlying principle is the same: **each piece of evidence updates our belief about whether tampering occurred.** We start with a prior (the bias term), and each check provides a likelihood ratio that shifts the conclusion. Multiple weak signals pointing the same direction compound into strong evidence.

This is like the "wisdom of crowds" effect: individually unreliable judges, when independent and numerous, produce collectively reliable judgments. The key is **independence** — the checks must measure genuinely different things. quevidkit achieves this by spanning metadata, timing, codec structure, visual quality, audio, and noise domains.

---

## 7. Chain of Custody and Legal Use

### What Chain of Custody Means

Chain of custody is the documented history of who handled evidence, what they did with it, when, and why. It creates an unbroken trail from collection to courtroom. For digital video:

- **Acquisition:** Document how the video was obtained (seized from device, downloaded, received from witness), date/time, who performed it, tools used.
- **Hashing:** Compute a cryptographic hash (SHA-256) immediately upon acquisition. This creates a mathematical fingerprint proving the file has not changed since collection. quevidkit computes SHA-256 for exactly this purpose.
- **Secure storage:** Maintain evidence in write-protected, access-controlled storage with logging.
- **Analysis documentation:** Record every tool used, every action taken, every result. quevidkit records start/finish timestamps, analysis options, and complete check results.
- **Transfer documentation:** Log every handoff between individuals or systems.

### Legal Admissibility

For digital evidence to be admissible, courts look for:

1. **Authenticity:** Proof the evidence is what it claims to be (hash verification).
2. **Integrity:** Proof it has not been altered since collection.
3. **Reliability:** Proof the forensic tools are scientifically sound. Open-source tools with transparent, readable code (like quevidkit) support this — anyone can audit the methodology.
4. **Reproducibility:** Another examiner using the same tools should reach the same findings.

### The Documentation Principle

> "If you did not write it down, it did not happen."

This is the guiding principle of digital forensics. quevidkit supports it by generating comprehensive JSON and HTML reports documenting every check, score, confidence, and the reasoning behind the final verdict.

---

## 8. The State of the Field in 2026

### The AI Arms Race

Video forensics is in an arms race between creation and detection:

- **Generation quality is improving faster than detection.** A landmark CSIRO study assessed 16 leading deepfake detectors and found **none performed reliably across a broad range of manipulation techniques**.
- **Anti-forensics is real.** Adversaries specifically design manipulations to evade detection — adversarial perturbations that suppress the features detectors rely on, and deliberate re-encoding to erase compression traces.
- **Generalization failure.** Many detectors achieve 95%+ accuracy on their training data but fail on unseen methods. This is a fundamental limitation of learning-based approaches.

### Why Traditional Signal-Processing Forensics Still Matters

Despite the focus on AI, traditional forensics (the approach quevidkit takes) remains essential:

1. **It is interpretable.** A court can understand "the GOP structure changed at 45.2 seconds" in a way it cannot understand "the neural network output 0.87."
2. **It is reproducible.** Same input + same algorithm = identical result, every time.
3. **It detects what AI misses.** Simple frame deletion, splicing, and re-encoding are often invisible to deepfake detectors but clearly visible to codec analysis.
4. **It requires no training data.** The physics and mathematics *are* the training. Double compression detection works because of the mathematics of quantization, not because a model was shown examples.

### Emerging Directions

- **Multi-feature temporal forensics:** Fusing frame differences, structural similarity, optical flow, and temporal prediction error. Recent 1D-CNN approaches have achieved 95-100% accuracy on specific tampering types.
- **Score-based likelihood ratios:** Applying formal statistical frameworks to forensic conclusions, moving toward rigorous evidence evaluation.
- **Codec-level + pixel-level fusion:** Combining traditional signal-processing with deep learning for comprehensive coverage — codec analysis catches editing artifacts, neural networks catch content manipulation.

### The Fundamental Truth

No automated tool can provide **legal certainty**. quevidkit produces **evidence-backed probability with explanation**, not proof. The tool identifies anomalies; a qualified human interprets what those anomalies mean in context.

The most robust forensic analysis combines:
- Multiple independent detection techniques (what quevidkit does)
- Expert interpretation of results
- Consideration of alternative explanations (transcoding, platform processing, etc.)
- Proper chain of custody documentation
- Reproducible methodology

---

## 9. Further Reading

### Academic Papers and Standards

- *An Overview of Video Tampering Detection Techniques* — IEEE, 2023
- *Systematic Analysis of Video Tampering and Detection Techniques* — Cogent Engineering, 2024
- *Temporal Tampering Detection in Automotive Dashcam Videos* — PMC, 2026
- *Deepfake Media Forensics: Status and Future Challenges* — PMC, 2025
- *Double Compression Detection for H.264 Videos with Adaptive GOP Structure* — Springer, 2019
- *SWGDE Best Practices for Digital Forensic Video Analysis* — SWGDE.org

### Accessible Explanations

- *How to Check Video Integrity by Detecting Double Encoding* — Forensic Focus
- *Error Level Analysis Tutorial* — FotoForensics.com
- *Screen Capture: It's Not the Evidence* — Amped Software Blog
- *How to Maintain Chain of Custody for Digital Evidence* — AMU/APUS
- *How to Make Digital Evidence Admissible in Court* — TrueScreen, 2026

### Tools and Software

- **quevidkit** — Open-source forensic video analysis (this project)
- **FFmpeg / FFprobe** — The foundational video processing toolkit that quevidkit builds on
- **Amped FIVE** — Commercial forensic video analysis suite
- **MediaInfo** — Open-source metadata inspection tool
