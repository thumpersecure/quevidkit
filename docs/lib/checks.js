/**
 * Forensic Check Modules
 *
 * Each check mirrors the Python backend pipeline:
 *   1. containerMetadataCheck  – replaces metadata_codec_checks (ffprobe)
 *   2. timingCheck             – replaces packet_timing_checks (ffprobe)
 *   3. structureCheck          – replaces frame_structure_checks (ffprobe)
 *   4. visualFrameCheck        – replaces opencv_frame_quality_checks
 *   5. audioConsistencyCheck   – new: cross-track duration/codec checks
 *
 * All checks return { name, category, score, confidence, summary, details, segments }.
 */

import { clamp01 } from './scoring.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

function median(arr) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

function mad(values, fallback = 1) {
  if (!values.length) return fallback;
  const med = median(values);
  const spread = median(values.map(v => Math.abs(v - med)));
  return spread > 1e-9 ? spread : fallback;
}

function zScore(value, values) {
  const med = median(values);
  const m = mad(values, 1);
  return (value - med) / (1.4826 * m + 1e-9);
}

const EDITOR_MARKERS = [
  'adobe', 'premiere', 'davinci', 'capcut', 'final cut', 'imovie',
  'handbrake', 'lavf', 'ffmpeg', 'avidemux', 'shotcut', 'openshot',
  'kdenlive', 'hitfilm', 'filmora', 'vegas', 'pinnacle', 'cyberlink',
  'powerdirector', 'movavi', 'kinemaster', 'inshot', 'splice',
  'videoleap', 'luma fusion', 'vn video', 'youcut',
];

const KNOWN_BRANDS = {
  'isom': 'ISO Base Media (generic)',
  'iso2': 'ISO Base Media v2',
  'mp41': 'MP4 v1',
  'mp42': 'MP4 v2',
  'M4V ': 'Apple M4V',
  'M4A ': 'Apple M4A',
  'qt  ': 'Apple QuickTime',
  'avc1': 'AVC/H.264',
  'MSNV': 'Sony MSNV',
  '3gp4': '3GPP v4',
  '3gp5': '3GPP v5',
  'NDSC': 'Nikon DSLR',
  'NDXH': 'Nikon DSLR',
};

// ── 1. Container / Metadata Check ────────────────────────────────────────────

export function containerMetadataCheck(parsed) {
  const findings = [];
  const details = {};

  const { ftyp, mvhd, videoTrack, audioTrack, tags, moovBeforeMdat, fileSize, layout } = parsed;

  if (ftyp.majorBrand) {
    details.majorBrand = ftyp.majorBrand;
    details.brandDescription = KNOWN_BRANDS[ftyp.majorBrand] || 'Unknown';
    details.compatibleBrands = ftyp.compatibleBrands || [];
  }

  if (mvhd.durationSeconds != null) {
    details.containerDurationS = mvhd.durationSeconds;
    details.timescale = mvhd.timescale;
  }

  if (mvhd.creationTime && mvhd.modificationTime) {
    details.creationTime = mvhd.creationTime.toISOString();
    details.modificationTime = mvhd.modificationTime.toISOString();
    const diffMs = Math.abs(mvhd.modificationTime - mvhd.creationTime);
    details.creationModDiffS = diffMs / 1000;
    if (diffMs > 86400000) {
      findings.push(['creation/modification date gap > 24h', clamp01(Math.min(1, diffMs / (86400000 * 30)))]);
    }
  }

  if (videoTrack) {
    const vDur = videoTrack.mdhd?.durationSeconds || 0;
    const cDur = mvhd.durationSeconds || 0;
    details.videoTrackDurationS = vDur;
    details.resolution = `${videoTrack.tkhd?.width || '?'}x${videoTrack.tkhd?.height || '?'}`;

    if (cDur > 0 && vDur > 0) {
      const relDiff = Math.abs(cDur - vDur) / Math.max(cDur, 1e-9);
      details.durationRelativeDiff = relDiff;
      if (relDiff > 0.02 && Math.abs(cDur - vDur) > 0.5) {
        findings.push(['container/stream duration mismatch', clamp01((relDiff - 0.02) / 0.12)]);
      }
    }

    if (videoTrack.stsd?.entries?.length) {
      details.videoCodec = videoTrack.stsd.entries[0]?.format || 'unknown';
    }

    const totalSamples = videoTrack.stsz?.sampleCount || 0;
    if (totalSamples > 0 && vDur > 0) {
      details.estimatedFps = totalSamples / vDur;
    }
  }

  if (audioTrack) {
    const aDur = audioTrack.mdhd?.durationSeconds || 0;
    const cDur = mvhd.durationSeconds || 0;
    details.audioTrackDurationS = aDur;
    if (aDur > 0 && cDur > 0) {
      const avDiff = Math.abs(aDur - cDur);
      details.audioVideoDurationDiffS = avDiff;
      if (avDiff > 0.35) {
        findings.push(['audio/video duration mismatch', clamp01((avDiff - 0.35) / 3.0)]);
      }
    }
    if (audioTrack.stsd?.entries?.length) {
      details.audioCodec = audioTrack.stsd.entries[0]?.format || 'unknown';
    }
  }

  if (fileSize > 0 && mvhd.durationSeconds > 0) {
    const observedBitrate = (fileSize * 8) / mvhd.durationSeconds;
    details.observedBitrateKbps = Math.round(observedBitrate / 1000);
    details.fileSizeBytes = fileSize;
  }

  const tagStr = Object.values(tags).join(' ').toLowerCase();
  const matchedEditors = EDITOR_MARKERS.filter(m => tagStr.includes(m));
  if (matchedEditors.length > 0) {
    details.editorSignatures = matchedEditors;
    findings.push(['editing/transcoding software marker present', 0.2]);
  }
  if (Object.keys(tags).length > 0) {
    details.tags = tags;
  }

  if (moovBeforeMdat !== null) {
    details.moovBeforeMdat = moovBeforeMdat;
    if (moovBeforeMdat) {
      details.moovNote = 'moov before mdat (web-optimized or re-muxed)';
    }
  }

  if (videoTrack?.elst) {
    const editEntries = videoTrack.elst.entries || [];
    if (editEntries.length > 1) {
      findings.push(['multiple edit list entries (complex editing)', clamp01(0.15 + editEntries.length * 0.05)]);
      details.editListEntries = editEntries.length;
    } else if (editEntries.length === 1) {
      details.editListEntries = 1;
    }
  }

  const topTypes = layout.map(l => l.type);
  details.topLevelBoxes = topTypes;
  const freeCount = topTypes.filter(t => t === 'free' || t === 'skip').length;
  if (freeCount >= 3) {
    findings.push(['excessive free/skip boxes (multiple muxing passes)', clamp01(0.1 + freeCount * 0.04)]);
  }

  let score, summary;
  if (!findings.length) {
    score = 0.05;
    summary = 'Metadata and container checks look consistent.';
  } else {
    score = clamp01(findings.reduce((s, [, w]) => s + w, 0) / findings.length);
    summary = findings.map(([m]) => m).join('; ');
  }

  let confidence = 0.85;
  if (!videoTrack) confidence -= 0.4;
  if (!mvhd.durationSeconds) confidence -= 0.15;

  return {
    name: 'container_metadata',
    category: 'metadata',
    score,
    confidence: clamp01(confidence),
    summary,
    details: { ...details, findings: findings.map(([m, w]) => ({ finding: m, severity: w })) },
    segments: [],
  };
}

// ── 2. Timing Check (from stts / ctts) ──────────────────────────────────────

export function timingCheck(parsed) {
  const vt = parsed.videoTrack;
  if (!vt || !vt.stts?.entries?.length) {
    return {
      name: 'sample_timing',
      category: 'timing',
      score: 0,
      confidence: 0.05,
      summary: 'No sample timing data available.',
      details: {},
      segments: [],
    };
  }

  const timescale = vt.mdhd?.timescale || 1;
  const sttsEntries = vt.stts.entries;
  const details = {};
  const segments = [];

  const deltas = sttsEntries.map(e => e.sampleDelta / timescale);
  const totalSamples = sttsEntries.reduce((a, e) => a + e.sampleCount, 0);
  details.totalSamples = totalSamples;
  details.sttsEntryCount = sttsEntries.length;

  const uniqueDeltas = [...new Set(sttsEntries.map(e => e.sampleDelta))];
  details.uniqueDeltaValues = uniqueDeltas.length;

  let nonUniformRate = 0;
  if (sttsEntries.length > 1) {
    const medDelta = median(deltas);
    let sampleIdx = 0;
    let timeSoFar = 0;
    for (const entry of sttsEntries) {
      const delta = entry.sampleDelta / timescale;
      if (delta > 0) {
        const ratio = delta / (medDelta || 1e-9);
        if (ratio > 3.5 || ratio < 0.25) {
          const startS = timeSoFar;
          const endS = timeSoFar + delta * entry.sampleCount;
          segments.push({
            category: 'timing_anomaly',
            start_s: startS,
            end_s: endS,
            confidence: 0.75,
            details: { delta, medianDelta: medDelta, ratio },
          });
          nonUniformRate++;
        }
      }
      timeSoFar += delta * entry.sampleCount;
      sampleIdx += entry.sampleCount;
    }
  }

  if (vt.ctts?.entries?.length) {
    const cttsEntries = vt.ctts.entries;
    details.cttsEntryCount = cttsEntries.length;
    const offsets = cttsEntries.map(e => e.sampleOffset / timescale);
    const negativeOffsets = offsets.filter(o => o < 0);
    details.negativeCttsOffsets = negativeOffsets.length;
  }

  const spikeRate = nonUniformRate / Math.max(1, sttsEntries.length);
  details.timingAnomalyRate = spikeRate;

  const isVFR = uniqueDeltas.length > 2;
  details.variableFrameRate = isVFR;

  let score;
  if (isVFR && sttsEntries.length > 10) {
    score = clamp01(0.15 + spikeRate * 2);
  } else {
    score = clamp01(spikeRate * 3);
  }

  const confidence = clamp01(0.55 + Math.min(totalSamples, 10000) / 15000);

  return {
    name: 'sample_timing',
    category: 'timing',
    score,
    confidence,
    summary: score < 0.1
      ? 'Sample timing is consistent.'
      : 'Timing anomalies detected in sample duration table.',
    details,
    segments: segments.slice(0, 150),
  };
}

// ── 3. Structure Check (GOP / sample sizes) ─────────────────────────────────

export function structureCheck(parsed) {
  const vt = parsed.videoTrack;
  if (!vt) {
    return {
      name: 'frame_structure',
      category: 'codec',
      score: 0,
      confidence: 0.05,
      summary: 'No video track found.',
      details: {},
      segments: [],
    };
  }

  const details = {};
  const segments = [];
  let gopScore = 0, sizeScore = 0, codecScore = 0;

  if (vt.stss?.entries?.length) {
    const keyframes = vt.stss.entries;
    details.keyframeCount = keyframes.length;
    const intervals = [];
    for (let i = 1; i < keyframes.length; i++) {
      intervals.push(keyframes[i] - keyframes[i - 1]);
    }
    if (intervals.length > 0) {
      const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((s, x) => s + (x - avg) ** 2, 0) / Math.max(1, intervals.length - 1);
      const std = Math.sqrt(variance);
      const cv = std / Math.max(avg, 1e-9);
      details.gopIntervalMean = avg;
      details.gopIntervalStd = std;
      details.gopIntervalCV = cv;
      gopScore = clamp01((cv - 0.6) / 0.9);

      if (cv > 0.8) {
        const timescale = vt.mdhd?.timescale || 1;
        const medInterval = median(intervals);
        let sampleIdx = 0;
        let timeAcc = 0;
        const sttsEntries = vt.stts?.entries || [];
        const sampleTimes = [];
        for (const entry of sttsEntries) {
          for (let j = 0; j < entry.sampleCount; j++) {
            sampleTimes.push(timeAcc / timescale);
            timeAcc += entry.sampleDelta;
          }
        }
        for (let i = 1; i < keyframes.length; i++) {
          const gap = keyframes[i] - keyframes[i - 1];
          if (gap > medInterval * 3) {
            const startIdx = keyframes[i - 1] - 1;
            const endIdx = keyframes[i] - 1;
            segments.push({
              category: 'gop_irregularity',
              start_s: sampleTimes[startIdx] || 0,
              end_s: sampleTimes[endIdx] || 0,
              confidence: 0.7,
              details: { gopGap: gap, medianGop: medInterval },
            });
          }
        }
      }
    }
  } else {
    details.keyframeCount = 0;
    details.noSyncSampleTable = true;
  }

  if (vt.stsz?.entries?.length > 10) {
    const sizes = vt.stsz.entries;
    const med = median(sizes);
    const m = mad(sizes, 1);
    let outlierCount = 0;
    for (const sz of sizes) {
      const z = Math.abs(sz - med) / (1.4826 * m + 1e-9);
      if (z > 6) outlierCount++;
    }
    const outlierRate = outlierCount / sizes.length;
    details.sampleSizeOutlierRate = outlierRate;
    sizeScore = clamp01(outlierRate * 5);
  } else if (vt.stsz?.sampleSize > 0) {
    details.constantSampleSize = vt.stsz.sampleSize;
  }

  if (vt.stsd?.entries?.length > 1) {
    codecScore = 0.6;
    details.multipleCodecEntries = vt.stsd.entries.map(e => e.format);
  }

  const score = clamp01(gopScore * 0.45 + sizeScore * 0.3 + codecScore * 0.25);
  const totalSamples = vt.stsz?.sampleCount || 0;
  const confidence = clamp01(0.5 + Math.min(totalSamples, 6000) / 10000);

  return {
    name: 'frame_structure',
    category: 'codec',
    score,
    confidence,
    summary: score < 0.1
      ? 'Frame structure looks stable.'
      : 'Frame-level structural anomalies detected.',
    details,
    segments: segments.slice(0, 120),
  };
}

// ── 4. Visual Frame Check (Canvas-based) ─────────────────────────────────────

function averageHash(gray, width, height) {
  const tw = 8, th = 8;
  const cw = width / tw, ch = height / th;
  const sample = [];
  for (let y = 0; y < th; y++) {
    for (let x = 0; x < tw; x++) {
      const px = Math.min(width - 1, Math.floor((x + 0.5) * cw));
      const py = Math.min(height - 1, Math.floor((y + 0.5) * ch));
      sample.push(gray[py * width + px]);
    }
  }
  const mean = sample.reduce((a, b) => a + b, 0) / sample.length;
  return sample.map(v => (v >= mean ? 1 : 0));
}

function dHash(gray, width, height) {
  const tw = 9, th = 8;
  const cw = width / tw, ch = height / th;
  const sample = new Uint8Array(tw * th);
  for (let y = 0; y < th; y++) {
    for (let x = 0; x < tw; x++) {
      const px = Math.min(width - 1, Math.floor((x + 0.5) * cw));
      const py = Math.min(height - 1, Math.floor((y + 0.5) * ch));
      sample[y * tw + x] = gray[py * width + px];
    }
  }
  const bits = [];
  for (let y = 0; y < th; y++) {
    for (let x = 0; x < th; x++) {
      bits.push(sample[y * tw + x] < sample[y * tw + x + 1] ? 1 : 0);
    }
  }
  return bits;
}

function hammingBits(a, b) {
  let d = 0;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) d++;
  }
  return d;
}

function getGray(imageData) {
  const { data, width, height } = imageData;
  const gray = new Uint8Array(width * height);
  let idx = 0;
  for (let i = 0; i < data.length; i += 4) {
    gray[idx++] = Math.round(0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]);
  }
  return { gray, width, height };
}

function meanAbsDiff(a, b) {
  const len = Math.min(a.length, b.length);
  let sum = 0;
  for (let i = 0; i < len; i++) sum += Math.abs(a[i] - b[i]);
  return sum / Math.max(1, len);
}

function laplacianVariance(gray, w, h) {
  if (w < 3 || h < 3) return 0;
  let mean = 0, sq = 0, count = 0;
  for (let y = 1; y < h - 1; y++) {
    for (let x = 1; x < w - 1; x++) {
      const c = gray[y * w + x];
      const lap = 4 * c - gray[(y - 1) * w + x] - gray[(y + 1) * w + x]
                       - gray[y * w + (x - 1)] - gray[y * w + (x + 1)];
      mean += lap;
      sq += lap * lap;
      count++;
    }
  }
  if (!count) return 0;
  mean /= count;
  return sq / count - mean * mean;
}

function computeBlockiness(gray, w, h) {
  if (w < 17 || h < 17) return 0;
  let edge = 0, eCount = 0, inner = 0, iCount = 0;
  for (let x = 8; x < w; x += 8) {
    for (let y = 0; y < h; y++) { edge += Math.abs(gray[y * w + x] - gray[y * w + (x - 1)]); eCount++; }
  }
  for (let y = 8; y < h; y += 8) {
    for (let x = 0; x < w; x++) { edge += Math.abs(gray[y * w + x] - gray[(y - 1) * w + x]); eCount++; }
  }
  for (let x = 4; x < w; x += 8) {
    for (let y = 0; y < h; y++) { inner += Math.abs(gray[y * w + x] - gray[y * w + (x - 1)]); iCount++; }
  }
  for (let y = 4; y < h; y += 8) {
    for (let x = 0; x < w; x++) { inner += Math.abs(gray[y * w + x] - gray[(y - 1) * w + x]); iCount++; }
  }
  return Math.max(0, edge / Math.max(1, eCount) - inner / Math.max(1, iCount));
}

function luminanceHistogram(gray) {
  const hist = new Uint32Array(256);
  for (let i = 0; i < gray.length; i++) hist[gray[i]]++;
  return hist;
}

function histogramCorrelation(h1, h2) {
  const n = h1.length;
  let sum1 = 0, sum2 = 0;
  for (let i = 0; i < n; i++) { sum1 += h1[i]; sum2 += h2[i]; }
  const mean1 = sum1 / n, mean2 = sum2 / n;
  let num = 0, d1 = 0, d2 = 0;
  for (let i = 0; i < n; i++) {
    const a = h1[i] - mean1, b = h2[i] - mean2;
    num += a * b;
    d1 += a * a;
    d2 += b * b;
  }
  const denom = Math.sqrt(d1 * d2);
  return denom > 0 ? num / denom : 1;
}

function waitSeek(video, t) {
  return new Promise((resolve, reject) => {
    const onSeeked = () => { video.removeEventListener('seeked', onSeeked); resolve(); };
    const onError = () => { video.removeEventListener('error', onError); reject(new Error('Seek failed')); };
    video.addEventListener('seeked', onSeeked, { once: true });
    video.addEventListener('error', onError, { once: true });
    video.currentTime = t;
  });
}

function loadVideoMeta(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const v = document.createElement('video');
    v.preload = 'metadata';
    v.muted = true;
    v.playsInline = true;
    v.src = url;
    v.onloadedmetadata = () => resolve({ video: v, url, duration: v.duration, width: v.videoWidth, height: v.videoHeight });
    v.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Cannot decode video in browser.')); };
  });
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

export async function visualFrameCheck(file, options, onProgress) {
  const meta = await loadVideoMeta(file);
  const cw = 320, ch = 180;
  const canvas = document.createElement('canvas');
  canvas.width = cw;
  canvas.height = ch;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) throw new Error('Canvas unavailable');

  const sampleTimes = [];
  for (let t = 0; t < meta.duration; t += options.sampleInterval) {
    sampleTimes.push(t);
    if (sampleTimes.length >= options.maxSamples) break;
  }
  if (!sampleTimes.length) sampleTimes.push(0);

  const blurs = [], blocks = [], histograms = [];
  const duplicateSegs = [], missingSegs = [], qualitySegs = [], histSegs = [];
  let dupRunStart = null, prevGray = null, prevHash = null, prevTime = 0, prevHist = null;

  for (let i = 0; i < sampleTimes.length; i++) {
    const t = sampleTimes[i];
    try { await waitSeek(meta.video, t); } catch { continue; }
    ctx.drawImage(meta.video, 0, 0, cw, ch);
    const imgData = ctx.getImageData(0, 0, cw, ch);
    const { gray, width, height } = getGray(imgData);
    const h = dHash(gray, width, height);
    const blur = laplacianVariance(gray, width, height);
    const block = computeBlockiness(gray, width, height);
    const hist = luminanceHistogram(gray);

    blurs.push(blur);
    blocks.push(block);
    histograms.push(hist);

    if (prevGray && prevHash) {
      const diff = meanAbsDiff(gray, prevGray);
      const hd = hammingBits(h, prevHash) / 64;

      if (hd < 0.06 && diff < 3.2) {
        if (dupRunStart === null) dupRunStart = sampleTimes[i - 1];
      } else if (dupRunStart !== null) {
        duplicateSegs.push({ category: 'duplicate_frames', start_s: dupRunStart, end_s: t, confidence: 0.86 });
        dupRunStart = null;
      }

      const obsDelta = t - prevTime;
      if (obsDelta > options.sampleInterval * 1.8) {
        missingSegs.push({
          category: 'missing_frames',
          start_s: prevTime,
          end_s: t,
          confidence: Math.min(0.96, 0.55 + (obsDelta / options.sampleInterval) * 0.08),
        });
      }

      if (prevHist) {
        const corr = histogramCorrelation(hist, prevHist);
        if (corr < 0.7) {
          histSegs.push({
            category: 'histogram_break',
            start_s: prevTime,
            end_s: t,
            confidence: clamp01(0.5 + (1 - corr)),
            details: { correlation: corr },
          });
        }
      }
    }

    prevGray = gray;
    prevHash = h;
    prevTime = t;
    prevHist = hist;

    if (onProgress) onProgress(i, sampleTimes.length);
    if (i % 4 === 0) await sleep(0);
  }

  if (dupRunStart !== null && sampleTimes.length > 1) {
    duplicateSegs.push({ category: 'duplicate_frames', start_s: dupRunStart, end_s: sampleTimes[sampleTimes.length - 1], confidence: 0.84 });
  }

  URL.revokeObjectURL(meta.url);

  const shifts = [];
  for (let i = 1; i < blurs.length; i++) {
    shifts.push(Math.abs(blurs[i] - blurs[i - 1]) * 0.7 + Math.abs(blocks[i] - blocks[i - 1]) * 0.3);
  }
  if (shifts.length > 0) {
    const center = median(shifts);
    const spread = mad(shifts, 1);
    for (let i = 0; i < shifts.length; i++) {
      const z = (shifts[i] - center) / (1.4826 * spread + 1e-9);
      if (z > 4) {
        qualitySegs.push({
          category: 'quality_shift',
          start_s: sampleTimes[i],
          end_s: sampleTimes[Math.min(sampleTimes.length - 1, i + 1)],
          confidence: clamp01(Math.min(0.98, 0.55 + z / 10)),
          details: { zScore: z },
        });
      }
    }
  }

  const allSegs = [...duplicateSegs, ...missingSegs, ...qualitySegs, ...histSegs]
    .sort((a, b) => a.start_s - b.start_s);

  const dupRate = duplicateSegs.length / Math.max(1, sampleTimes.length);
  const missRate = missingSegs.length / Math.max(1, sampleTimes.length);
  const qualRate = qualitySegs.length / Math.max(1, sampleTimes.length);
  const histRate = histSegs.length / Math.max(1, sampleTimes.length);

  const score = clamp01(dupRate * 8 + missRate * 6 + qualRate * 10 + histRate * 4);
  const confidence = clamp01(0.35 + Math.min(sampleTimes.length, options.maxSamples) / Math.max(options.maxSamples, 1));

  return {
    name: 'visual_frame_analysis',
    category: 'quality',
    score,
    confidence,
    summary: score < 0.1
      ? 'No strong visual anomalies found.'
      : 'Visual anomalies indicate possible duplicate/drop or quality discontinuities.',
    details: {
      sampledFrames: sampleTimes.length,
      videoDurationS: meta.duration,
      videoResolution: `${meta.width}x${meta.height}`,
      duplicateRuns: duplicateSegs.length,
      missingEvents: missingSegs.length,
      qualityShifts: qualitySegs.length,
      histogramBreaks: histSegs.length,
    },
    segments: allSegs.slice(0, 200),
  };
}

// ── 5. Audio Consistency Check ───────────────────────────────────────────────

export function audioConsistencyCheck(parsed) {
  const { audioTrack, videoTrack, mvhd } = parsed;
  if (!audioTrack) {
    return {
      name: 'audio_consistency',
      category: 'audio',
      score: 0,
      confidence: 0.1,
      summary: 'No audio track present.',
      details: {},
      segments: [],
    };
  }

  const findings = [];
  const details = {};
  const aDur = audioTrack.mdhd?.durationSeconds || 0;
  const vDur = videoTrack?.mdhd?.durationSeconds || mvhd?.durationSeconds || 0;
  details.audioDurationS = aDur;
  details.videoDurationS = vDur;

  if (aDur > 0 && vDur > 0) {
    const diff = Math.abs(aDur - vDur);
    details.avDurationDiffS = diff;
    if (diff > 0.5) {
      findings.push(['audio/video duration mismatch', clamp01((diff - 0.5) / 3.0)]);
    }
  }

  if (audioTrack.stts?.entries?.length > 1) {
    const sttsEntries = audioTrack.stts.entries;
    const uniqueDeltas = new Set(sttsEntries.map(e => e.sampleDelta));
    if (uniqueDeltas.size > 5) {
      findings.push(['variable audio frame timing', 0.15]);
      details.audioTimingVariants = uniqueDeltas.size;
    }
  }

  if (audioTrack.elst?.entries?.length > 1) {
    findings.push(['audio edit list with multiple entries', 0.25]);
    details.audioEditListEntries = audioTrack.elst.entries.length;
  }

  const audioSamples = audioTrack.stsz?.sampleCount || 0;
  details.audioSampleCount = audioSamples;

  let score = 0;
  if (findings.length > 0) {
    score = clamp01(findings.reduce((s, [, w]) => s + w, 0) / findings.length);
  }

  return {
    name: 'audio_consistency',
    category: 'audio',
    score,
    confidence: clamp01(0.5 + (audioSamples > 1000 ? 0.3 : 0)),
    summary: score < 0.1
      ? 'Audio track appears consistent.'
      : findings.map(([m]) => m).join('; '),
    details,
    segments: [],
  };
}
