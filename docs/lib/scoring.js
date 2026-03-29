/**
 * Score Fusion Module
 *
 * Direct port of src/quevidkit/scoring.py to JavaScript.
 * Combines individual check scores into a final tamper probability,
 * confidence, and decision label.
 */

export function clamp01(v) {
  return Math.max(0, Math.min(1, v));
}

function weightedMean(pairs) {
  let num = 0, den = 0;
  for (const [value, weight] of pairs) {
    num += value * weight;
    den += weight;
  }
  return den === 0 ? 0 : num / den;
}

function qualityGate(checks) {
  const signals = [];
  for (const c of checks) {
    if (c.name === 'visual_frame_analysis' || c.name === 'frame_quality_shift') {
      signals.push([1 - clamp01(c.score), 1.0]);
    } else if (['metadata', 'codec', 'timing', 'quality', 'audio'].includes(c.category)) {
      signals.push([clamp01(c.confidence), 0.6]);
    }
  }
  return weightedMean(signals);
}

function corroborationFactor(checks) {
  const flaggedCategories = new Set();
  for (const c of checks) {
    if (c.score >= 0.25 && c.confidence >= 0.35) {
      flaggedCategories.add(c.category);
    }
  }
  const n = flaggedCategories.size;
  if (n === 0) return 0;
  if (n === 1) return 0.4;
  if (n === 2) return 0.7;
  return Math.min(1, 0.7 + n * 0.1);
}

function loneWolfPenalty(checks) {
  const high = checks.filter(c => c.score >= 0.35 && c.confidence >= 0.3);
  const low = checks.filter(c => c.score < 0.15 && c.confidence >= 0.3);
  if (high.length === 1 && low.length >= 3) return 0.55;
  if (high.length === 1 && low.length >= 2) return 0.70;
  return 1.0;
}

export function fuseScores(checks, sensitivity = 0.7) {
  if (!checks.length) return { probability: 0.5, confidence: 0, label: 'inconclusive' };

  const weighted = checks.map(c => [clamp01(c.score), Math.max(0.05, c.confidence)]);
  const base = weightedMean(weighted);
  const gate = qualityGate(checks);
  const corr = corroborationFactor(checks);
  const penalty = loneWolfPenalty(checks);

  const bias = -3.0 + sensitivity * 1.6;
  const logit = bias + base * 5.2 + gate * 0.4 + corr * 1.0;
  let probability = 1 / (1 + Math.exp(-logit));
  probability *= penalty;

  const coverage = Math.min(1, checks.length / 15);
  const agreement = 1 - Math.abs(base - 0.5) * 0.5;
  const confidence = clamp01(coverage * 0.6 + gate * 0.2 + agreement * 0.1 + corr * 0.1);

  let label;
  if (gate < 0.3 || confidence < 0.35) {
    label = 'inconclusive';
  } else if (probability >= 0.65) {
    label = 'tampered';
  } else if (probability >= 0.38) {
    label = 'suspicious';
  } else {
    label = 'authentic';
  }

  return {
    probability: clamp01(probability),
    confidence,
    label,
  };
}

// ── Per-check context for rich explanations ──────────────────────────────────

const CHECK_CONTEXT = {
  container_metadata: {
    what: 'Compares container metadata (durations, bitrates, format tags) against stream data.',
    tampered: 'Metadata mismatches can indicate re-muxing, trimming, or splicing without updating container headers.',
    benign: 'Legitimate re-encoding, format conversion, or streaming software commonly causes minor metadata drift.',
  },
  metadata_codec_consistency: {
    what: 'Compares container metadata (durations, bitrates, format tags) against stream data.',
    tampered: 'Metadata mismatches can indicate re-muxing, trimming, or splicing without updating container headers.',
    benign: 'Legitimate re-encoding, format conversion, or streaming software commonly causes minor metadata drift.',
  },
  sample_timing: {
    what: 'Inspects sample/packet timing for gaps or non-monotonic sequences.',
    tampered: 'Timestamp discontinuities often appear at splice points where segments were joined.',
    benign: 'VFR cameras, screen captures, and live recordings commonly produce irregular timing.',
  },
  packet_timing_anomalies: {
    what: 'Inspects packet timestamp continuity for gaps or non-monotonic sequences.',
    tampered: 'Timestamp discontinuities often appear at splice points where segments were joined.',
    benign: 'VFR cameras, screen captures, and live recordings commonly produce irregular timing.',
  },
  frame_structure: {
    what: 'Analyzes GOP regularity, resolution consistency, and color profile stability.',
    tampered: 'Irregular GOP patterns or mid-stream resolution changes suggest concatenated content.',
    benign: 'Adaptive bitrate recording and scene-based keyframe insertion intentionally vary GOP structure.',
  },
  frame_structure_anomalies: {
    what: 'Analyzes GOP regularity, resolution consistency, and color profile stability.',
    tampered: 'Irregular GOP patterns or mid-stream resolution changes suggest concatenated content.',
    benign: 'Adaptive bitrate recording and scene-based keyframe insertion intentionally vary GOP structure.',
  },
  visual_frame_analysis: {
    what: 'Measures frame-to-frame quality changes (blur, blockiness, duplicate/missing frames).',
    tampered: 'Abrupt quality discontinuities can indicate where a tampered segment was inserted.',
    benign: 'Scene changes, focus shifts, and bandwidth-adaptive encoding naturally cause quality variation.',
  },
  frame_quality_shift: {
    what: 'Measures frame-to-frame quality changes (blur, blockiness, duplicate/missing frames).',
    tampered: 'Abrupt quality discontinuities can indicate where a tampered segment was inserted.',
    benign: 'Scene changes, focus shifts, and bandwidth-adaptive encoding naturally cause quality variation.',
  },
  audio_consistency: {
    what: 'Checks audio track duration, codec, and cross-track consistency.',
    tampered: 'Audio/video duration mismatches or codec inconsistencies may indicate post-processing.',
    benign: 'Minor A/V duration differences are common in many container formats.',
  },
  browser_temporal_continuity: {
    what: 'Analyzes frame-to-frame pixel continuity for abrupt visual breaks.',
    tampered: 'Sharp visual discontinuities between adjacent frames may indicate inserted content.',
    benign: 'Scene cuts, camera motion, and flash effects produce legitimate visual breaks.',
  },
  compression_consistency: {
    what: 'Compares packet-size distributions across timeline segments per frame type.',
    tampered: 'If part of the video was re-encoded at different quality, that segment shows different packet sizes.',
    benign: 'VBR encoding and scene complexity naturally cause legitimate packet-size variation.',
  },
  scene_cut_forensics: {
    what: 'Correlates scene transitions with GOP/keyframe structure.',
    tampered: 'Spliced content often shows scene changes that don\'t align with the natural keyframe cadence.',
    benign: 'Scene-based encoding and variable GOP modes produce legitimate misalignment.',
  },
  audio_spectral_continuity: {
    what: 'Computes audio spectral features over sliding windows to detect abrupt discontinuities.',
    tampered: 'Audio splices produce sharp spectral breaks from different recording environments.',
    benign: 'Sudden sounds, background noise changes, and microphone handling create legitimate breaks.',
  },
  temporal_noise_consistency: {
    what: 'Measures per-frame noise levels to detect source changes across the timeline.',
    tampered: 'Content from a different camera/encoder produces a different noise profile at splice boundaries.',
    benign: 'Lighting changes, auto-ISO adjustments, and scene complexity naturally alter noise characteristics.',
  },
  double_compression_detection: {
    what: 'Analyzes I-frame size periodicity to detect re-encoding over previously compressed video.',
    tampered: 'A detected GOP period that doesn\'t match the current GOP strongly indicates re-processing.',
    benign: 'Social media uploads and messaging apps routinely re-encode video without content changes.',
  },
  ela_frame_analysis: {
    what: 'Re-compresses frames at fixed quality and measures the residual difference.',
    tampered: 'Regions re-compressed at different quality produce ELA residuals that stand out.',
    benign: 'Complex textures and sharp edges naturally produce higher ELA variation.',
  },
  bitstream_structure: {
    what: 'Checks for mid-stream codec parameter changes (color space, interlacing, frame-type distributions).',
    tampered: 'Parameter switches strongly indicate concatenation from different encoding sessions.',
    benign: 'Some broadcast formats legitimately switch parameters (HDR/SDR transitions).',
  },
  qp_consistency: {
    what: 'Analyzes GOP frame-type patterns for consistency across the timeline.',
    tampered: 'Pattern changes indicate segments encoded by different software or settings.',
    benign: 'Scene-based encoding decisions intentionally vary GOP patterns for optimal quality.',
  },
  thumbnail_mismatch: {
    what: 'Compares the embedded thumbnail against the actual first frame of the video.',
    tampered: 'Editing tools often update content but leave the original thumbnail unchanged.',
    benign: 'Some platforms set thumbnails from a mid-video keyframe, not the first frame.',
  },
  av_sync_drift: {
    what: 'Measures audio-video timing offset at checkpoints across the timeline.',
    tampered: 'Splicing without adjusting audio timestamps causes A/V sync jumps at edit points.',
    benign: 'VFR recording and streaming protocols introduce minor A/V offsets normally.',
  },
  bitrate_distribution: {
    what: 'Tests whether packet-size distribution is unimodal (single source) or bimodal (mixed sources).',
    tampered: 'Splicing content from two quality levels creates a bimodal distribution.',
    benign: 'Highly variable content and VBR encoding can produce wide distributions.',
  },
};

function confidenceQualifier(confidence) {
  if (confidence >= 0.8) return 'strongly suggests';
  if (confidence >= 0.6) return 'suggests';
  if (confidence >= 0.4) return 'may indicate';
  return 'weakly hints at';
}

export function buildExplanation(checks, label, probability, confidence) {
  const lines = [];
  const active = checks.filter(c => c.score >= 0.1);
  const high = checks.filter(c => c.score >= 0.4 && c.confidence >= 0.4);
  const total = checks.length;

  // Overall verdict
  if (label === 'authentic') {
    lines.push(
      `Verdict: AUTHENTIC \u2014 After running ${total} forensic checks, no significant ` +
      `tampering indicators were detected. The video\u2019s metadata, timing, compression, ` +
      `and visual characteristics are all consistent with a single recording session.`
    );
    if (active.length) {
      lines.push(
        `Note: ${active.length} check(s) showed minor anomalies (listed below), ` +
        `but none were strong enough to indicate tampering. Minor anomalies are normal.`
      );
    }
  } else if (label === 'inconclusive') {
    lines.push(
      `Verdict: INCONCLUSIVE \u2014 The evidence quality was not sufficient for a confident ` +
      `determination. This can happen with very short videos, unusual codecs, or when anomalies ` +
      `could equally be explained by legitimate processing. Try the deep preset for more thorough analysis.`
    );
  } else if (label === 'suspicious') {
    lines.push(
      `Verdict: SUSPICIOUS \u2014 ${active.length} of ${total} checks detected anomalies, ` +
      `with ${high.length} showing moderate-to-strong signals. While these findings ` +
      `are consistent with tampering, they could also result from legitimate video processing ` +
      `(re-encoding, format conversion, platform upload). See per-check details below.`
    );
  } else {
    const flaggedCats = new Set(high.map(c => c.category));
    let corrMsg = '';
    if (flaggedCats.size >= 3) {
      corrMsg = ` Critically, ${flaggedCats.size} independent forensic categories ` +
        `(${[...flaggedCats].sort().join(', ')}) detected anomalies simultaneously, ` +
        `which significantly reduces the likelihood of false positive.`;
    } else if (flaggedCats.size === 2) {
      corrMsg = ` Two independent categories (${[...flaggedCats].sort().join(', ')}) ` +
        `flagged anomalies, providing some corroboration.`;
    } else {
      corrMsg = ` However, the findings come from only ${flaggedCats.size ? 'one category' : 'limited data'}, ` +
        `so consider the benign explanations below before concluding tampering.`;
    }
    const prob = probability != null ? (probability * 100).toFixed(0) : '?';
    const conf = confidence != null ? (confidence * 100).toFixed(0) : '?';
    lines.push(
      `Verdict: TAMPERED \u2014 ${high.length} of ${total} checks found strong anomalies ` +
      `(tamper probability ${prob}%, confidence ${conf}%).${corrMsg}`
    );
  }

  // Per-check detail
  const strongest = [...checks].sort((a, b) => b.score * b.confidence - a.score * a.confidence);
  for (const c of strongest) {
    if (c.score < 0.08) continue;
    const ctx = CHECK_CONTEXT[c.name] || {};
    const qualifier = confidenceQualifier(c.confidence);
    const parts = [];
    parts.push(`[${humanizeCheckName(c.name)}] score=${(c.score * 100).toFixed(0)}%, confidence=${(c.confidence * 100).toFixed(0)}%`);
    parts.push(`  Finding: ${c.summary}`);
    if (ctx.what) parts.push(`  Method: ${ctx.what}`);
    if (c.score >= 0.3) {
      if (ctx.tampered) parts.push(`  If tampered: ${ctx.tampered}`);
      if (ctx.benign) parts.push(`  Benign alternative: ${ctx.benign}`);
    } else {
      parts.push(`  This is a weak signal that ${qualifier} a minor anomaly. Likely benign on its own.`);
    }
    // Corroboration
    const sameCategory = checks.filter(o => o.category === c.category && o.name !== c.name && o.score >= 0.15);
    if (sameCategory.length) {
      parts.push(`  Corroborated by: ${sameCategory.map(o => humanizeCheckName(o.name)).join(', ')} (same category)`);
    } else if (c.score >= 0.3) {
      parts.push(`  Note: No corroborating signal from other ${c.category} checks.`);
    }
    lines.push(parts.join('\n'));
  }

  // Unavailable checks
  const unavailable = checks.filter(c => c.confidence <= 0.05 && c.score === 0 && c.summary);
  if (unavailable.length) {
    lines.push('Unavailable checks: ' + unavailable.map(c => `${humanizeCheckName(c.name)}: ${c.summary}`).join('; '));
  }

  return lines;
}

export function humanizeCheckName(name) {
  const map = {
    container_metadata: 'Container & Metadata',
    sample_timing: 'Sample Timing',
    frame_structure: 'Frame Structure (GOP)',
    visual_frame_analysis: 'Visual Frame Analysis',
    audio_consistency: 'Audio Consistency',
    metadata_codec_consistency: 'Metadata Consistency',
    packet_timing_anomalies: 'Packet Timing',
    frame_structure_anomalies: 'Frame Structure',
    frame_quality_shift: 'Visual Quality Shifts',
    browser_temporal_continuity: 'Frame Continuity',
    compression_consistency: 'Compression Consistency',
    scene_cut_forensics: 'Scene Cut Forensics',
    audio_spectral_continuity: 'Audio Spectral Analysis',
    temporal_noise_consistency: 'Temporal Noise Analysis',
    double_compression_detection: 'Double Compression Detection',
    ela_frame_analysis: 'Error Level Analysis (ELA)',
    bitstream_structure: 'Bitstream Structure',
    qp_consistency: 'QP / GOP Consistency',
    thumbnail_mismatch: 'Thumbnail Mismatch',
    av_sync_drift: 'A/V Sync Drift',
    bitrate_distribution: 'Bitrate Distribution',
  };
  return map[name] || name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export function humanizeCategory(cat) {
  const map = {
    duplicate_frames: 'Duplicate Frames',
    missing_frames: 'Missing Frames',
    quality_shift: 'Quality Shift',
    timing_anomaly: 'Timing Anomaly',
    gop_irregularity: 'GOP Irregularity',
    histogram_break: 'Histogram Break',
    timing_break: 'Timing Break',
    timestamp_spike: 'Timestamp Spike',
    resolution_switch: 'Resolution Switch',
    compression_shift: 'Compression Shift',
    misaligned_scene_cut: 'Misaligned Scene Cut',
    scene_cluster: 'Scene Cluster',
    audio_spectral_break: 'Audio Spectral Break',
    audio_silence_gap: 'Audio Silence Gap',
    noise_shift: 'Noise Floor Shift',
    ela_shift: 'ELA Residual Shift',
    bitstream_param_change: 'Bitstream Parameter Change',
    gop_pattern_anomaly: 'GOP Pattern Anomaly',
    av_sync_jump: 'A/V Sync Jump',
    bitrate_mode_shift: 'Bitrate Mode Shift',
  };
  return map[cat] || (cat || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export function verdictColor(label) {
  if (label === 'tampered') return '#ff5a6b';
  if (label === 'suspicious') return '#f6b73c';
  if (label === 'authentic') return '#3dd68c';
  return '#6f7d97';
}
