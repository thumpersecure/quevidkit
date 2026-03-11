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

export function fuseScores(checks, sensitivity = 0.7) {
  if (!checks.length) return { probability: 0.5, confidence: 0, label: 'inconclusive' };

  const weighted = checks.map(c => [clamp01(c.score), Math.max(0.05, c.confidence)]);
  const base = weightedMean(weighted);
  const gate = qualityGate(checks);

  const bias = -2.6 + sensitivity * 1.6;
  const logit = bias + base * 5.2 + gate * 0.4;
  const probability = 1 / (1 + Math.exp(-logit));

  const coverage = Math.min(1, checks.length / 6);
  const agreement = 1 - Math.abs(base - 0.5) * 0.5;
  const confidence = clamp01(coverage * 0.7 + gate * 0.2 + agreement * 0.1);

  let label;
  if (gate < 0.3 || confidence < 0.35) {
    label = 'inconclusive';
  } else if (probability >= 0.6) {
    label = 'tampered';
  } else if (probability >= 0.35) {
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

export function buildExplanation(checks, label) {
  const lines = [];

  if (label === 'authentic') {
    lines.push('No strong tampering indicators were found across all enabled checks.');
  } else if (label === 'inconclusive') {
    lines.push('Evidence quality was not high enough for a definitive decision.');
  } else {
    lines.push('Multiple forensic signals suggest possible alteration.');
  }

  const strongest = [...checks].sort((a, b) => b.score * b.confidence - a.score * a.confidence);
  for (const c of strongest.slice(0, 5)) {
    if (c.score < 0.1) continue;
    lines.push(`${humanizeCheckName(c.name)}: ${c.summary} (score=${(c.score * 100).toFixed(1)}%, confidence=${(c.confidence * 100).toFixed(1)}%)`);
  }

  for (const c of checks) {
    if (c.score === 0 && c.confidence <= 0.05 && c.summary) {
      lines.push(`Note: ${c.summary}`);
    }
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
  };
  return map[cat] || (cat || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export function verdictColor(label) {
  if (label === 'tampered') return '#ff5a6b';
  if (label === 'suspicious') return '#f6b73c';
  if (label === 'authentic') return '#3dd68c';
  return '#6f7d97';
}
