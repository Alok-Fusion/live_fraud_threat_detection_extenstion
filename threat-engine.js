/**
 * Live Call Firewall — Threat Engine
 * Aggregates multi-signal inputs into a weighted threat score
 * with explainable AI summaries.
 */

// ─── Signal Weights ─────────────────────────────────────────────────────────
const WEIGHTS = {
  behaviour: 0.45,   // Text/keyword analysis (highest weight)
  voice: 0.30,       // Audio anomaly signals
  url: 0.25,         // URL / link risk analysis (heuristic)
  context: 0.00,     // Caller context (future)
  visual: 0.00       // Visual deepfake signals (future)
};

// ─── Threat Level Labels ─────────────────────────────────────────────────────
function getThreatLabel(score) {
  if (score < 30) return { label: "Low Risk", color: "#22c55e", emoji: "🟢" };
  if (score < 60) return { label: "Suspicious", color: "#f59e0b", emoji: "🟡" };
  if (score < 80) return { label: "Likely Scam", color: "#f97316", emoji: "🟠" };
  return { label: "Critical Threat", color: "#ef4444", emoji: "🔴" };
}

// ─── Explainable AI Summary Generator ───────────────────────────────────────
function generateExplanation(signals) {
  const reasons = [];

  if (signals.behaviourDetails) {
    const bd = signals.behaviourDetails;
    if (bd.urgencyHits > 0) reasons.push(`high-pressure urgency language detected (${bd.urgencyHits} trigger${bd.urgencyHits > 1 ? 's' : ''})`);
    if (bd.authorityHits > 0) reasons.push(`authority impersonation patterns (${bd.authorityHits} instance${bd.authorityHits > 1 ? 's' : ''})`);
    if (bd.financialHits > 0) reasons.push(`financial action requests (OTP/transfer/payment keywords)`);
    if (bd.fearHits > 0) reasons.push(`fear and threat framing rhetoric`);
    if (bd.linkShareHits > 0) reasons.push(`suspicious link or screen-share request`);
  }

  if (signals.voiceDetails) {
    const vd = signals.voiceDetails;
    if (vd.lowPitchVariance) reasons.push("unnatural pitch stability suggesting synthetic voice");
    if (vd.waveformAnomaly) reasons.push("waveform smoothness anomaly (possible AI-generated audio)");
    if (vd.energySpike) reasons.push("sudden energy spikes consistent with scripted aggression");
  }

  if (signals.urlDetails && Array.isArray(signals.urlDetails.links) && signals.urlDetails.links.length > 0) {
    const links = signals.urlDetails.links.filter(Boolean);
    const worst = links.reduce((best, l) => {
      if (!best) return l;
      return (l.score || 0) > (best.score || 0) ? l : best;
    }, null);

    if (worst) {
      const host = worst.hostname || null;
      if (worst.verdict === 'malicious') reasons.push(`high-risk link shared during the call${host ? ` (${host})` : ''}`);
      else if (worst.verdict === 'suspicious') reasons.push(`suspicious link shared during the call${host ? ` (${host})` : ''}`);
      else if ((worst.score || 0) >= 25) reasons.push(`link with risk indicators shared${host ? ` (${host})` : ''}`);
    }
  }

  if (signals.contextDetails) {
    const cd = signals.contextDetails;
    if (cd.unknownCaller) reasons.push("call from unknown or unverified source");
    if (cd.maskedNumber) reasons.push("masked or spoofed caller ID");
    if (cd.repeatedAttempts) reasons.push("multiple repeated call attempts detected");
  }

  if (signals.visualDetails) {
    const vi = signals.visualDetails;
    if (vi.lipSyncMismatch) reasons.push("lip-sync mismatch detected (possible deepfake video)");
    if (vi.blinkIrregularity) reasons.push("blink irregularity consistent with synthetic face");
    if (vi.faceBoundaryFlicker) reasons.push("face boundary flickering (AI face-swap artifact)");
  }

  if (reasons.length === 0) {
    return "No significant threat indicators detected at this time.";
  }

  return `This call is flagged because the caller exhibited: ${reasons.join("; ")}.`;
}

// ─── Confidence Calculator ───────────────────────────────────────────────────
function calculateConfidence(signals) {
  let signalCount = 0;
  let activeSignals = 0;

  // Count how many signal categories have data vs are non-zero
  if (signals.behaviourScore !== undefined) { signalCount++; if (signals.behaviourScore > 0) activeSignals++; }
  if (signals.voiceScore !== undefined)     { signalCount++; if (signals.voiceScore > 0) activeSignals++; }
  if (signals.urlScore !== undefined)       { signalCount++; if (signals.urlScore > 0) activeSignals++; }
  if (signals.contextScore !== undefined)   { signalCount++; if (signals.contextScore > 0) activeSignals++; }
  if (signals.visualScore !== undefined)    { signalCount++; if (signals.visualScore > 0) activeSignals++; }

  const dataCompleteness = signalCount >= 3 ? 1.0 : signalCount / 3;
  const signalStrength = signalCount > 0 ? activeSignals / signalCount : 0;

  return Math.round((dataCompleteness * 0.5 + signalStrength * 0.5) * 100);
}

// ─── Main Threat Score Compute ───────────────────────────────────────────────
function computeThreatScore(signals) {
  const behaviourScore = Math.min(100, signals.behaviourScore || 0);
  const voiceScore     = Math.min(100, signals.voiceScore     || 0);
  const urlScore       = Math.min(100, signals.urlScore       || 0);
  const contextScore   = Math.min(100, signals.contextScore   || 0);
  const visualScore    = Math.min(100, signals.visualScore    || 0);

  const rawScore =
    behaviourScore * WEIGHTS.behaviour +
    voiceScore     * WEIGHTS.voice     +
    urlScore       * WEIGHTS.url       +
    contextScore   * WEIGHTS.context   +
    visualScore    * WEIGHTS.visual;

  const score = Math.round(Math.min(100, rawScore));
  const { label, color, emoji } = getThreatLabel(score);
  const explanation = generateExplanation(signals);
  const confidence = calculateConfidence(signals);

  return {
    score,
    label,
    color,
    emoji,
    explanation,
    confidence,
    timestamp: new Date().toISOString(),
    breakdown: {
      behaviour: Math.round(behaviourScore * WEIGHTS.behaviour),
      voice: Math.round(voiceScore * WEIGHTS.voice),
      url: Math.round(urlScore * WEIGHTS.url),
      context: Math.round(contextScore * WEIGHTS.context),
      visual: Math.round(visualScore * WEIGHTS.visual)
    }
  };
}

// ─── Exports ─────────────────────────────────────────────────────────────────
if (typeof module !== 'undefined') {
  module.exports = { computeThreatScore, getThreatLabel, generateExplanation };
}

export { computeThreatScore, getThreatLabel, generateExplanation };
