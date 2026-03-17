/**
 * Live Call Firewall — Audio Analyzer
 * Analyzes microphone/call audio stream for voice authenticity signals
 * using the Web Audio API.
 */

class AudioAnalyzer {
  constructor() {
    this.audioContext = null;
    this.analyserNode = null;
    this.source = null;
    this.stream = null;
    this.isAnalyzing = false;
    this.intervalId = null;
    this.onUpdate = null; // Callback(voiceScore, voiceDetails)

    // Rolling history for trend analysis
    this.pitchHistory = [];
    this.energyHistory = [];
    this.centroidHistory = [];
    this.WINDOW_SIZE = 10; // Keep last 10 readings (~30 seconds)
  }

  async start(stream) {
    try {
      this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
      this.analyserNode = this.audioContext.createAnalyser();
      this.analyserNode.fftSize = 2048;
      this.analyserNode.smoothingTimeConstant = 0.8;

      this.source = this.audioContext.createMediaStreamSource(stream);
      this.source.connect(this.analyserNode);

      this.isAnalyzing = true;
      this.intervalId = setInterval(() => this._analyze(), 3000);
      console.log("[LCF] 🔊 Audio analyzer started");
    } catch (err) {
      console.error("[LCF] Audio analyzer start failed:", err);
    }
  }

  _analyze() {
    if (!this.isAnalyzing || !this.analyserNode) return;

    const bufferLength = this.analyserNode.frequencyBinCount;
    const freqData = new Float32Array(bufferLength);
    const timeData = new Float32Array(bufferLength);

    this.analyserNode.getFloatFrequencyData(freqData);
    this.analyserNode.getFloatTimeDomainData(timeData);

    // ── 1. Pitch Variance (low variance = synthetic/robotic) ──────────────
    const pitchVariance = this._computePitchVariance(freqData);
    this.pitchHistory.push(pitchVariance);
    if (this.pitchHistory.length > this.WINDOW_SIZE) this.pitchHistory.shift();

    // ── 2. Waveform Smoothness (too smooth = synthetic) ───────────────────
    const waveformSmoothness = this._computeWaveformSmoothness(timeData);

    // ── 3. Energy / RMS (energy spikes = aggression/script) ──────────────
    const energy = this._computeRMS(timeData);
    this.energyHistory.push(energy);
    if (this.energyHistory.length > this.WINDOW_SIZE) this.energyHistory.shift();

    // ── 4. Spectral Centroid (voice vs synthetic distinction) ─────────────
    const centroid = this._computeSpectralCentroid(freqData);
    this.centroidHistory.push(centroid);
    if (this.centroidHistory.length > this.WINDOW_SIZE) this.centroidHistory.shift();

    // ── 5. Derive Anomaly Signals ─────────────────────────────────────────
    const avgPitchVariance = this._mean(this.pitchHistory);
    const energySpike = this.energyHistory.length > 3 &&
      energy > this._mean(this.energyHistory.slice(0, -1)) * 2.5;

    // Suspicious if pitch variance is very low (robotic) and has energy
    const lowPitchVariance = avgPitchVariance < 0.015 && energy > 0.001;
    const waveformAnomaly = waveformSmoothness > 0.85; // Too smooth

    // ── 6. Compute Voice Score ────────────────────────────────────────────
    let voiceScore = 0;
    if (lowPitchVariance) voiceScore += 40;
    if (waveformAnomaly) voiceScore += 35;
    if (energySpike) voiceScore += 25;

    const voiceDetails = {
      lowPitchVariance,
      waveformAnomaly,
      energySpike,
      pitchVariance: avgPitchVariance.toFixed(4),
      waveformSmoothness: waveformSmoothness.toFixed(3),
      energy: energy.toFixed(4),
      spectralCentroid: centroid.toFixed(1)
    };

    if (this.onUpdate) {
      this.onUpdate(Math.min(100, voiceScore), voiceDetails);
    }
  }

  // Pitch variance via autocorrelation proxy (frequency domain variance)
  _computePitchVariance(freqData) {
    const startBin = Math.floor(80 / (this.audioContext.sampleRate / this.analyserNode.fftSize));
    const endBin = Math.floor(400 / (this.audioContext.sampleRate / this.analyserNode.fftSize));
    const slice = Array.from(freqData.slice(startBin, endBin)).map(v => Math.pow(10, v / 20));
    return this._stdDev(slice);
  }

  // Waveform smoothness: ratio of zero-crossings (low = too smooth = synthetic)
  _computeWaveformSmoothness(timeData) {
    let zeroCrossings = 0;
    for (let i = 1; i < timeData.length; i++) {
      if ((timeData[i] >= 0) !== (timeData[i - 1] >= 0)) zeroCrossings++;
    }
    const normalizedZC = zeroCrossings / timeData.length;
    // Invert: high smoothness means low zero crossings
    return 1 - Math.min(1, normalizedZC * 10);
  }

  // RMS energy
  _computeRMS(timeData) {
    const sum = timeData.reduce((acc, val) => acc + val * val, 0);
    return Math.sqrt(sum / timeData.length);
  }

  // Spectral centroid (Hz) — distinguishes voice characteristics
  _computeSpectralCentroid(freqData) {
    const binWidth = this.audioContext.sampleRate / this.analyserNode.fftSize;
    let weightedSum = 0;
    let totalPower = 0;

    for (let i = 0; i < freqData.length; i++) {
      const power = Math.pow(10, freqData[i] / 20);
      weightedSum += i * binWidth * power;
      totalPower += power;
    }

    return totalPower > 0 ? weightedSum / totalPower : 0;
  }

  _mean(arr) {
    if (!arr.length) return 0;
    return arr.reduce((a, b) => a + b, 0) / arr.length;
  }

  _stdDev(arr) {
    if (arr.length < 2) return 0;
    const avg = this._mean(arr);
    const variance = arr.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / arr.length;
    return Math.sqrt(variance);
  }

  stop() {
    this.isAnalyzing = false;
    if (this.intervalId) clearInterval(this.intervalId);
    if (this.source) this.source.disconnect();
    if (this.audioContext && this.audioContext.state !== 'closed') {
      this.audioContext.close();
    }
    this.pitchHistory = [];
    this.energyHistory = [];
    this.centroidHistory = [];
    console.log("[LCF] Audio analyzer stopped");
  }
}
