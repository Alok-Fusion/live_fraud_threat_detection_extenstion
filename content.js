/**
 * Live Call Firewall — Content Script
 * Injected into call platform tabs. Detects active call state,
 * captures audio stream, runs analyzers, and reports to background.
 */

// ═══════════════════════════════════════════════════════════════════════════
// Inline the analyzer classes (content scripts can't import modules easily)
// ═══════════════════════════════════════════════════════════════════════════

// ─── Platform Call Detectors (DOM Signals) ────────────────────────────────────
const CALL_DETECTORS = {
  "meet.google.com": {
    callActive: () => {
      // 100% reliable method: if we are on a specific meeting URL (not the homepage)
      // e.g. meet.google.com/abc-defg-hij
      const path = window.location.pathname;
      const isMeetingRoom = path.length > 10 && path.split('/').length === 2; // e.g., "/abc-defg-hij"
      
      const isNotEnded = !document.querySelector('[data-call-ended="true"]') && 
                         !document.querySelector('.OcAp0') &&
                         !document.body.innerText.includes('You left the meeting');
                         
      return isMeetingRoom && isNotEnded;
    },
    callEnded: () => !!document.querySelector('[data-call-ended="true"]') ||
                     !!document.querySelector('.OcAp0') ||
                     document.body.innerText.includes('You left the meeting')
  },
  "zoom.us": {
    callActive: () => !!document.querySelector('.meeting-client-inner') ||
      !!document.querySelector('.join-audio-by-voip__join-btn'),
    callEnded: () => !!document.querySelector('.meeting-left-container')
  },
  "teams.microsoft.com": {
    callActive: () => !!document.querySelector('.calling-screen') ||
      !!document.querySelector('[data-tid="call-controls-bar"]'),
    callEnded: () => !!document.querySelector('.end-call-screen')
  },
  "web.whatsapp.com": {
    callActive: () => !!document.querySelector('._2DU3i') ||
      !!document.querySelector('[data-id*="call"]'),
    callEnded: () => false
  }
};

// ─── State ────────────────────────────────────────────────────────────────────
let callActive = false;
let checkInterval = null;
let audioStream = null;
let audioContext = null;
let analyserNode = null;
let textAnalysisInterval = null;
let recognition = null;
let hitCounts = { urgency: 0, authority: 0, financial: 0, fear: 0, linkShare: 0 };
let voiceSignal = { score: 0, details: {} };

// ─── URL Monitoring State ─────────────────────────────────────────────────────
let urlObserver = null;
let urlScanQueue = [];
let urlScanTimer = null;
let seenUrls = new Set();
let urlClickHandler = null;
let urlToastEl = null;
let urlToastTimer = null;

// ─── Keyword Dictionaries (inline for content script) ─────────────────────────
const KEYWORDS = {
  urgency: ["immediately","right now","urgent","hurry","last chance","within 24 hours","act now","time is running out","final warning","do it now","emergency","quickly","expires today"],
  authority: ["rbi","reserve bank","income tax","police","cyber crime","court","government","bank officer","senior official","legal notice","enforcement directorate","cbi","warrant","officer speaking"],
  financial: ["otp","pin","password","account number","transfer money","send payment","upi id","bank details","credit card","debit card","cvv","wallet","cryptocurrency","gift card","pay now","refund","processing charge"],
  fear: ["arrest","prison","jail","illegal","suspend","block","freeze","legal action","fir","criminal charge","money laundering","fraud detected","account blocked","penalty","fine"],
  linkShare: ["click the link","open this link","download this app","install this","share your screen","anydesk","teamviewer","remote access","give me access","type this url","follow this link"]
};

const KEYWORD_WEIGHTS = { urgency: 25, authority: 30, financial: 35, fear: 20, linkShare: 20 };

// ─── Platform Detection ───────────────────────────────────────────────────────
function getCurrentPlatform() {
  const host = window.location.hostname;
  for (const key of Object.keys(CALL_DETECTORS)) {
    if (host.includes(key)) return key;
  }
  return null;
}

// ─── Call Monitoring ──────────────────────────────────────────────────────────
function startMonitoring() {
  const platform = getCurrentPlatform();
  if (!platform) return;

  console.log(`[LCF Content] Monitoring ${platform}`);

  checkInterval = setInterval(() => {
    const detector = CALL_DETECTORS[platform];
    const isCallNow = detector?.callActive() ?? false;

    if (isCallNow && !callActive) {
      callActive = true;
      onCallStarted();
    } else if (!isCallNow && callActive) {
      callActive = false;
      onCallEnded();
    }
  }, 2000);
}

// ─── Call Event Handlers ──────────────────────────────────────────────────────
async function onCallStarted() {
  console.log("[LCF Content] 🟢 Call detected — starting analysis");
  chrome.runtime.sendMessage({ type: 'CALL_STARTED', data: { url: window.location.href } });

  startUrlMonitoring();

  // Capture microphone audio
  try {
    audioStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    startAudioAnalysis(audioStream);
  } catch (err) {
    console.warn("[LCF Content] Cannot capture audio:", err.message);
  }

  // Start speech recognition
  startSpeechRecognition();
}

function onCallEnded() {
  console.log("[LCF Content] 🔴 Call ended");
  chrome.runtime.sendMessage({ type: 'CALL_ENDED' });
  stopAudioAnalysis();
  stopSpeechRecognition();
  stopUrlMonitoring();
  removeOverlay();
  hitCounts = { urgency: 0, authority: 0, financial: 0, fear: 0, linkShare: 0 };
}

// ─── URL Monitoring ──────────────────────────────────────────────────────────
const URL_TEXT_REGEX = /\bhttps?:\/\/[^\s<>"']+|\bwww\.[^\s<>"']+/gi;
const BARE_SHORTENER_REGEX = /\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rebrand\.ly|ow\.ly|rb\.gy|lnkd\.in|shorturl\.at)\/[^\s<>"']+/gi;

function stripEdgePunctuation(value) {
  let v = String(value || '').trim();
  v = v.replace(/^[<([{"'`]+/g, '');
  v = v.replace(/[>\])}",'`.?!;:]+$/g, '');
  return v.trim();
}

function shouldIgnoreUrl(rawUrl) {
  const u = String(rawUrl || '').trim();
  if (!u) return true;
  if (u.startsWith('chrome-extension:')) return true;

  // Ignore obvious self-links to the call platform to reduce noise.
  let candidate = u;
  if (/^www\./i.test(candidate)) candidate = `https://${candidate}`;
  try {
    const parsed = new URL(candidate);
    const host = String(parsed.hostname || '').toLowerCase();
    const self = String(location.hostname || '').toLowerCase();
    if (host && self && host === self) return true;

    if (host.endsWith('meet.google.com')) return true;
    if (host.endsWith('zoom.us')) return true;
    if (host === 'teams.microsoft.com') return true;
    if (host === 'web.whatsapp.com') return true;
    if (host.endsWith('webex.com')) return true;
  } catch (e) {
    // If we can't parse it, keep it. Background normalisation will decide.
  }
  return false;
}

function extractUrlsFromText(text) {
  const out = [];
  const t = String(text || '');
  const matches1 = t.match(URL_TEXT_REGEX) || [];
  const matches2 = t.match(BARE_SHORTENER_REGEX) || [];
  return out.concat(matches1, matches2);
}

function reportUrlFound(url, source) {
  const cleaned = stripEdgePunctuation(url);
  if (!cleaned) return;
  if (shouldIgnoreUrl(cleaned)) return;

  const key = cleaned.toLowerCase();
  if (seenUrls.has(key)) return;
  seenUrls.add(key);

  chrome.runtime.sendMessage({
    type: 'URL_DETECTED',
    data: {
      url: cleaned,
      source: source || 'dom',
      pageUrl: window.location.href,
      timestamp: new Date().toISOString()
    }
  });
}

function scanNodeForUrls(node) {
  try {
    if (!node) return;

    // Anchors
    if (node.nodeType === Node.ELEMENT_NODE) {
      const el = /** @type {Element} */ (node);
      if (el.matches?.('a[href]')) {
        const href = el.getAttribute('href') || el.href;
        if (href) reportUrlFound(href, 'link');
      }

      el.querySelectorAll?.('a[href]').forEach((a) => {
        const href = a.getAttribute('href') || a.href;
        if (href) reportUrlFound(href, 'link');
      });

      // Safe redirect hints (Google sometimes stores the real link here)
      const safe = el.getAttribute?.('data-saferedirecturl');
      if (safe) reportUrlFound(safe, 'link');

      // Text patterns (limit to avoid scanning huge DOM chunks)
      const txt = (el.textContent || '');
      if (txt && txt.length <= 2000) {
        extractUrlsFromText(txt).forEach((u) => reportUrlFound(u, 'text'));
      }
    } else if (node.nodeType === Node.TEXT_NODE) {
      const txt = String(node.textContent || '');
      if (txt && txt.length <= 2000) {
        extractUrlsFromText(txt).forEach((u) => reportUrlFound(u, 'text'));
      }
    }
  } catch (e) {}
}

function flushUrlScanQueue() {
  urlScanTimer = null;
  const batch = urlScanQueue.splice(0, urlScanQueue.length);
  batch.forEach(scanNodeForUrls);
}

function startUrlMonitoring() {
  try {
    if (urlObserver) return;
    seenUrls = new Set();

    // Initial scan (best-effort)
    scanNodeForUrls(document.body);

    urlObserver = new MutationObserver((mutations) => {
      for (const m of mutations) {
        (m.addedNodes || []).forEach((n) => urlScanQueue.push(n));
      }
      if (!urlScanTimer) urlScanTimer = setTimeout(flushUrlScanQueue, 250);
    });

    urlObserver.observe(document.body, { childList: true, subtree: true });

    urlClickHandler = (e) => {
      const target = e?.target;
      const a = target?.closest?.('a[href]');
      if (!a) return;
      const href = a.getAttribute('href') || a.href;
      if (href) reportUrlFound(href, 'click');
    };
    document.addEventListener('click', urlClickHandler, true);
  } catch (e) {}
}

function stopUrlMonitoring() {
  try {
    if (urlObserver) {
      urlObserver.disconnect();
      urlObserver = null;
    }
    if (urlClickHandler) {
      document.removeEventListener('click', urlClickHandler, true);
      urlClickHandler = null;
    }
    if (urlScanTimer) {
      clearTimeout(urlScanTimer);
      urlScanTimer = null;
    }
    urlScanQueue = [];
    seenUrls = new Set();
  } catch (e) {}
}

// ─── Audio Analysis ───────────────────────────────────────────────────────────
function startAudioAnalysis(stream) {
  audioContext = new (window.AudioContext || window.webkitAudioContext)();
  analyserNode = audioContext.createAnalyser();
  analyserNode.fftSize = 2048;
  analyserNode.smoothingTimeConstant = 0.8;

  const source = audioContext.createMediaStreamSource(stream);
  source.connect(analyserNode);

  let pitchHistory = [];
  let energyHistory = [];

  textAnalysisInterval = setInterval(() => {
    const freqData = new Float32Array(analyserNode.frequencyBinCount);
    const timeData = new Float32Array(analyserNode.frequencyBinCount);
    analyserNode.getFloatFrequencyData(freqData);
    analyserNode.getFloatTimeDomainData(timeData);

    // RMS Energy
    const energy = Math.sqrt(timeData.reduce((s, v) => s + v*v, 0) / timeData.length);

    // Zero-crossing waveform smoothness
    let zc = 0;
    for (let i = 1; i < timeData.length; i++) {
      if ((timeData[i] >= 0) !== (timeData[i-1] >= 0)) zc++;
    }
    const smoothness = 1 - Math.min(1, (zc / timeData.length) * 10);

    // Pitch variance proxy (frequency domain std dev in voice range)
    const binWidth = audioContext.sampleRate / analyserNode.fftSize;
    const voiceBins = Array.from(freqData.slice(
      Math.floor(80/binWidth), Math.floor(400/binWidth)
    )).map(v => Math.pow(10, v/20));
    const mean = voiceBins.reduce((a,b) => a+b, 0) / voiceBins.length;
    const pitchVariance = Math.sqrt(voiceBins.reduce((s,v) => s+Math.pow(v-mean,2),0)/voiceBins.length);

    pitchHistory.push(pitchVariance);
    energyHistory.push(energy);
    if (pitchHistory.length > 10) pitchHistory.shift();
    if (energyHistory.length > 10) energyHistory.shift();

    const avgPitch = pitchHistory.reduce((a,b)=>a+b,0)/pitchHistory.length;
    const prevEnergy = energyHistory.slice(0,-1).reduce((a,b)=>a+b,0)/Math.max(1,energyHistory.length-1);

    const lowPitchVariance = avgPitch < 0.015 && energy > 0.001;
    const waveformAnomaly = smoothness > 0.85;
    const energySpike = energy > prevEnergy * 2.5 && energy > 0.01;

    let vScore = 0;
    if (lowPitchVariance) vScore += 40;
    if (waveformAnomaly) vScore += 35;
    if (energySpike) vScore += 25;

    voiceSignal = {
      score: Math.min(100, vScore),
      details: { lowPitchVariance, waveformAnomaly, energySpike, energy: energy.toFixed(4) }
    };

    sendSignalUpdate();
  }, 3000);
}

function stopAudioAnalysis() {
  if (textAnalysisInterval) { clearInterval(textAnalysisInterval); textAnalysisInterval = null; }
  if (audioContext) { audioContext.close(); audioContext = null; }
  if (audioStream) { audioStream.getTracks().forEach(t => t.stop()); audioStream = null; }
}

// ─── Speech Recognition ───────────────────────────────────────────────────────
function startSpeechRecognition() {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SR) return;

  recognition = new SR();
  recognition.continuous = true;
  recognition.interimResults = false;
  recognition.lang = 'en-IN';

  recognition.onresult = (event) => {
    for (let i = event.resultIndex; i < event.results.length; i++) {
      if (event.results[i].isFinal) {
        processTranscript(event.results[i][0].transcript.toLowerCase());
      }
    }
  };

  recognition.onend = () => {
    if (callActive) setTimeout(() => { try { recognition.start(); } catch(e){} }, 1000);
  };

  try { recognition.start(); } catch(e) {}
}

function stopSpeechRecognition() {
  if (recognition) { recognition.stop(); recognition = null; }
}

function processTranscript(text) {
  let newHit = false;
  for (const [cat, keywords] of Object.entries(KEYWORDS)) {
    for (const kw of keywords) {
      if (text.includes(kw)) {
        hitCounts[cat]++;
        newHit = true;
      }
    }
  }
  if (newHit) sendSignalUpdate();
}

// ─── Signal Reporting ─────────────────────────────────────────────────────────
function computeBehaviourScore() {
  const weights = KEYWORD_WEIGHTS;
  let score = 0;
  for (const [cat, w] of Object.entries(weights)) {
    const hits = hitCounts[cat] || 0;
    score += Math.min(100, hits * w) * (w / 130);
  }
  return Math.round(Math.min(100, score));
}

function sendSignalUpdate() {
  const bScore = computeBehaviourScore();
  chrome.runtime.sendMessage({
    type: 'SIGNAL_UPDATE',
    data: {
      behaviourScore: bScore,
      behaviourDetails: {
        urgencyHits: hitCounts.urgency || 0,
        authorityHits: hitCounts.authority || 0,
        financialHits: hitCounts.financial || 0,
        fearHits: hitCounts.fear || 0,
        linkShareHits: hitCounts.linkShare || 0
      },
      voiceScore: voiceSignal.score,
      voiceDetails: voiceSignal.details
    }
  });
}

// ─── Threat Update Handler (from background) ──────────────────────────────────
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === 'THREAT_UPDATE') {
    updateOverlay(msg.threat);
    return;
  }

  if (msg.type === 'URL_ANALYSIS') {
    showUrlToast(msg.analysis);
    return;
  }

  if (msg.type === 'GET_CALL_STATUS') {
    const host = window.location.hostname;
    let platform = null;
    if (host.includes('meet.google.com')) platform = 'Google Meet';
    else if (host.includes('zoom.us')) platform = 'Zoom';
    else if (host.includes('teams.microsoft.com')) platform = 'Microsoft Teams';
    else if (host.includes('web.whatsapp.com')) platform = 'WhatsApp Web';
    else if (host.includes('webex.com')) platform = 'Cisco Webex';

    sendResponse({ callActive, platform, url: window.location.href });
  }
});

// ─── Overlay Injection ────────────────────────────────────────────────────────
let overlayEl = null;
let alertSoundPlayed = false;

function showUrlToast(analysis) {
  try {
    if (!analysis) return;
    const verdict = analysis.verdict || 'unknown';
    const score = analysis.score ?? 0;
    const hostname = analysis.hostname || '';
    const url = analysis.normalizedUrl || analysis.originalUrl || '';

    // Only toast when the background believes this needs attention.
    if (verdict !== 'malicious' && verdict !== 'suspicious') return;

    if (!urlToastEl) {
      urlToastEl = document.createElement('div');
      urlToastEl.id = 'lcf-url-toast';
      urlToastEl.addEventListener('click', () => {
        urlToastEl.style.display = 'none';
      });
      document.body.appendChild(urlToastEl);
    }

    urlToastEl.className = `lcf-url-toast lcf-url-toast--${verdict}`;
    urlToastEl.innerHTML = `
      <div class="lcf-url-toast__title">${verdict === 'malicious' ? 'High-Risk Link Detected' : 'Suspicious Link Detected'}</div>
      <div class="lcf-url-toast__meta">${hostname ? hostname : 'Link'} · score ${score}/100</div>
      <div class="lcf-url-toast__url">${escapeHtml(truncate(url, 90))}</div>
    `;

    urlToastEl.style.display = 'block';
    if (urlToastTimer) clearTimeout(urlToastTimer);
    urlToastTimer = setTimeout(() => {
      if (urlToastEl) urlToastEl.style.display = 'none';
    }, 8000);
  } catch (e) {}
}

function truncate(value, maxLen) {
  const s = String(value ?? '');
  if (s.length <= maxLen) return s;
  return s.slice(0, Math.max(0, maxLen - 3)) + '...';
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => {
    return ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[ch] || ch;
  });
}

function updateOverlay(threat) {
  if (!threat || threat.score < 30) {
    if (overlayEl) { overlayEl.style.display = 'none'; }
    return;
  }

  if (!overlayEl) {
    createOverlay();
  }

  overlayEl.style.display = 'flex';
  const scoreEl = overlayEl.querySelector('#lcf-score');
  const labelEl = overlayEl.querySelector('#lcf-label');
  const explainEl = overlayEl.querySelector('#lcf-explain');
  const confEl = overlayEl.querySelector('#lcf-confidence');
  const guidanceEl = overlayEl.querySelector('#lcf-guidance');

  if (scoreEl) scoreEl.textContent = `${threat.score}%`;
  if (labelEl) {
    labelEl.textContent = `${threat.emoji} ${threat.label}`;
    labelEl.style.color = threat.color;
  }
  if (confEl) confEl.textContent = `Confidence: ${threat.confidence}%`;
  if (explainEl) explainEl.textContent = threat.explanation;

  // Update overlay border color by threat level
  const borderColor = threat.color;
  overlayEl.style.borderLeftColor = borderColor;
  overlayEl.style.boxShadow = `0 0 20px ${borderColor}44`;

  // Guidance based on threat
  const tips = [];
  if (threat.score >= 30) {
    tips.push("🚫 Do NOT share OTP, PIN, or passwords");
    tips.push("📞 Verify by calling back on the official number");
  }
  if (threat.score >= 60) {
    tips.push("🔗 Do NOT click any links sent during this call");
    tips.push("📱 Avoid screen-sharing with the caller");
  }
  if (threat.score >= 80) {
    tips.push("⛔ STRONGLY RECOMMEND ending this call immediately");
    tips.push("🚔 Report to cybercrime.gov.in");
    if (!alertSoundPlayed) {
      playAlertSound();
      alertSoundPlayed = true;
    }
  }
  if (guidanceEl) {
    guidanceEl.innerHTML = tips.map(t => `<div class="lcf-tip">${t}</div>`).join('');
  }

  // Pulse animation for critical
  if (threat.score >= 80) {
    overlayEl.classList.add('lcf-critical');
  } else {
    overlayEl.classList.remove('lcf-critical');
    alertSoundPlayed = false;
  }
}

function createOverlay() {
  overlayEl = document.createElement('div');
  overlayEl.id = 'lcf-overlay';
  const dashboardUrl = chrome.runtime.getURL('dashboard/index.html');
  overlayEl.innerHTML = `
    <div class="lcf-header">
      <span class="lcf-brand">🛡 Live Call Firewall</span>
      <button class="lcf-dismiss" id="lcf-dismiss-btn">✕</button>
    </div>
    <div class="lcf-score-row">
      <div class="lcf-score-circle">
        <span id="lcf-score">—</span>
      </div>
      <div class="lcf-score-info">
        <div id="lcf-label" class="lcf-label">Analysing...</div>
        <div id="lcf-confidence" class="lcf-confidence">Confidence: —</div>
      </div>
    </div>
    <div id="lcf-explain" class="lcf-explain">Monitoring your call for threats...</div>
    <div id="lcf-guidance" class="lcf-guidance"></div>
    <div class="lcf-footer">
      <a href="${dashboardUrl}" target="_blank" class="lcf-dashboard-btn">View Dashboard →</a>
    </div>
  `;

  document.body.appendChild(overlayEl);

  // Dismiss button
  document.getElementById('lcf-dismiss-btn')?.addEventListener('click', () => {
    overlayEl.style.display = 'none';
  });
}

function removeOverlay() {
  if (overlayEl) {
    overlayEl.remove();
    overlayEl = null;
    alertSoundPlayed = false;
  }
}

function playAlertSound() {
  try {
    const ctx = new AudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.frequency.setValueAtTime(880, ctx.currentTime);
    osc.frequency.setValueAtTime(440, ctx.currentTime + 0.15);
    gain.gain.setValueAtTime(0.3, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.5);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.5);
  } catch(e) {}
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
function init() {
  console.log("[LCF Content] 🛡 Live Call Firewall content script active. Waiting for call...");
  startMonitoring();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

// Fallback manual trigger (can be invoked via DevTools: window.postMessage({type: 'FORCE_LCF_START'}, '*'))
window.addEventListener('message', (event) => {
  if (event.data.type === 'FORCE_LCF_START') {
    console.log("[LCF] Manual Force Start triggered");
    callActive = true;
    onCallStarted();
  }
});
