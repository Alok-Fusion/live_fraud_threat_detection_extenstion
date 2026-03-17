/**
 * Live Call Firewall — Background Service Worker
 * Manages tab monitoring, call detection, and coordination between
 * content scripts, audio analysis, and threat engine.
 */

import { computeThreatScore } from './threat-engine.js';
import { analyzeUrl } from './url-analyzer.js';

// ─── Call Platform Detection ──────────────────────────────────────────────────
const CALL_PLATFORMS = [
  { pattern: /meet\.google\.com/, name: "Google Meet" },
  { pattern: /zoom\.us\/wc\//, name: "Zoom" },
  { pattern: /teams\.microsoft\.com/, name: "Microsoft Teams" },
  { pattern: /web\.whatsapp\.com/, name: "WhatsApp Web" },
  { pattern: /webex\.com/, name: "Cisco Webex" }
];

// ─── State ────────────────────────────────────────────────────────────────────
let activeCallTabs = {};  // tabId → { platform, startTime, captureStream }
let currentSignals = {
  behaviourScore: 0, voiceScore: 0, urlScore: 0, contextScore: 0, visualScore: 0,
  behaviourDetails: {}, voiceDetails: {}, urlDetails: { links: [] }, contextDetails: {}
};
let currentThreat = null;
let scoringInterval = null;

const DASHBOARD_BASE_URL = 'http://localhost:3000';
const LOCAL_LOG_KEY = 'lcf_logs';
const MAX_LOCAL_LOGS = 2000;

let lastThreatLogAt = 0;
let lastThreatLogSignature = '';

const MAX_TRACKED_LINKS = 20;
const MAX_ANALYZE_URLS = 20;
const URL_TEXT_REGEX = /\bhttps?:\/\/[^\s<>"']+|\bwww\.[^\s<>"']+/gi;
const BARE_SHORTENER_REGEX = /\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rebrand\.ly|ow\.ly|rb\.gy|lnkd\.in|shorturl\.at)\/[^\s<>"']+/gi;

function extractCandidateUrls(text) {
  const t = String(text || '');
  const matches1 = t.match(URL_TEXT_REGEX) || [];
  const matches2 = t.match(BARE_SHORTENER_REGEX) || [];
  let candidates = [...matches1, ...matches2];

  const trimmed = t.trim();
  if (candidates.length === 0 && trimmed) {
    // Try treating the entire input as a single URL if it's "url-like".
    if (!/\s/.test(trimmed) && trimmed.includes('.')) candidates = [trimmed];
  }

  const seen = new Set();
  const out = [];
  for (const c of candidates) {
    const u = String(c || '').trim();
    if (!u) continue;
    const key = u.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(u);
    if (out.length >= MAX_ANALYZE_URLS) break;
  }
  return out;
}

// ─── Tab Event Listeners ──────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url) return;

  const platform = detectPlatform(tab.url);
  if (platform && !activeCallTabs[tabId]) {
    console.log(`[LCF] 📞 Potential call tab detected: ${platform} (Tab ${tabId})`);
    activeCallTabs[tabId] = {
      platform,
      url: tab.url,
      startTime: Date.now(),
      callActive: false
    };
    updateBadge("WATCH", "#6366f1");
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  if (activeCallTabs[tabId]) {
    console.log(`[LCF] Tab ${tabId} closed — ending call monitoring`);
    endCallSession(tabId);
  }
});

// ─── Message Handler (from content.js) ────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  switch (msg.type) {
    case 'CALL_STARTED':
      handleCallStarted(tabId, msg.data, sender.tab);
      sendResponse({ ok: true });
      break;

    case 'CALL_ENDED':
      endCallSession(tabId);
      sendResponse({ ok: true });
      break;

    case 'SIGNAL_UPDATE':
      updateSignals(msg.data);
      sendResponse({ ok: true });
      break;

    case 'URL_DETECTED':
      handleUrlDetected(tabId, msg.data);
      sendResponse({ ok: true });
      break;

    case 'ANALYZE_URL': {
      try {
        const text = msg.data?.text ?? msg.data?.url ?? '';
        const urls = extractCandidateUrls(text);
        const analyses = urls.map((u) => analyzeUrl(u));
        const worst = analyses.reduce((best, a) => {
          if (!best) return a;
          return (a?.score || 0) > (best?.score || 0) ? a : best;
        }, null);
        sendResponse({
          ok: true,
          analyses,
          worst,
          maxScore: worst?.score || 0
        });
      } catch (e) {
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
      break;
    }

    case 'GET_THREAT':
      sendResponse({ threat: currentThreat, signals: currentSignals, platform: getActivePlatform() });
      break;

    case 'GET_CALL_STATUS':
      const tabInfo = activeCallTabs[tabId] || null;
      sendResponse({ callActive: tabInfo?.callActive || false, platform: tabInfo?.platform || null });
      break;

    case 'USER_REPORT':
      sendLogToDashboard({
        event: 'user_report',
        ...msg.data,
        timestamp: msg.data?.timestamp || new Date().toISOString()
      });
      sendResponse({ ok: true });
      break;

    case 'CONTEXT_UPDATE':
      currentSignals.contextScore = msg.data.score || 0;
      currentSignals.contextDetails = msg.data.details || {};
      recomputeThreatAndNotify();
      sendResponse({ ok: true });
      break;

    default:
      // Important: don't return true without responding, or callers can hang forever.
      sendResponse({ ok: false, error: `Unhandled message type: ${String(msg?.type || 'unknown')}` });
      break;
  }

  return true; // Keep channel open for async responses
});

// ─── Call Session Management ──────────────────────────────────────────────────
function handleCallStarted(tabId, data) {
  if (!tabId) return;

  const url = data?.url || null;
  if (!activeCallTabs[tabId]) {
    activeCallTabs[tabId] = {
      platform: (url ? detectPlatform(url) : null) || "Unknown",
      url,
      startTime: Date.now(),
      callActive: true,
      peakScore: 0,
      peakLabel: "Low Risk"
    };
  } else {
    if (url) activeCallTabs[tabId].url = url;
    if (!activeCallTabs[tabId].platform && url) {
      activeCallTabs[tabId].platform = detectPlatform(url) || activeCallTabs[tabId].platform;
    }
    activeCallTabs[tabId].callActive = true;
    activeCallTabs[tabId].startTime = Date.now();
    activeCallTabs[tabId].peakScore = 0;
    activeCallTabs[tabId].peakLabel = "Low Risk";
  }
  resetSignals();

  updateBadge("LIVE", "#ef4444");
  currentThreat = computeThreatScore(currentSignals);

  // Track peak per active session (signals are global, so we apply the same threat to each active tab).
  Object.values(activeCallTabs).forEach((session) => {
    if (!session?.callActive) return;
    const prevPeak = session.peakScore || 0;
    if (currentThreat.score > prevPeak) {
      session.peakScore = currentThreat.score;
      session.peakLabel = currentThreat.label;
    }
  });

  // Log call start to dashboard
  sendLogToDashboard({
    event: 'call_started',
    platform: activeCallTabs[tabId]?.platform,
    url: activeCallTabs[tabId]?.url || null,
    timestamp: new Date().toISOString()
  });

  console.log(`[LCF] 🟢 Call started on ${activeCallTabs[tabId]?.platform}`);
}

function endCallSession(tabId) {
  if (!activeCallTabs[tabId]) return;

  stopScoringLoop();

  const session = activeCallTabs[tabId];
  const duration = Math.round((Date.now() - (session.startTime || Date.now())) / 1000);
  const links = Array.isArray(currentSignals.urlDetails?.links) ? currentSignals.urlDetails.links : [];
  const peakScore = Math.max(session.peakScore || 0, currentThreat?.score || 0);

  // Final log entry (always)
  sendLogToDashboard({
    event: 'call_ended',
    platform: session.platform,
    url: session.url || null,
    duration_seconds: duration,
    peak_score: peakScore,
    peak_label: peakScore === (session.peakScore || 0)
      ? (session.peakLabel ?? currentThreat?.label ?? "Low Risk")
      : (currentThreat?.label ?? session.peakLabel ?? "Low Risk"),
    reasons: extractReasons(),
    links_shared: links.length,
    links: links.slice(-5).map((l) => ({
      url: l?.normalizedUrl || l?.originalUrl || null,
      hostname: l?.hostname || null,
      score: l?.score ?? null,
      verdict: l?.verdict || null
    })),
    timestamp: new Date().toISOString()
  });

  delete activeCallTabs[tabId];
  resetSignals();
  updateBadge("", "");

  // Notify popup that call ended
  try { chrome.runtime.sendMessage({ type: 'CALL_ENDED_NOTIFY' }, () => {}); } catch (e) {}
  console.log(`[LCF] 🔴 Call ended (Duration: ${duration}s)`);
}

// ─── Signal Integration ───────────────────────────────────────────────────────
function updateSignals(data) {
  if (data.behaviourScore !== undefined) {
    currentSignals.behaviourScore = data.behaviourScore;
    currentSignals.behaviourDetails = data.behaviourDetails || {};
  }
  if (data.voiceScore !== undefined) {
    currentSignals.voiceScore = data.voiceScore;
    currentSignals.voiceDetails = data.voiceDetails || {};
  }
  recomputeThreatAndNotify();
}

function handleUrlDetected(tabId, data) {
  try {
    const url = String(data?.url || '').trim();
    if (!url) return;

    const analysis = analyzeUrl(url);
    const normalizedKey = String(analysis.normalizedUrl || analysis.originalUrl || '').toLowerCase();

    if (!currentSignals.urlDetails || !Array.isArray(currentSignals.urlDetails.links)) {
      currentSignals.urlDetails = { links: [] };
    }

    // Deduplicate by normalized URL (fallback to original).
    const alreadySeen = currentSignals.urlDetails.links.some((l) => {
      const key = String(l?.normalizedUrl || l?.originalUrl || '').toLowerCase();
      return key && key === normalizedKey;
    });
    if (alreadySeen) return;

    const detectedAt = new Date().toISOString();
    const linkEntry = {
      ...analysis,
      source: data?.source || 'unknown',
      pageUrl: data?.pageUrl || null,
      detectedAt
    };

    currentSignals.urlDetails.links.push(linkEntry);
    if (currentSignals.urlDetails.links.length > MAX_TRACKED_LINKS) {
      currentSignals.urlDetails.links.splice(0, currentSignals.urlDetails.links.length - MAX_TRACKED_LINKS);
    }

    currentSignals.urlScore = Math.max(currentSignals.urlScore || 0, analysis.score || 0);

    const category =
      analysis.verdict === 'malicious' ? 'Malicious URL Detected' :
      analysis.verdict === 'suspicious' ? 'Suspicious URL Detected' :
      null;

    sendLogToDashboard({
      event: 'url_detected',
      platform: getActivePlatform(),
      url: analysis.normalizedUrl || analysis.originalUrl,
      hostname: analysis.hostname,
      tld: analysis.tld,
      score: analysis.score,
      label: analysis.verdict,
      verdict: analysis.verdict,
      reasons: category ? [category] : [],
      url_reasons: analysis.reasons,
      url_signals: analysis.signals,
      source: data?.source || null,
      pageUrl: data?.pageUrl || null,
      timestamp: detectedAt
    });

    // Proactive notification for suspicious/malicious links.
    if (analysis.verdict === 'malicious' || analysis.verdict === 'suspicious') {
      try {
        const title = analysis.verdict === 'malicious' ? 'High-Risk Link Detected' : 'Suspicious Link Detected';
        const message = `${analysis.hostname || (analysis.normalizedUrl || analysis.originalUrl)} (score ${analysis.score}/100)`;
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title,
          message
        });
      } catch (e) {}

      if (tabId) {
        try {
          chrome.tabs.sendMessage(tabId, { type: 'URL_ANALYSIS', analysis: linkEntry }, () => {});
        } catch (e) {}
      }
    }

    recomputeThreatAndNotify();
  } catch (e) {
    console.warn('[LCF] URL analysis failed:', e?.message || e);
  }
}

function resetSignals() {
  currentSignals = {
    behaviourScore: 0, voiceScore: 0, urlScore: 0, contextScore: 0, visualScore: 0,
    behaviourDetails: {}, voiceDetails: {}, urlDetails: { links: [] }, contextDetails: {}
  };
  currentThreat = null;
}

function recomputeThreatAndNotify() {
  // Only compute/broadcast while at least one call tab is active.
  if (!Object.values(activeCallTabs).some(t => t?.callActive)) return;

  currentThreat = computeThreatScore(currentSignals);

  // Track peak per active session (signals are global, so we apply the same threat to each active tab).
  Object.values(activeCallTabs).forEach((session) => {
    if (!session?.callActive) return;
    const prevPeak = session.peakScore || 0;
    if (currentThreat.score > prevPeak) {
      session.peakScore = currentThreat.score;
      session.peakLabel = currentThreat.label;
    }
  });

  // Push threat update to active tabs
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      if (activeCallTabs[tab.id]?.callActive) {
        chrome.tabs.sendMessage(tab.id, {
          type: 'THREAT_UPDATE',
          threat: currentThreat
        }, () => {
          // Ignore errors for tabs without a receiving content script.
        });
      }
    });
  });

  // Update extension badge
  const score = currentThreat.score;
  if (score >= 80) updateBadge("ALRT", "#ef4444");
  else if (score >= 60) updateBadge("HIGH", "#f97316");
  else if (score >= 30) updateBadge("WARN", "#f59e0b");
  else updateBadge("SAFE", "#22c55e");

  // Log important threat updates (throttled)
  const reasons = extractReasons();
  const signature = `${currentThreat.score}|${currentThreat.label}|${reasons.join(',')}`;
  const now = Date.now();
  const shouldLog = (now - lastThreatLogAt) > 5000 || signature !== lastThreatLogSignature;
  if (shouldLog && (currentThreat.score > 20 || reasons.length > 0)) {
    lastThreatLogAt = now;
    lastThreatLogSignature = signature;
    sendLogToDashboard({
      event: 'threat_update',
      platform: getActivePlatform(),
      score: currentThreat.score,
      label: currentThreat.label,
      confidence: currentThreat.confidence,
      explanation: currentThreat.explanation,
      reasons,
      breakdown: currentThreat.breakdown,
      links: (currentSignals.urlDetails?.links || []).slice(-5).map((l) => ({
        url: l?.normalizedUrl || l?.originalUrl || null,
        hostname: l?.hostname || null,
        score: l?.score ?? null,
        verdict: l?.verdict || null
      })),
      timestamp: currentThreat.timestamp
    });
  }
}

// ─── Scoring Loop ─────────────────────────────────────────────────────────────
function startScoringLoop(tabId) {
  stopScoringLoop();

  scoringInterval = setInterval(() => {
    currentThreat = computeThreatScore(currentSignals);

    // Push threat update to active tabs
    chrome.tabs.query({}, (tabs) => {
      tabs.forEach(tab => {
        if (activeCallTabs[tab.id]?.callActive) {
          try {
            chrome.tabs.sendMessage(tab.id, {
              type: 'THREAT_UPDATE',
              threat: currentThreat
            }, () => {});
          } catch (e) {}
        }
      });
    });

    // Update extension badge
    const score = currentThreat.score;
    if (score >= 80) updateBadge("⚠", "#ef4444");
    else if (score >= 60) updateBadge("!", "#f97316");
    else if (score >= 30) updateBadge("~", "#f59e0b");
    else updateBadge("✓", "#22c55e");

    // Send periodic log to dashboard
    if (score > 20) {
      sendLogToDashboard({
        event: 'threat_update',
        score: currentThreat.score,
        label: currentThreat.label,
        confidence: currentThreat.confidence,
        explanation: currentThreat.explanation,
        reasons: extractReasons(),
        breakdown: currentThreat.breakdown,
        timestamp: currentThreat.timestamp
      });
    }

  }, 5000); // Rescore every 5 seconds
}

function stopScoringLoop() {
  if (scoringInterval) {
    clearInterval(scoringInterval);
    scoringInterval = null;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function detectPlatform(url) {
  for (const p of CALL_PLATFORMS) {
    if (p.pattern.test(url)) return p.name;
  }
  return null;
}

function getActivePlatform() {
  const sessions = Object.values(activeCallTabs);
  const active = sessions.find(s => s?.callActive && s?.platform);
  if (active) return active.platform;
  const watched = sessions.find(s => s?.platform);
  return watched ? watched.platform : null;
}

function updateBadge(text, color) {
  chrome.action.setBadgeText({ text: text.substring(0, 4) });
  if (color) chrome.action.setBadgeBackgroundColor({ color });
}

function extractReasons() {
  const reasons = [];
  const bd = currentSignals.behaviourDetails || {};
  if (bd.urgencyHits > 0) reasons.push("Urgency Language");
  if (bd.authorityHits > 0) reasons.push("Authority Impersonation");
  if (bd.financialHits > 0) reasons.push("Financial Request");
  if (bd.fearHits > 0) reasons.push("Fear/Threat Framing");
  if (bd.linkShareHits > 0) reasons.push("Link/Screen-Share Request");
  const vd = currentSignals.voiceDetails || {};
  if (vd.lowPitchVariance) reasons.push("Synthetic Voice Detected");
  if (vd.waveformAnomaly) reasons.push("Audio Waveform Anomaly");

  const links = Array.isArray(currentSignals.urlDetails?.links) ? currentSignals.urlDetails.links : [];
  if (links.length > 0) {
    const worst = links.reduce((best, l) => {
      if (!best) return l;
      return (l?.score || 0) > (best?.score || 0) ? l : best;
    }, null);

    const worstScore = worst?.score || 0;
    const verdict = worst?.verdict || null;
    if (verdict === 'malicious' || worstScore >= 80) reasons.push("Malicious URL Detected");
    else if (verdict === 'suspicious' || worstScore >= 40) reasons.push("Suspicious URL Detected");
  }
  return reasons;
}

function sendLogToDashboard(data) {
  const entry = {
    id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
    received_at: new Date().toISOString(),
    ...data
  };

  // Always persist locally so the built-in dashboard works without a separate server.
  chrome.storage.local.get([LOCAL_LOG_KEY], (result) => {
    const logs = Array.isArray(result[LOCAL_LOG_KEY]) ? result[LOCAL_LOG_KEY] : [];
    logs.push(entry);
    if (logs.length > MAX_LOCAL_LOGS) logs.splice(0, logs.length - MAX_LOCAL_LOGS);
    chrome.storage.local.set({ [LOCAL_LOG_KEY]: logs });
  });

  // Best-effort: also send to the local dashboard server if it's running.
  fetch(`${DASHBOARD_BASE_URL}/api/log`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(entry)
  }).catch(() => {});
}

console.log("[LCF] 🛡 Live Call Firewall background service started");
