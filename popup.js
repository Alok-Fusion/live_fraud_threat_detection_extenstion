/**
 * Live Call Firewall — Popup Logic
 * Communicates with background service worker to display real-time threat data.
 */

// ─── DOM References ───────────────────────────────────────────────────────────
const statusPill    = document.getElementById('status-pill');
const statusDot     = document.getElementById('status-dot');
const statusText    = document.getElementById('status-text');
const gaugeArc      = document.getElementById('gauge-arc');
const gaugeText     = document.getElementById('gauge-text');
const threatLevel   = document.getElementById('threat-level');
const explainText   = document.getElementById('explain-text');
const confFill      = document.getElementById('confidence-fill');
const confPct       = document.getElementById('confidence-pct');
const bvScore       = document.getElementById('bv-score');
const voScore       = document.getElementById('vo-score');
const cxScore       = document.getElementById('cx-score');
const callPlatform  = document.getElementById('call-platform');
const pillBehaviour = document.getElementById('pill-behaviour');
const pillVoice     = document.getElementById('pill-voice');
const pillContext   = document.getElementById('pill-context');

const urlCheckInput  = document.getElementById('urlcheck-input');
const urlCheckBtn    = document.getElementById('btn-urlcheck');
const urlCheckResult = document.getElementById('urlcheck-result');

let lastThreat = null;
let lastUrlCheck = null;

// SVG gauge constants
const GAUGE_CIRCUMFERENCE = 251.3;  // 2 * PI * 50 (radius)
const GAUGE_VISIBLE = 188.5;        // ~75% of circle (from -210 to +30 degrees)

// ─── Update Gauge ─────────────────────────────────────────────────────────────
function updateGauge(score) {
  // dashoffset goes from full circumference (0%) to (circumference - visible_arc * pct)
  const offset = GAUGE_CIRCUMFERENCE - (GAUGE_VISIBLE * score / 100);
  gaugeArc.style.strokeDashoffset = offset;
  gaugeText.textContent = score > 0 ? `${score}%` : '—';

  // Color the gauge text
  if (score < 30) gaugeText.setAttribute('fill', '#22c55e');
  else if (score < 60) gaugeText.setAttribute('fill', '#f59e0b');
  else if (score < 80) gaugeText.setAttribute('fill', '#f97316');
  else gaugeText.setAttribute('fill', '#ef4444');
}

// ─── Update Threat Display ────────────────────────────────────────────────────
function displayThreat(threat) {
  if (!threat) return;

  updateGauge(threat.score);

  threatLevel.textContent = `${threat.emoji} ${threat.label}`;
  threatLevel.style.color = threat.color;

  explainText.textContent = threat.explanation || "Monitoring active...";

  // Confidence bar
  const conf = threat.confidence || 0;
  confFill.style.width = conf + '%';
  confPct.textContent = conf + '%';

  // Breakdown pills
  const bd = threat.breakdown || {};
  bvScore.textContent = bd.behaviour || 0;
  voScore.textContent = bd.voice || 0;
  cxScore.textContent = bd.context || 0;

  // Highlight active pills
  pillBehaviour.classList.toggle('active', (bd.behaviour || 0) > 0);
  pillVoice.classList.toggle('active', (bd.voice || 0) > 0);
  pillContext.classList.toggle('active', (bd.context || 0) > 0);
}

// ─── Update Call Status ───────────────────────────────────────────────────────
function setStatus(state, platform) {
  statusDot.className = `status-dot ${state}`;

  switch (state) {
    case 'idle':
      statusText.textContent = 'Idle';
      statusPill.style.borderColor = 'rgba(255,255,255,0.1)';
      break;
    case 'watch':
      statusText.textContent = 'Watching';
      statusPill.style.borderColor = 'rgba(99,102,241,0.4)';
      break;
    case 'live':
      statusText.textContent = '🔴 LIVE';
      statusPill.style.borderColor = 'rgba(239,68,68,0.4)';
      break;
    case 'safe':
      statusText.textContent = '✓ Safe';
      statusPill.style.borderColor = 'rgba(34,197,94,0.4)';
      break;
  }

  callPlatform.textContent = platform || '—';
}

// ─── Polling Background for Latest Threat ────────────────────────────────────
function pollBackground() {
  chrome.runtime.sendMessage({ type: 'GET_THREAT' }, (response) => {
    if (chrome.runtime.lastError || !response) return;

    const { threat } = response;
    lastThreat = threat || null;

    if (threat) {
      displayThreat(threat);
      // Determine status from score
      if (threat.score >= 60) setStatus('live', response.platform);
      else if (threat.score >= 30) setStatus('watch', response.platform);
      else setStatus('safe', response.platform);
    }
  });

  // Also get call status
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]) return;
    chrome.tabs.sendMessage(tabs[0].id, { type: 'GET_CALL_STATUS' }, (response) => {
      if (chrome.runtime.lastError || !response) {
        setStatus('idle', null);
        return;
      }

      if (response.callActive) {
        if (!lastThreat) {
          setStatus('live', response.platform);
          updateGauge(0);
          threatLevel.textContent = 'Monitoring Call';
          threatLevel.style.color = '#e2e8f0';
          explainText.textContent = 'Call detected. Listening for scam and deepfake indicators...';
          confFill.style.width = '0%';
          confPct.textContent = '—%';
          bvScore.textContent = '0';
          voScore.textContent = '0';
          cxScore.textContent = '0';
          pillBehaviour.classList.remove('active');
          pillVoice.classList.remove('active');
          pillContext.classList.remove('active');
        }
        return;
      }

      // Not in-call on a supported platform: show Watching; otherwise Idle.
      if (!lastThreat) {
        updateGauge(0);
        threatLevel.textContent = 'No Call Detected';
        threatLevel.style.color = '#e2e8f0';
        explainText.textContent = 'Start or join a video/audio call to begin real-time threat analysis.';
        confFill.style.width = '0%';
        confPct.textContent = '—%';
        bvScore.textContent = '0';
        voScore.textContent = '0';
        cxScore.textContent = '0';
        pillBehaviour.classList.remove('active');
        pillVoice.classList.remove('active');
        pillContext.classList.remove('active');
      }

      setStatus(response.platform ? 'watch' : 'idle', response.platform);
    });
  });
}

// ─── Action Handlers ──────────────────────────────────────────────────────────
function openDashboard() {
  const baseUrl = 'http://localhost:3000';
  const extUrl = chrome.runtime.getURL('dashboard/index.html');

  // Prefer the server dashboard when available; otherwise fall back to the built-in dashboard.
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 1200);

  fetch(`${baseUrl}/health`, { signal: controller.signal })
    .then((res) => {
      if (!res.ok) throw new Error(`Health check failed (${res.status})`);
      chrome.tabs.create({ url: baseUrl });
    })
    .catch(() => {
      chrome.tabs.create({ url: extUrl });
      explainText.textContent = 'Opened built-in dashboard (local logs). To use the full server dashboard, start it in the `server` folder with `npm start`.';
    })
    .finally(() => clearTimeout(timeoutId));
}

window.openDashboard = openDashboard;

function reportThreat() {
  chrome.runtime.sendMessage({ type: 'GET_THREAT' }, (response) => {
    const threat = response?.threat;

    // Open cybercrime portal immediately (avoid losing the click gesture).
    chrome.tabs.create({ url: 'https://cybercrime.gov.in' });

    // Persist the report via background (stored locally and sent to server if available).
    chrome.runtime.sendMessage({
      type: 'USER_REPORT',
      data: {
        platform: response?.platform || null,
        score: threat?.score || 0,
        label: threat?.label || 'Unknown',
        explanation: threat?.explanation || '',
        timestamp: new Date().toISOString()
      }
    });

    explainText.textContent = 'Report opened (cybercrime.gov.in) and saved to dashboard logs.';
  });
}

window.reportThreat = reportThreat;

// ─── URL Check ───────────────────────────────────────────────────────────────
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

function truncate(value, maxLen) {
  const s = String(value ?? '');
  if (s.length <= maxLen) return s;
  return s.slice(0, Math.max(0, maxLen - 3)) + '...';
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(String(text ?? ''));
    return true;
  } catch (e) {
    return false;
  }
}

function renderUrlCheckResult(payload) {
  if (!urlCheckResult) return;

  const worst = payload?.worst || null;
  const analyses = Array.isArray(payload?.analyses) ? payload.analyses : [];

  if (!worst) {
    urlCheckResult.style.display = 'block';
    urlCheckResult.innerHTML = `<div style="color:#94a3b8;font-size:12px">No valid URL found in the input.</div>`;
    return;
  }

  const verdict = worst.verdict || 'unknown';
  const score = worst.score ?? 0;
  const badgeLabel =
    verdict === 'malicious' ? 'Malicious' :
    verdict === 'suspicious' ? 'Suspicious' :
    verdict === 'safe' ? 'Safe' :
    'Unknown';

  const url = worst.normalizedUrl || worst.originalUrl || '';
  const hostname = worst.hostname || '--';
  const tld = worst.tld ? `.${worst.tld}` : '--';

  const topReasons = Array.isArray(worst.reasons) ? worst.reasons.slice(0, 6) : [];
  const reasonsHtml = topReasons.length
    ? `<b>Indicators:</b><br>${topReasons.map((r) => `&bull; ${escapeHtml(r)}`).join('<br>')}`
    : `<b>Indicators:</b><br>&bull; --`;

  urlCheckResult.style.display = 'block';
  urlCheckResult.innerHTML = `
    <div class="urlcheck-top">
      <span class="urlcheck-badge ${escapeHtml(verdict)}">${escapeHtml(badgeLabel)} · ${escapeHtml(score)}/100</span>
      <button class="urlcheck-copy" type="button" id="btn-urlcheck-copy">Copy JSON</button>
    </div>
    <div class="urlcheck-url" title="${escapeHtml(url)}">${escapeHtml(truncate(url, 90))}</div>
    <div class="urlcheck-meta">
      <span>Host: ${escapeHtml(hostname)}</span>
      <span>TLD: ${escapeHtml(tld)}</span>
      <span>Scanned: ${escapeHtml(analyses.length)}</span>
    </div>
    <div class="urlcheck-reasons">${reasonsHtml}</div>
  `;

  document.getElementById('btn-urlcheck-copy')?.addEventListener('click', async () => {
    await copyText(JSON.stringify(lastUrlCheck, null, 2));
  });
}

function runUrlCheck() {
  if (!urlCheckBtn || !urlCheckInput) return;
  const text = String(urlCheckInput.value || '').trim();
  if (!text) return;

  urlCheckBtn.disabled = true;
  urlCheckBtn.textContent = 'Checking...';

  let finished = false;
  const timeoutId = setTimeout(() => {
    if (finished) return;
    finished = true;
    urlCheckBtn.disabled = false;
    urlCheckBtn.textContent = 'Check';
    if (urlCheckResult) {
      urlCheckResult.style.display = 'block';
      urlCheckResult.innerHTML = `<div style="color:#f87171;font-size:12px">No response from the background. Reload the extension and try again.</div>`;
    }
  }, 2500);

  try {
    chrome.runtime.sendMessage({ type: 'ANALYZE_URL', data: { text } }, (resp) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeoutId);

      urlCheckBtn.disabled = false;
      urlCheckBtn.textContent = 'Check';

      if (chrome.runtime.lastError || !resp?.ok) {
        lastUrlCheck = null;
        if (urlCheckResult) {
          urlCheckResult.style.display = 'block';
          urlCheckResult.innerHTML = `<div style="color:#f87171;font-size:12px">URL scan failed. Please try again.</div>`;
        }
        return;
      }

      lastUrlCheck = resp;
      renderUrlCheckResult(resp);
    });
  } catch (e) {
    if (finished) return;
    finished = true;
    clearTimeout(timeoutId);
    urlCheckBtn.disabled = false;
    urlCheckBtn.textContent = 'Check';
    if (urlCheckResult) {
      urlCheckResult.style.display = 'block';
      urlCheckResult.innerHTML = `<div style="color:#f87171;font-size:12px">URL scan failed. Please try again.</div>`;
    }
  }
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setStatus('idle', null);
  updateGauge(0);

  // MV3 blocks inline onclick handlers via CSP; wire buttons here instead.
  document.getElementById('btn-dashboard')?.addEventListener('click', openDashboard);
  document.getElementById('btn-report')?.addEventListener('click', reportThreat);
  document.getElementById('btn-urlcheck')?.addEventListener('click', runUrlCheck);
  document.getElementById('urlcheck-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) runUrlCheck();
  });

  // Initial poll
  pollBackground();

  // Refresh every 3 seconds while popup is open
  const pollTimer = setInterval(pollBackground, 3000);

  // Clean up on popup close
  window.addEventListener('beforeunload', () => clearInterval(pollTimer));
});
