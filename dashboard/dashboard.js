/**
 * Live Call Firewall — Dashboard JavaScript
 * Polls API, renders Chart.js charts, updates live feed table.
 */

// ─── State ────────────────────────────────────────────────────────────────────
let allLogs       = [];
let activeFilter  = 'all';
let chartDaily    = null;
let chartCats     = null;
let chartPlatform = null;
let lastLogId     = null;
let fallbackDailyEl = null;
let fallbackCats = null;
let fallbackPlatform = null;
let detailsSelectedId = null;
let detailsLog = null;
let detailsToastTimer = null;

const IS_EXTENSION = location.protocol === 'chrome-extension:';
const KNOWN_PLATFORMS = ['Google Meet', 'Zoom', 'Microsoft Teams', 'WhatsApp Web', 'Cisco Webex'];

// ─── Chart.js Global Config ───────────────────────────────────────────────────
// When opened as an extension page, remote scripts (Chart.js CDN) are blocked by MV3 CSP.
if (window.Chart) {
  Chart.defaults.color = '#64748b';
  Chart.defaults.font.family = "'Inter', sans-serif";
  Chart.defaults.plugins.legend.labels.boxWidth = 12;
}

// ─── Colour Palette ───────────────────────────────────────────────────────────
const CHART_COLORS = [
  '#6366f1', '#ef4444', '#f59e0b', '#22c55e', '#06b6d4',
  '#a855f7', '#f97316', '#14b8a6'
];

// ─── Category Labels ─────────────────────────────────────────────────────────
const CATEGORY_LABELS = {
  "Urgency Language":           { icon: "⚡", color: "#f59e0b" },
  "Authority Impersonation":    { icon: "🎭", color: "#a855f7" },
  "Financial Request":          { icon: "💰", color: "#ef4444" },
  "Fear/Threat Framing":        { icon: "😨", color: "#f97316" },
  "Link/Screen-Share Request":  { icon: "🔗", color: "#06b6d4" },
  "Suspicious URL Detected":    { icon: "URL", color: "#f59e0b" },
  "Malicious URL Detected":     { icon: "URL", color: "#ef4444" },
  "Synthetic Voice Detected":   { icon: "🤖", color: "#ec4899" },
  "Audio Waveform Anomaly":     { icon: "〰️", color: "#8b5cf6" }
};

// ─── Initialise Charts ────────────────────────────────────────────────────────
function initCharts() {
  if (!window.Chart) {
    initFallbackCharts();
    return;
  }
  // ── Daily Exposure Bar ────────────────────────────────────────────────────
  const ctxDaily = document.getElementById('chart-daily').getContext('2d');
  chartDaily = new Chart(ctxDaily, {
    type: 'bar',
    data: {
      labels: getLastNDays(7),
      datasets: [
        {
          label: 'Calls Monitored',
          data: new Array(7).fill(0),
          backgroundColor: 'rgba(99,102,241,0.45)',
          borderColor: 'rgba(99,102,241,0.9)',
          borderWidth: 1,
          borderRadius: 6,
          borderSkipped: false
        },
        {
          label: 'Threat Events',
          data: new Array(7).fill(0),
          backgroundColor: 'rgba(239,68,68,0.35)',
          borderColor: 'rgba(239,68,68,0.9)',
          borderWidth: 1,
          borderRadius: 6,
          borderSkipped: false
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(8,10,22,0.95)',
          borderColor: 'rgba(99,102,241,0.3)',
          borderWidth: 1,
          padding: 10
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: { color: '#475569' }
        },
        y: {
          grid: { color: 'rgba(255,255,255,0.04)' },
          ticks: { color: '#475569', stepSize: 1 },
          beginAtZero: true
        }
      }
    }
  });

  // ── Attack Categories Donut ───────────────────────────────────────────────
  const ctxCats = document.getElementById('chart-categories').getContext('2d');
  chartCats = new Chart(ctxCats, {
    type: 'doughnut',
    data: {
      labels: ['Awaiting data...'],
      datasets: [{ data: [1], backgroundColor: ['rgba(255,255,255,0.05)'], borderWidth: 0 }]
    },
    options: {
      responsive: true,
      cutout: '68%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { padding: 12, font: { size: 11 } }
        },
        tooltip: {
          backgroundColor: 'rgba(8,10,22,0.95)',
          borderColor: 'rgba(99,102,241,0.3)',
          borderWidth: 1
        }
      }
    }
  });

  // ── Platform Breakdown Donut ──────────────────────────────────────────────
  const ctxPlatform = document.getElementById('chart-platforms').getContext('2d');
  chartPlatform = new Chart(ctxPlatform, {
    type: 'doughnut',
    data: {
      labels: ['Awaiting data...'],
      datasets: [{ data: [1], backgroundColor: ['rgba(255,255,255,0.05)'], borderWidth: 0 }]
    },
    options: {
      responsive: true,
      cutout: '68%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { padding: 12, font: { size: 11 } }
        },
        tooltip: {
          backgroundColor: 'rgba(8,10,22,0.95)',
          borderColor: 'rgba(99,102,241,0.3)',
          borderWidth: 1
        }
      }
    }
  });
}

// ─── Fetch & Update Data ──────────────────────────────────────────────────────
function readLocalLogs() {
  return new Promise((resolve) => {
    if (!IS_EXTENSION || !chrome?.storage?.local) {
      resolve([]);
      return;
    }
    chrome.storage.local.get(['lcf_logs'], (result) => {
      resolve(Array.isArray(result.lcf_logs) ? result.lcf_logs : []);
    });
  });
}

function computeAnalyticsFromLogs(logs) {
  const calls = logs.filter(l => l.event === 'call_ended');
  const threats = logs.filter(l => l.event === 'threat_update' && (l.score || 0) > 0);

  const now = Date.now();
  const dailyCalls = {};
  const dailyThreats = {};
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now - i * 86400000);
    const key = d.toISOString().split('T')[0];
    dailyCalls[key] = 0;
    dailyThreats[key] = 0;
  }

  calls.forEach(c => {
    const key = (c.timestamp || c.received_at || '').split('T')[0];
    if (dailyCalls[key] !== undefined) dailyCalls[key]++;
  });

  threats.forEach(t => {
    const key = (t.timestamp || t.received_at || '').split('T')[0];
    if (dailyThreats[key] !== undefined) dailyThreats[key]++;
  });

  const reasonCounts = {};
  logs.forEach(l => {
    (l.reasons || []).forEach(r => {
      reasonCounts[r] = (reasonCounts[r] || 0) + 1;
    });
  });

  const platforms = {};
  calls.forEach(c => {
    if (c.platform) platforms[c.platform] = (platforms[c.platform] || 0) + 1;
  });

  return {
    totalCalls: calls.length,
    avgPeakScore: calls.length
      ? Math.round(calls.reduce((s, c) => s + (c.peak_score || 0), 0) / calls.length)
      : 0,
    highRiskCalls: calls.filter(c => (c.peak_score || 0) >= 60).length,
    criticalCalls: calls.filter(c => (c.peak_score || 0) >= 80).length,
    dailyCalls,
    dailyThreats,
    // Backwards-compat key used by older dashboard code.
    dailyExposure: dailyThreats,
    reasonCounts,
    platforms
  };
}

async function fetchLogs() {
  try {
    if (IS_EXTENSION) {
      const stored = await readLocalLogs();
      const sorted = [...stored].sort((a, b) => {
        const ta = new Date(a.received_at || a.timestamp || 0).getTime();
        const tb = new Date(b.received_at || b.timestamp || 0).getTime();
        return tb - ta;
      });

       allLogs = sorted.slice(0, 200);
       document.getElementById('total-log-count').textContent = stored.length;
       document.getElementById('live-count').textContent =
         stored.filter(l =>
           l.event === 'threat_update' ||
           l.event === 'url_detected' ||
           l.event === 'user_report' ||
           (l.event === 'call_ended' && (((l.peak_score || 0) >= 30) || ((l.reasons || []).length > 0)))
         ).length;
       renderFeed();
       renderThreatMap(stored);
      return;
    }

    const res = await fetch('/api/logs?limit=200');
    if (!res.ok) throw new Error('fetch failed');
    const data = await res.json();
    allLogs = data.entries || [];
    document.getElementById('total-log-count').textContent = data.total || 0;
    document.getElementById('live-count').textContent =
      allLogs.filter(l =>
        l.event === 'threat_update' ||
        l.event === 'url_detected' ||
        l.event === 'user_report' ||
        (l.event === 'call_ended' && (((l.peak_score || 0) >= 30) || ((l.reasons || []).length > 0)))
      ).length;
    renderFeed();
    renderThreatMap(allLogs);
  } catch(e) {
    // Server might not be running, show sample state
  }
}

async function fetchAnalytics() {
  try {
    if (IS_EXTENSION) {
      const stored = await readLocalLogs();
      const data = computeAnalyticsFromLogs(stored);
      updateKPIs(data);
      updateCharts(data);
      return;
    }

    const res = await fetch('/api/analytics');
    if (!res.ok) throw new Error();
    const apiData = await res.json();
    let data = apiData || {};

    // Backfill missing/newer fields using the logs we already fetched.
    // This keeps charts correct even if the server isn't restarted after updates.
    if (Array.isArray(allLogs) && allLogs.length > 0) {
      const computed = computeAnalyticsFromLogs(allLogs);
      data = {
        ...computed,
        ...data,
        dailyCalls: data.dailyCalls || computed.dailyCalls,
        dailyThreats: data.dailyThreats || data.dailyExposure || computed.dailyThreats,
        dailyExposure: data.dailyExposure || data.dailyThreats || computed.dailyThreats,
        reasonCounts: (data.reasonCounts && Object.keys(data.reasonCounts).length)
          ? data.reasonCounts
          : computed.reasonCounts,
        platforms: (data.platforms && Object.keys(data.platforms).length)
          ? data.platforms
          : computed.platforms
      };
    }

    updateKPIs(data);
    updateCharts(data);
  } catch(e) {}
}

// ─── Update KPI Cards ─────────────────────────────────────────────────────────
function updateKPIs(data) {
  animateCount('kpi-total-calls', data.totalCalls || 0);
  animateCount('kpi-high-risk', data.highRiskCalls || 0);
  animateCount('kpi-critical', data.criticalCalls || 0);
  animateCount('kpi-avg-score', data.avgPeakScore || 0);
}

function animateCount(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const current = parseInt(el.textContent) || 0;
  const diff = target - current;
  if (diff === 0) return;
  let step = 0;
  const steps = 20;
  const timer = setInterval(() => {
    step++;
    const val = Math.round(current + (diff * step / steps));
    el.textContent = id === 'kpi-avg-score' ? `${val}%` : val;
    if (step >= steps) { el.textContent = id === 'kpi-avg-score' ? `${target}%` : target; clearInterval(timer); }
  }, 30);
}

// ─── Update Charts ────────────────────────────────────────────────────────────
function updateCharts(data) {
  const dailyCalls = data.dailyCalls || null;
  const dailyThreats = data.dailyThreats || data.dailyExposure || null;

  if (!window.Chart) {
    updateFallbackDaily(dailyCalls, dailyThreats);
    updateFallbackDonut(fallbackCats, data.reasonCounts || {}, { showIcons: true });
    updateFallbackDonut(fallbackPlatform, data.platforms || {}, { showIcons: false });
    return;
  }

  // Daily Exposure (Calls + Threats)
  if ((dailyCalls || dailyThreats) && chartDaily) {
    const base = dailyCalls || dailyThreats;
    const keys = Object.keys(base);
    const callVals = keys.map(k => dailyCalls?.[k] ?? 0);
    const threatVals = keys.map(k => dailyThreats?.[k] ?? 0);

    chartDaily.data.labels = keys.map((k) => {
      const d = new Date(k);
      return d.toLocaleDateString('en-IN', { weekday: 'short', month: 'short', day: 'numeric' });
    });
    if (chartDaily.data.datasets[0]) chartDaily.data.datasets[0].data = callVals;
    if (chartDaily.data.datasets[1]) chartDaily.data.datasets[1].data = threatVals;
    chartDaily.update('none');
  }

  // Attack Categories
  if (data.reasonCounts && chartCats) {
    const entries = Object.entries(data.reasonCounts).sort((a,b) => b[1]-a[1]);
    if (entries.length > 0) {
      chartCats.data.labels = entries.map(e => e[0]);
      chartCats.data.datasets[0].data = entries.map(e => e[1]);
      chartCats.data.datasets[0].backgroundColor = entries.map((_, i) => CHART_COLORS[i % CHART_COLORS.length]);
      chartCats.update('none');
    }
  }

  // Platform Breakdown
  if (data.platforms && chartPlatform) {
    const entries = Object.entries(data.platforms).sort((a,b) => b[1]-a[1]);
    if (entries.length > 0) {
      chartPlatform.data.labels = entries.map(e => e[0]);
      chartPlatform.data.datasets[0].data = entries.map(e => e[1]);
      chartPlatform.data.datasets[0].backgroundColor = entries.map((_, i) => CHART_COLORS[i % CHART_COLORS.length]);
      chartPlatform.update('none');
    }
  }
}

// ─── Render Feed Table ────────────────────────────────────────────────────────
function renderFeed() {
  const tbody = document.getElementById('feed-tbody');
  const filtered = activeFilter === 'all'
    ? allLogs
    : allLogs.filter(l => l.event === activeFilter);

  if (filtered.length === 0) {
    const hint = IS_EXTENSION
      ? 'Join a call to generate events, then refresh this dashboard.'
      : 'Make sure the dashboard server is running: <code>node server/server.js</code>';
    tbody.innerHTML = `<tr class="empty-row"><td colspan="6">
      <div class="empty-state">🛡 No events yet. Install the extension and join a call to begin monitoring.<br>
      <span>${hint}</span></div>
    </td></tr>`;
    return;
  }

  // Show the newest explanation (prefer threat_update, fall back to call summary).
  const explainSection = document.getElementById('explain-section');
  const explainBody = document.getElementById('explain-body');
  if (explainSection && explainBody) {
    const latestExplain = allLogs.find((l) => {
      if (l?.explanation) return true;
      if (l?.event === 'call_ended' && Array.isArray(l?.reasons) && l.reasons.length > 0) return true;
      return false;
    });

    if (latestExplain) {
      const reasons = Array.isArray(latestExplain.reasons) ? latestExplain.reasons : [];
      const fallback = reasons.length ? `Call summary: ${reasons.join(', ')}.` : '';
      const text = latestExplain.explanation || fallback;
      if (text) {
        explainSection.style.display = 'block';
        explainBody.textContent = text;
      } else {
        explainSection.style.display = 'none';
      }
    } else {
      explainSection.style.display = 'none';
    }
  }

  tbody.innerHTML = filtered.slice(0, 50).map(log => {
    const time = log.received_at || log.timestamp || '';
    const timeStr = time ? new Date(time).toLocaleTimeString('en-IN', { hour12: false }) : '—';
    const dateStr = time ? new Date(time).toLocaleDateString('en-IN', { day:'2-digit', month:'short' }) : '';
    const score = (log.score ?? log.peak_score);
    const scoreBadge = (score !== undefined && score !== null)
      ? `<span class="score-badge ${getScoreClass(score)}">${score}%</span>`
      : `<span class="score-badge" style="color:#475569">—</span>`;
    const eventTag = getEventTag(log.event);
    const platform = log.platform || log.source || '—';
    const label = log.label || log.peak_label || '—';
    const reasons = (log.reasons || []).map(r =>
      `<span class="signal-pill">${r}</span>`
    ).join('');
    const rowAttr = log.id ? `data-log-id="${escapeHtml(log.id)}"` : '';
    const rowClass = (log.id && log.id === detailsSelectedId) ? 'is-selected' : '';

    return `<tr ${rowAttr} class="${rowClass}">
      <td><div style="font-size:12px">${timeStr}</div><div style="font-size:10px;color:#475569">${dateStr}</div></td>
      <td>${eventTag}</td>
      <td>${platform}</td>
      <td>${scoreBadge}</td>
      <td style="color:${getScoreColor(score)};font-weight:600;font-family:'Inter',sans-serif">${label}</td>
      <td><div class="signals-list">${reasons || '<span style="color:#334155">—</span>'}</div></td>
    </tr>`;
  }).join('');

  // Update ticker with latest threat
  const latestThreat = allLogs.find(l => l.event === 'threat_update' && (l.score || 0) > 30);
  if (latestThreat) {
    document.getElementById('ticker-text').textContent =
      `${latestThreat.label} — ${latestThreat.score}% — ${latestThreat.platform || 'Unknown Platform'}`;
  } else {
    const lastCall = allLogs.find(l => l.event === 'call_ended');
    if (lastCall) {
      const peak = lastCall.peak_score ?? lastCall.score ?? 0;
      const plat = lastCall.platform || 'Unknown Platform';
      document.getElementById('ticker-text').textContent =
        `Last call ended — Peak ${peak}% — ${plat}`;
    }
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function getScoreClass(score) {
  if (score === undefined || score === null) return '';
  if (score < 30) return 'score-low';
  if (score < 60) return 'score-sus';
  if (score < 80) return 'score-likely';
  return 'score-critical';
}

function getScoreColor(score) {
  if (score === undefined || score === null) return '#475569';
  if (score < 30) return '#22c55e';
  if (score < 60) return '#f59e0b';
  if (score < 80) return '#f97316';
  return '#ef4444';
}

function getEventTag(event) {
  const map = {
    'call_started':   ['tag-call-started', 'Call Start'],
    'call_ended':     ['tag-call-ended', 'Call End'],
    'threat_update':  ['tag-threat-update', 'Threat'],
    'url_detected':   ['tag-url-detected', 'Link'],
    'user_report':    ['tag-user-report', 'Report'],
    'user_action':    ['tag-call-ended', 'Action']
  };
  const [cls, label] = map[event] || ['tag-call-ended', event || 'Event'];
  return `<span class="event-tag ${cls}">${label}</span>`;
}

function getLastNDays(n) {
  return Array.from({ length: n }, (_, i) => {
    const d = new Date(Date.now() - (n-1-i) * 86400000);
    return d.toLocaleDateString('en-IN', { weekday: 'short', day: 'numeric' });
  });
}

// ─── Filter Buttons ───────────────────────────────────────────────────────────
// ─── Navigation ──────────────────────────────────────────────────────────────
function initNavigation() {
  const items = Array.from(document.querySelectorAll('.nav-item'));
  if (items.length === 0) return;

  const titles = {
    'overview': 'Security Overview',
    'live-feed': 'Live Feed',
    'analytics': 'Analytics',
    'threats': 'Threat Map'
  };

  const titleEl = document.querySelector('.page-title');
  const setActive = (sectionKey) => {
    items.forEach((it) => it.classList.toggle('active', it.dataset.section === sectionKey));
    if (titleEl) titleEl.textContent = titles[sectionKey] || 'Dashboard';
  };

  const sectionFromHash = () => {
    const hash = location.hash || '';
    const match = items.find((it) => (it.getAttribute('href') || '') === hash);
    return match?.dataset.section || 'overview';
  };

  setActive(sectionFromHash());

  items.forEach((it) => {
    it.addEventListener('click', (e) => {
      const section = it.dataset.section || 'overview';
      const href = it.getAttribute('href') || '';
      if (href.startsWith('#')) {
        e.preventDefault();
        const target = document.querySelector(href);
        if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        history.replaceState(null, '', href);
      }
      setActive(section);
    });
  });

  window.addEventListener('hashchange', () => setActive(sectionFromHash()));
}

// ─── Server Status ───────────────────────────────────────────────────────────
async function updateServerStatus() {
  const dot = document.getElementById('server-dot');
  const label = document.getElementById('server-label');
  if (!dot || !label) return;

  if (IS_EXTENSION) {
    dot.style.background = 'var(--cyan)';
    dot.style.animation = 'none';
    label.textContent = 'Extension Mode (Local Logs)';
    return;
  }

  try {
    const res = await fetch('/health', { cache: 'no-store' });
    if (!res.ok) throw new Error(`health ${res.status}`);
    const data = await res.json();
    dot.style.background = 'var(--green)';
    dot.style.animation = '';
    label.textContent = `Server Online (${data.logCount ?? 0} events)`;
  } catch (e) {
    dot.style.background = 'var(--red)';
    dot.style.animation = 'none';
    label.textContent = 'Server Offline';
  }
}

// ─── Details Drawer ──────────────────────────────────────────────────────────
function initDetailsDrawer() {
  const closeBtn = document.getElementById('details-close');
  const backdrop = document.getElementById('details-backdrop');
  closeBtn?.addEventListener('click', closeDetails);
  backdrop?.addEventListener('click', closeDetails);

  // Keyboard: Esc closes the drawer.
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeDetails();
  });

  // Drawer action buttons.
  const drawer = document.getElementById('details-drawer');
  drawer?.addEventListener('click', async (e) => {
    const btn = e.target?.closest?.('[data-action]');
    const action = btn?.dataset?.action;
    if (!action) return;
    e.preventDefault();

    if (!detailsLog) {
      showDetailsToast('No event selected.');
      return;
    }

    if (action === 'copy-json') {
      const ok = await copyText(JSON.stringify(detailsLog, null, 2));
      showDetailsToast(ok ? 'Copied JSON.' : 'Copy failed.');
      return;
    }

    if (action === 'copy-url') {
      const url = detailsLog.url || '';
      const ok = await copyText(url);
      showDetailsToast(ok ? 'Copied URL.' : 'Copy failed.');
      return;
    }

    if (action === 'copy-explanation') {
      const explanation = detailsLog.explanation || buildFallbackExplanation(detailsLog) || '';
      const ok = await copyText(explanation);
      showDetailsToast(ok ? 'Copied explanation.' : 'Copy failed.');
      return;
    }

    if (action === 'toggle-raw') {
      const raw = document.getElementById('details-raw');
      if (!raw) return;
      const isHidden = raw.style.display === 'none' || raw.style.display === '';
      raw.style.display = isHidden ? 'block' : 'none';
      btn.textContent = isHidden ? 'Hide Raw' : 'Show Raw';
      return;
    }
  });

  // Toast element (created once).
  if (!document.getElementById('details-toast')) {
    const toast = document.createElement('div');
    toast.id = 'details-toast';
    toast.className = 'details-toast';
    toast.textContent = '';
    document.body.appendChild(toast);
  }
}

function initFeedInteractions() {
  const tbody = document.getElementById('feed-tbody');
  if (!tbody) return;

  tbody.addEventListener('click', (e) => {
    const row = e.target?.closest?.('tr[data-log-id]');
    const id = row?.dataset?.logId;
    if (!row || !id) return;

    const log = allLogs.find((l) => l?.id === id);
    if (!log) return;

    // Highlight selection.
    tbody.querySelectorAll('tr.is-selected').forEach((r) => r.classList.remove('is-selected'));
    row.classList.add('is-selected');
    detailsSelectedId = id;

    openDetails(log);
  });
}

function openDetails(log) {
  if (!log) return;
  detailsLog = log;

  const titleEl = document.getElementById('details-title');
  const subEl = document.getElementById('details-sub');
  const bodyEl = document.getElementById('details-body');

  const eventName = formatEventName(log.event);
  const platform = log.platform || log.source || null;
  const time = log.received_at || log.timestamp || '';
  const timeStr = time
    ? new Date(time).toLocaleString('en-IN', {
        weekday: 'short', year: 'numeric', month: 'short', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
      })
    : '—';

  if (titleEl) titleEl.textContent = platform ? `${eventName} · ${platform}` : eventName;
  if (subEl) subEl.textContent = `${timeStr}${log.id ? ` · ${log.id}` : ''}`;
  if (bodyEl) bodyEl.innerHTML = renderDetailsBody(log);

  document.body.classList.add('lcf-details-open');
  document.getElementById('details-drawer')?.focus?.();
}

function closeDetails() {
  document.body.classList.remove('lcf-details-open');
  detailsLog = null;
  detailsSelectedId = null;

  const tbody = document.getElementById('feed-tbody');
  tbody?.querySelectorAll?.('tr.is-selected')?.forEach?.((r) => r.classList.remove('is-selected'));
}

function renderDetailsBody(log) {
  const platform = log.platform || log.source || '—';
  const eventName = formatEventName(log.event);
  const score = (log.score ?? log.peak_score);
  const label = log.label || log.peak_label || '—';
  const confidence = (log.confidence ?? null);
  const duration = (log.duration_seconds ?? null);
  const reasons = Array.isArray(log.reasons) ? log.reasons : [];
  const urlReasons = Array.isArray(log.url_reasons) ? log.url_reasons : [];
  const explanation = log.explanation || buildFallbackExplanation(log) || '';
  const url = log.url || null;
  const breakdown = log.breakdown || null;
  const time = log.received_at || log.timestamp || '';
  const timeStr = time
    ? new Date(time).toLocaleString('en-IN', { weekday: 'short', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
    : '—';

  const scoreBadge = (score !== undefined && score !== null)
    ? `<span class="score-badge ${getScoreClass(score)}">${score}%</span>`
    : `<span class="score-badge" style="color:#475569">—</span>`;

  const reasonHtml = reasons.length
    ? `<div class="details-reasons">${reasons.map((r) => `<span class="details-reason-pill">${escapeHtml(r)}</span>`).join('')}</div>`
    : `<div class="details-v mono">—</div>`;

  const urlIndicatorsHtml = urlReasons.length
    ? `<div style="margin-top:10px">
        <div class="details-k">URL Indicators</div>
        <div class="details-v" style="margin-top:6px">${urlReasons.map((r) => `&bull; ${escapeHtml(r)}`).join('<br>')}</div>
      </div>`
    : '';

  const breakdownHtml = breakdown && typeof breakdown === 'object'
    ? `<div class="details-card">
        <div class="details-card-title">Breakdown</div>
        <div class="details-grid">
          ${Object.entries(breakdown).map(([k, v]) => `
            <div class="details-item">
              <div class="details-k">${escapeHtml(k)}</div>
              <div class="details-v mono">${escapeHtml(v)} pts</div>
            </div>
          `).join('')}
        </div>
      </div>`
    : '';

  const rawJson = JSON.stringify(log, null, 2);

  return `
    <div class="details-card">
      <div class="details-card-title">Summary</div>
      <div class="details-grid">
        <div class="details-item">
          <div class="details-k">Event</div>
          <div class="details-v">${escapeHtml(eventName)}</div>
        </div>
        <div class="details-item">
          <div class="details-k">Platform</div>
          <div class="details-v">${escapeHtml(platform)}</div>
        </div>
        <div class="details-item">
          <div class="details-k">Score</div>
          <div class="details-v">${scoreBadge}</div>
        </div>
        <div class="details-item">
          <div class="details-k">Label</div>
          <div class="details-v" style="color:${getScoreColor(score)};font-weight:800">${escapeHtml(label)}</div>
        </div>
        <div class="details-item">
          <div class="details-k">Confidence</div>
          <div class="details-v mono">${confidence !== null ? `${escapeHtml(confidence)}%` : '—'}</div>
        </div>
        <div class="details-item">
          <div class="details-k">Time</div>
          <div class="details-v mono">${escapeHtml(timeStr)}</div>
        </div>
        <div class="details-item">
          <div class="details-k">Duration</div>
          <div class="details-v mono">${duration !== null ? `${escapeHtml(duration)}s` : '—'}</div>
        </div>
        <div class="details-item">
          <div class="details-k">Event ID</div>
          <div class="details-v mono">${escapeHtml(log.id || '—')}</div>
        </div>
        <div class="details-item" style="grid-column: 1 / -1;">
          <div class="details-k">URL</div>
          <div class="details-v mono">${url ? escapeHtml(url) : '—'}</div>
        </div>
      </div>

      <div class="details-actions">
        ${url ? `<a class="details-btn primary" href="${escapeHtml(url)}" target="_blank" rel="noopener">Open URL</a>` : ''}
        ${url ? `<button class="details-btn" type="button" data-action="copy-url">Copy URL</button>` : ''}
        <button class="details-btn" type="button" data-action="copy-json">Copy JSON</button>
        ${explanation ? `<button class="details-btn" type="button" data-action="copy-explanation">Copy Explanation</button>` : ''}
        <button class="details-btn" type="button" data-action="toggle-raw">Show Raw</button>
      </div>
    </div>

    <div class="details-card">
      <div class="details-card-title">Signals</div>
      ${reasonHtml}
      ${urlIndicatorsHtml}
    </div>

    ${breakdownHtml}

    <div class="details-card">
      <div class="details-card-title">Explanation</div>
      <div class="details-v">${explanation ? escapeHtml(explanation) : '—'}</div>
    </div>

    <div class="details-card">
      <div class="details-card-title">Raw JSON</div>
      <pre class="details-pre" id="details-raw" style="display:none">${escapeHtml(rawJson)}</pre>
    </div>
  `;
}

function formatEventName(event) {
  const map = {
    'call_started': 'Call Start',
    'call_ended': 'Call End',
    'threat_update': 'Threat Update',
    'url_detected': 'Link Detected',
    'user_report': 'User Report',
    'user_action': 'User Action'
  };
  return map[event] || (event ? String(event).replace(/_/g, ' ') : 'Event');
}

function buildFallbackExplanation(log) {
  if (!log || !Array.isArray(log.reasons) || log.reasons.length === 0) return '';
  return `Call summary: ${log.reasons.join(', ')}.`;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(String(text ?? ''));
    return true;
  } catch (e) {
    try {
      const ta = document.createElement('textarea');
      ta.value = String(text ?? '');
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch (e2) {
      return false;
    }
  }
}

function showDetailsToast(message) {
  const toast = document.getElementById('details-toast');
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add('show');

  if (detailsToastTimer) clearTimeout(detailsToastTimer);
  detailsToastTimer = setTimeout(() => {
    toast.classList.remove('show');
  }, 1600);
}

// ─── Chart Fallbacks (No Chart.js) ───────────────────────────────────────────
function initFallbackCharts() {
  // Daily bars
  const dailyCanvas = document.getElementById('chart-daily');
  if (dailyCanvas && !fallbackDailyEl) {
    dailyCanvas.style.display = 'none';
    fallbackDailyEl = document.createElement('div');
    fallbackDailyEl.className = 'fb-bars';
    dailyCanvas.parentElement?.appendChild(fallbackDailyEl);
  }

  // Donuts
  if (!fallbackCats) fallbackCats = ensureFallbackDonut('chart-categories', 'cats');
  if (!fallbackPlatform) fallbackPlatform = ensureFallbackDonut('chart-platforms', 'platforms');
}

function ensureFallbackDonut(canvasId, prefix) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return null;

  const body = canvas.parentElement;
  if (!body) return null;

  canvas.style.display = 'none';

  const existing = body.querySelector(`.fb-donut-wrap[data-prefix=\"${prefix}\"]`);
  if (existing) {
    return {
      donut: existing.querySelector('.fb-donut'),
      legend: existing.querySelector('.fb-legend')
    };
  }

  const wrap = document.createElement('div');
  wrap.className = 'fb-donut-wrap';
  wrap.dataset.prefix = prefix;
  wrap.innerHTML = `<div class="fb-donut"></div><div class="fb-legend"></div>`;
  body.appendChild(wrap);

  return {
    donut: wrap.querySelector('.fb-donut'),
    legend: wrap.querySelector('.fb-legend')
  };
}

function updateFallbackDaily(dailyCalls, dailyThreats) {
  if (!fallbackDailyEl) return;

  const keys = Object.keys(dailyCalls || dailyThreats || {});
  if (keys.length === 0) {
    const now = Date.now();
    for (let i = 6; i >= 0; i--) {
      keys.push(new Date(now - i * 86400000).toISOString().split('T')[0]);
    }
  } else {
    keys.sort();
  }

  const callVals = keys.map((k) => dailyCalls?.[k] ?? 0);
  const threatVals = keys.map((k) => dailyThreats?.[k] ?? 0);
  const max = Math.max(1, ...callVals, ...threatVals);

  fallbackDailyEl.innerHTML = keys.map((k, idx) => {
    const calls = callVals[idx];
    const threats = threatVals[idx];
    const callsPct = Math.round((calls / max) * 100);
    const threatsPct = Math.round((threats / max) * 100);

    const d = new Date(k);
    const label = d.toLocaleDateString('en-IN', { weekday: 'short', day: 'numeric' });
    const valueText = threats > 0 ? `${calls}/${threats}` : `${calls}`;
    const title = `${d.toLocaleDateString('en-IN', { weekday: 'short', month: 'short', day: 'numeric' })} • Calls: ${calls} • Threats: ${threats}`;

    return `<div class="fb-bar" title="${escapeHtml(title)}">
      <div class="fb-stack">
        <div class="fb-fill-calls" style="height:${callsPct}%"></div>
        <div class="fb-fill-threats" style="height:${threatsPct}%"></div>
      </div>
      <div class="fb-value">${escapeHtml(valueText)}</div>
      <div class="fb-label">${escapeHtml(label)}</div>
    </div>`;
  }).join('');
}

function updateFallbackDonut(target, entriesObj, opts) {
  if (!target?.donut || !target?.legend) return;

  const pairs = Object.entries(entriesObj || {})
    .filter(([, v]) => (v || 0) > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  const total = pairs.reduce((s, [, v]) => s + v, 0);
  if (total <= 0) {
    target.donut.style.background = `conic-gradient(rgba(255,255,255,0.06) 0% 100%)`;
    target.legend.innerHTML = `<div class="empty-state" style="padding:18px 10px">No data yet.</div>`;
    return;
  }

  let acc = 0;
  const segs = pairs.map(([label, value], i) => {
    const metaColor = opts?.showIcons ? CATEGORY_LABELS[label]?.color : null;
    const color = metaColor || CHART_COLORS[i % CHART_COLORS.length];
    const start = ((acc / total) * 100).toFixed(2);
    acc += value;
    const end = ((acc / total) * 100).toFixed(2);
    return `${color} ${start}% ${end}%`;
  });

  target.donut.style.background = `conic-gradient(${segs.join(', ')})`;

  target.legend.innerHTML = pairs.map(([label, value], i) => {
    const icon = opts?.showIcons ? (CATEGORY_LABELS[label]?.icon || '') : '';
    const metaColor = opts?.showIcons ? CATEGORY_LABELS[label]?.color : null;
    const color = metaColor || CHART_COLORS[i % CHART_COLORS.length];
    return `<div class="fb-legend-item">
      <span class="fb-legend-swatch" style="background:${color}"></span>
      <span class="fb-legend-label">${icon ? `${icon} ` : ''}${escapeHtml(label)}</span>
      <span class="fb-legend-count">${value}</span>
    </div>`;
  }).join('');
}

// ─── Threat Map ──────────────────────────────────────────────────────────────
function renderThreatMap(logs) {
  const heatmapEl = document.getElementById('threat-heatmap');
  const hotspotsEl = document.getElementById('threat-hotspots');
  if (!heatmapEl || !hotspotsEl) return;

  const rows = Array.isArray(logs) ? logs : [];
  const reasons = Object.keys(CATEGORY_LABELS);

  const platformSet = new Set();
  let hasUnknown = false;
  rows.forEach((l) => {
    if (l?.platform) platformSet.add(l.platform);
    if (!l?.platform && Array.isArray(l?.reasons) && l.reasons.length > 0) hasUnknown = true;
  });

  const platforms = [
    ...KNOWN_PLATFORMS.filter((p) => platformSet.has(p)),
    ...Array.from(platformSet).filter((p) => !KNOWN_PLATFORMS.includes(p)).sort()
  ];
  if (hasUnknown) platforms.push('Unknown');
  if (platforms.length === 0) platforms.push('Unknown');

  const matrix = {};
  platforms.forEach((p) => {
    matrix[p] = {};
    reasons.forEach((r) => (matrix[p][r] = 0));
  });

  rows.forEach((l) => {
    const p = l?.platform || 'Unknown';
    if (!matrix[p]) return;
    (l?.reasons || []).forEach((r) => {
      if (matrix[p][r] !== undefined) matrix[p][r] += 1;
    });
  });

  let max = 0;
  platforms.forEach((p) => reasons.forEach((r) => { max = Math.max(max, matrix[p][r]); }));

  if (max === 0) {
    heatmapEl.innerHTML = `<div class="empty-state" style="padding:24px 16px">
      No threat signals yet.<br><span>Join a call and generate a few keyword hits (urgency/OTP/link) to populate this map.</span>
    </div>`;
    hotspotsEl.innerHTML = `<div class="empty-state" style="padding:24px 16px">No hotspots yet.</div>`;
    return;
  }

  const cols = reasons.length + 1;
  let html = `<div class="heatmap-grid" style="--cols:${cols}">`;

  html += `<div class="hm-cell hm-head"></div>`;
  reasons.forEach((r) => {
    const meta = CATEGORY_LABELS[r] || {};
    const short = shortReasonLabel(r);
    html += `<div class="hm-cell hm-head" title="${escapeHtml(r)}">${meta.icon ? `${meta.icon} ` : ''}${escapeHtml(short)}</div>`;
  });

  platforms.forEach((p) => {
    html += `<div class="hm-cell hm-rowhead" title="${escapeHtml(p)}">${escapeHtml(p)}</div>`;
    reasons.forEach((r) => {
      const count = matrix[p][r] || 0;
      const meta = CATEGORY_LABELS[r] || {};
      const color = meta.color || '#6366f1';
      const alpha = count > 0 ? (0.10 + (count / max) * 0.55) : 0.02;
      const bg = hexToRgba(color, alpha);
      const border = hexToRgba(color, count > 0 ? 0.28 : 0.08);
      const title = `${p} • ${r}: ${count}`;
      html += `<div class="hm-cell" style="background:${bg};border-color:${border}" title="${escapeHtml(title)}"><strong>${count}</strong></div>`;
    });
  });

  html += `</div>`;
  heatmapEl.innerHTML = html;

  const combos = [];
  platforms.forEach((p) => {
    reasons.forEach((r) => {
      const count = matrix[p][r] || 0;
      if (count <= 0) return;
      combos.push({
        platform: p,
        reason: r,
        count,
        color: CATEGORY_LABELS[r]?.color || '#6366f1',
        icon: CATEGORY_LABELS[r]?.icon || ''
      });
    });
  });
  combos.sort((a, b) => b.count - a.count);

  hotspotsEl.innerHTML = combos.slice(0, 8).map((c) => {
    const label = `${c.platform} · ${c.reason}`;
    return `<div class="hotspot-item" title="${escapeHtml(label)}">
      <span class="hotspot-dot" style="background:${c.color}"></span>
      <span class="hotspot-label">${c.icon ? `${c.icon} ` : ''}${escapeHtml(label)}</span>
      <span class="hotspot-count">${c.count}</span>
    </div>`;
  }).join('');
}

function shortReasonLabel(reason) {
  switch (reason) {
    case 'Urgency Language': return 'Urgency';
    case 'Authority Impersonation': return 'Authority';
    case 'Financial Request': return 'Financial';
    case 'Fear/Threat Framing': return 'Fear/Threat';
    case 'Link/Screen-Share Request': return 'Link/Share';
    case 'Synthetic Voice Detected': return 'Synthetic';
    case 'Audio Waveform Anomaly': return 'Waveform';
    default: return reason;
  }
}

function hexToRgba(hex, alpha) {
  const safe = typeof hex === 'string' ? hex.trim() : '';
  const raw = safe.startsWith('#') ? safe.slice(1) : safe;
  const h = raw.length === 3 ? raw.split('').map((c) => c + c).join('') : raw;
  if (h.length !== 6) return `rgba(99,102,241,${alpha})`;
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha})`;
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

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.filter;
    renderFeed();
  });
});

// ─── Clear Logs ───────────────────────────────────────────────────────────────
async function clearLogs() {
  if (!confirm('Clear all stored logs? This cannot be undone.')) return;
  try {
    if (IS_EXTENSION) {
      await new Promise((resolve) => chrome.storage.local.set({ lcf_logs: [] }, resolve));
    } else {
      await fetch('/api/logs', { method: 'DELETE' });
    }
    allLogs = [];
    closeDetails();
    renderFeed();
    document.getElementById('total-log-count').textContent = 0;
    document.getElementById('live-count').textContent = 0;
    renderThreatMap([]);
    const empty = computeAnalyticsFromLogs([]);
    updateKPIs(empty);
    updateCharts(empty);
  } catch(e) {}
}

// ─── Clock ────────────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById('current-time').textContent =
    new Date().toLocaleString('en-IN', {
      weekday: 'short', year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    });
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  initCharts();
  initNavigation();
  initDetailsDrawer();
  initFeedInteractions();
  updateServerStatus();
  updateClock();
  setInterval(updateClock, 1000);
  setInterval(updateServerStatus, 10000);

  if (false && IS_EXTENSION && !window.Chart) {
    document.querySelectorAll('.chart-body').forEach((el) => {
      el.innerHTML = `<div class="empty-state">
        🧩 Charts are disabled in the built-in dashboard.<br>
        <span>To enable charts, start the server: <code>cd server && npm start</code> then open <code>http://localhost:3000</code></span>
      </div>`;
    });
  }

  document.getElementById('btn-clear-logs')?.addEventListener('click', clearLogs);

  // Initial data load
  await fetchLogs();
  await fetchAnalytics();

  // Poll for new data every 3 seconds
  setInterval(async () => {
    await fetchLogs();
    await fetchAnalytics();
  }, 3000);
});
