/**
 * Live Call Firewall — Dashboard Server
 * Lightweight Express server that:
 * - Receives threat logs from the extension (POST /api/log)  
 * - Serves the cybersecurity dashboard (GET /)
 * - Provides log history API (GET /api/logs)
 */

const express = require('express');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');

const app     = express();
const PORT    = 3000;
const LOG_FILE = path.join(__dirname, 'logs.json');

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

// ─── In-Memory Log Store ──────────────────────────────────────────────────────
let logs = [];

// Load existing logs from file on startup
if (fs.existsSync(LOG_FILE)) {
  try {
    const raw = fs.readFileSync(LOG_FILE, 'utf8');
    logs = JSON.parse(raw);
    console.log(`[LCF Server] Loaded ${logs.length} existing log entries`);
  } catch (e) {
    logs = [];
  }
}

function persistLogs() {
  fs.writeFileSync(LOG_FILE, JSON.stringify(logs.slice(-2000), null, 2));
}

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', logCount: logs.length, uptime: process.uptime() });
});

// ─── Receive Log from Extension ───────────────────────────────────────────────
app.post('/api/log', (req, res) => {
  const entry = {
    id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
    received_at: new Date().toISOString(),
    ...req.body
  };

  logs.push(entry);

  // Keep latest 2000 entries
  if (logs.length > 2000) logs.splice(0, logs.length - 2000);

  // Persist async
  setImmediate(persistLogs);

  console.log(`[LCF] [${entry.event?.toUpperCase() || 'LOG'}] Score: ${entry.score || '-'} | ${entry.label || ''}`);

  res.json({ ok: true, id: entry.id });
});

// ─── Get All Logs ─────────────────────────────────────────────────────────────
app.get('/api/logs', (req, res) => {
  const limit  = parseInt(req.query.limit || '100');
  const offset = parseInt(req.query.offset || '0');
  const event  = req.query.event; // Filter by event type

  let filtered = logs;
  if (event) filtered = logs.filter(l => l.event === event);

  res.json({
    total: filtered.length,
    entries: filtered.slice(-limit - offset, filtered.length - offset).reverse()
  });
});

// ─── Analytics Summary ────────────────────────────────────────────────────────
app.get('/api/analytics', (req, res) => {
  const calls = logs.filter(l => l.event === 'call_ended');
  const threats = logs.filter(l => l.event === 'threat_update' && l.score > 0);

  // Daily buckets (last 7 days)
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

  // Reason frequency
  const reasonCounts = {};
  logs.forEach(l => {
    (l.reasons || []).forEach(r => {
      reasonCounts[r] = (reasonCounts[r] || 0) + 1;
    });
  });

  // Platform breakdown
  const platforms = {};
  calls.forEach(c => {
    if (c.platform) platforms[c.platform] = (platforms[c.platform] || 0) + 1;
  });

  res.json({
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
  });
});

// ─── Clear Logs ───────────────────────────────────────────────────────────────
app.delete('/api/logs', (req, res) => {
  logs = [];
  persistLogs();
  res.json({ ok: true, message: 'Logs cleared' });
});

// ─── Serve Dashboard Static Files ─────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '..', 'dashboard')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'dashboard', 'index.html'));
});

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡  Live Call Firewall Dashboard`);
  console.log(`   → http://localhost:${PORT}\n`);
  console.log(`   API Endpoints:`);
  console.log(`   POST /api/log      — Receive extension events`);
  console.log(`   GET  /api/logs     — Retrieve log history`);
  console.log(`   GET  /api/analytics — Analytics summary`);
  console.log(`   GET  /health       — Health check\n`);
});
