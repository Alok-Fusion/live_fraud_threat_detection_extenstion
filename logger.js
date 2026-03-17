/**
 * Live Call Firewall — Event Logger
 * Sends structured call events to the cybersecurity web dashboard.
 */

const DASHBOARD_URL = 'http://localhost:3000/api/log';

class Logger {
  constructor() {
    this.queue = [];
    this.isOnline = false;
    this.checkInterval = null;
    this.checkDashboardConnection();
  }

  async checkDashboardConnection() {
    try {
      const res = await fetch('http://localhost:3000/health', { method: 'GET' });
      this.isOnline = res.ok;
    } catch {
      this.isOnline = false;
    }

    // Retry queued logs if dashboard just came online
    if (this.isOnline && this.queue.length > 0) {
      this.flushQueue();
    }

    // Check every 30 seconds
    setTimeout(() => this.checkDashboardConnection(), 30000);
  }

  async log(payload) {
    const entry = {
      ...payload,
      id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
      logged_at: new Date().toISOString()
    };

    if (this.isOnline) {
      await this.send(entry);
    } else {
      this.queue.push(entry);
      // Persist to chrome.storage.local as backup
      chrome.storage.local.get(['lcf_logs'], (result) => {
        const logs = result.lcf_logs || [];
        logs.push(entry);
        // Keep last 500 entries
        if (logs.length > 500) logs.splice(0, logs.length - 500);
        chrome.storage.local.set({ lcf_logs: logs });
      });
    }
  }

  async send(entry) {
    try {
      const response = await fetch(DASHBOARD_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(entry),
        signal: AbortSignal.timeout(5000)
      });

      if (!response.ok) {
        this.queue.push(entry);
      }

      return response.ok;
    } catch (err) {
      this.isOnline = false;
      this.queue.push(entry);
      return false;
    }
  }

  async flushQueue() {
    const pending = [...this.queue];
    this.queue = [];

    for (const entry of pending) {
      const success = await this.send(entry);
      if (!success) break;
    }
  }

  // ─── Convenience Methods ───────────────────────────────────────────────────
  logCallStart(platform) {
    return this.log({ event: 'call_started', platform });
  }

  logThreatUpdate(threat, platform) {
    return this.log({
      event: 'threat_update',
      platform,
      score: threat.score,
      label: threat.label,
      confidence: threat.confidence,
      explanation: threat.explanation,
      breakdown: threat.breakdown
    });
  }

  logCallEnd(platform, peakScore, peakLabel, durationSeconds) {
    return this.log({
      event: 'call_ended',
      platform,
      peak_score: peakScore,
      peak_label: peakLabel,
      duration_seconds: durationSeconds
    });
  }

  logUserAction(action, context) {
    return this.log({ event: 'user_action', action, context });
  }

  // Get all locally stored logs
  getLocalLogs() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['lcf_logs'], (result) => {
        resolve(result.lcf_logs || []);
      });
    });
  }

  clearLocalLogs() {
    chrome.storage.local.remove('lcf_logs');
  }
}

// Export for use in background
if (typeof module !== 'undefined') {
  module.exports = { Logger };
}
