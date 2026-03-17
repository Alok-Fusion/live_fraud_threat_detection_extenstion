/**
 * Live Call Firewall — Text / Behaviour Analyzer
 * Analyses real-time speech transcript for scam behaviour signals.
 */

// ─── Keyword Dictionaries ────────────────────────────────────────────────────
const SIGNAL_PATTERNS = {
  urgency: {
    weight: 25,
    keywords: [
      "immediately", "right now", "urgent", "hurry", "last chance",
      "within 24 hours", "don't delay", "act now", "time is running out",
      "expires today", "final warning", "limited time", "as soon as possible",
      "do it now", "emergency", "quickly", "no time to waste"
    ]
  },
  authority: {
    weight: 30,
    keywords: [
      "rbi", "reserve bank", "income tax", "it department", "police",
      "cyber crime", "court", "judge", "government", "ministry",
      "bank officer", "senior official", "compliance team", "legal notice",
      "enforcement directorate", "ed office", "cbi", "narcotics",
      "interpol", "investigation", "warrant", "officer speaking"
    ]
  },
  financial: {
    weight: 35,
    keywords: [
      "otp", "pin", "password", "account number", "transfer money",
      "send payment", "upi id", "bank details", "credit card",
      "debit card", "cvv", "wallet", "cryptocurrency", "bitcoin",
      "gift card", "voucher code", "fund transfer", "pay now",
      "refund process", "verification fee", "processing charge"
    ]
  },
  fear: {
    weight: 20,
    keywords: [
      "arrest", "arrested", "prison", "jail", "illegal activity",
      "suspend", "block", "freeze", "legal action", "case filed",
      "fir", "complaint", "criminal charge", "money laundering",
      "drug trafficking", "fraud detected", "your account blocked",
      "suspended account", "penalty", "fine imposed"
    ]
  },
  linkShare: {
    weight: 20,
    keywords: [
      "click the link", "open this link", "download this app",
      "install this", "share your screen", "screen share",
      "anydesk", "teamviewer", "remote access", "give me access",
      "i'll connect to your computer", "type this url",
      "visit this website", "follow this link"
    ]
  }
};

// ─── Transcript Analyser ─────────────────────────────────────────────────────
class TextAnalyzer {
  constructor() {
    this.transcript = [];
    this.hitCounts = {
      urgency: 0, authority: 0, financial: 0, fear: 0, linkShare: 0
    };
    this.recentHits = new Set(); // Avoid double-counting repeated phrases
    this.recognition = null;
    this.isListening = false;
    this.onUpdate = null; // Callback when new score is ready
  }

  // Calculate behaviour score from hit counts
  computeBehaviourScore() {
    let totalScore = 0;

    for (const [category, data] of Object.entries(SIGNAL_PATTERNS)) {
      const hits = this.hitCounts[category] || 0;
      // Diminishing returns: first hit counts full, subsequent hits count less
      const categoryScore = Math.min(100, hits * data.weight * (1 + Math.log1p(hits - 1) * 0.3));
      totalScore += categoryScore * (data.weight / 130); // Normalize weights (sum=130)
    }

    return {
      score: Math.round(Math.min(100, totalScore)),
      details: {
        urgencyHits: this.hitCounts.urgency,
        authorityHits: this.hitCounts.authority,
        financialHits: this.hitCounts.financial,
        fearHits: this.hitCounts.fear,
        linkShareHits: this.hitCounts.linkShare
      }
    };
  }

  // Process a new transcript line
  processText(text) {
    if (!text || text.trim().length === 0) return;
    const lowerText = text.toLowerCase();
    this.transcript.push({ time: Date.now(), text: lowerText });

    let newHit = false;

    for (const [category, data] of Object.entries(SIGNAL_PATTERNS)) {
      for (const keyword of data.keywords) {
        const hitKey = `${category}:${keyword}`;
        if (lowerText.includes(keyword) && !this.recentHits.has(hitKey)) {
          this.hitCounts[category]++;
          this.recentHits.add(hitKey);
          newHit = true;

          // Allow re-detection after 30 seconds
          setTimeout(() => this.recentHits.delete(hitKey), 30000);
        }
      }
    }

    if (newHit && this.onUpdate) {
      this.onUpdate(this.computeBehaviourScore());
    }
  }

  // Start live speech recognition
  startRecognition(stream) {
    if (!('webkitSpeechRecognition' in window) && !('SpeechRecognition' in window)) {
      console.warn("[LCF] SpeechRecognition not supported in this browser.");
      return;
    }

    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    this.recognition = new SpeechRecognition();
    this.recognition.continuous = true;
    this.recognition.interimResults = true;
    this.recognition.lang = 'en-IN'; // Optimized for Indian English accent

    this.recognition.onresult = (event) => {
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const transcript = event.results[i][0].transcript;
        if (event.results[i].isFinal) {
          this.processText(transcript);
        }
      }
    };

    this.recognition.onerror = (err) => {
      console.warn("[LCF] SpeechRecognition error:", err.error);
      if (err.error !== 'no-speech') {
        setTimeout(() => this.restartRecognition(), 2000);
      }
    };

    this.recognition.onend = () => {
      if (this.isListening) {
        setTimeout(() => this.restartRecognition(), 1000);
      }
    };

    this.isListening = true;
    this.recognition.start();
    console.log("[LCF] 🎙 Speech recognition started");
  }

  restartRecognition() {
    if (this.isListening && this.recognition) {
      try { this.recognition.start(); } catch(e) {}
    }
  }

  stopRecognition() {
    this.isListening = false;
    if (this.recognition) {
      this.recognition.stop();
      this.recognition = null;
    }
  }

  reset() {
    this.hitCounts = { urgency: 0, authority: 0, financial: 0, fear: 0, linkShare: 0 };
    this.transcript = [];
    this.recentHits.clear();
  }

  getTranscriptSummary() {
    return this.transcript.slice(-20).map(t => t.text).join(' ');
  }
}
