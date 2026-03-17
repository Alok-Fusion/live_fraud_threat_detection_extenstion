/**
 * Live Call Firewall — URL Analyzer (Heuristic)
 * Lightweight, offline URL risk scoring (no external API keys required).
 *
 * NOTE: This is heuristic-based. It can flag suspicious patterns but cannot
 * guarantee a URL is malicious. It is designed to reduce false negatives
 * while keeping false positives reasonable.
 */

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'click', 'link', 'live', 'info', 'icu', 'tk', 'ml', 'ga', 'cf', 'gq',
  'site', 'online', 'store', 'work', 'support', 'loan', 'download', 'zip', 'mov'
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rebrand.ly', 'buff.ly',
  'ow.ly', 's.id', 'shorturl.at', 'rb.gy', 'soo.gd', 'v.gd', 'lnkd.in'
]);

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'verification', 'update', 'secure', 'security', 'account',
  'bank', 'otp', 'kyc', 'refund', 'reward', 'prize', 'gift', 'upi', 'wallet',
  'payment', 'invoice', 'support', 'helpdesk', 'reset', 'password', 'pin'
];

// More conservative list for the hostname itself (to avoid flagging legitimate banks/accounts too easily).
const HOST_SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'verification', 'otp', 'kyc', 'refund', 'reward', 'prize', 'gift',
  'upi', 'wallet', 'payment', 'invoice', 'reset', 'password', 'pin'
];

const REDIRECT_PARAMS = ['redirect', 'url', 'next', 'target', 'dest', 'destination', 'continue', 'return'];

function unwrapKnownRedirectors(urlObj) {
  try {
    const host = String(urlObj.hostname || '').toLowerCase();
    const path = String(urlObj.pathname || '');

    // Google safe redirect wrapper: https://www.google.com/url?q=<dest>
    if ((host === 'www.google.com' || host === 'google.com') && path === '/url') {
      return urlObj.searchParams.get('q') || urlObj.searchParams.get('url');
    }

    // Facebook wrapper: https://l.facebook.com/l.php?u=<dest>
    if (host === 'l.facebook.com' && path === '/l.php') {
      return urlObj.searchParams.get('u');
    }

    return null;
  } catch {
    return null;
  }
}

function stripEdgePunctuation(value) {
  let v = String(value || '').trim();
  // Remove leading wrappers like "(" or "<" and trailing punctuation like ".)"
  v = v.replace(/^[<([{"'`]+/g, '');
  v = v.replace(/[>\])}",'`.?!;:]+$/g, '');
  return v.trim();
}

function looksLikeIp(hostname) {
  const h = String(hostname || '').trim();
  if (!h) return false;
  // IPv4 dotted quad
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
  // Very rough IPv6 check (URL API strips brackets in hostname)
  if (/^[0-9a-f:]+$/i.test(h) && h.includes(':')) return true;
  return false;
}

function getTld(hostname) {
  const parts = String(hostname || '').toLowerCase().split('.').filter(Boolean);
  if (parts.length < 2) return '';
  return parts[parts.length - 1];
}

function countSubdomainParts(hostname) {
  const parts = String(hostname || '').split('.').filter(Boolean);
  // example: a.b.c.example.com -> subdomain parts = 3 (a,b,c)
  if (parts.length <= 2) return 0;
  return parts.length - 2;
}

function normalizeUrl(input) {
  const raw = stripEdgePunctuation(input);
  if (!raw) return null;

  // Add scheme for common forms.
  let candidate = raw;
  if (/^www\./i.test(candidate)) candidate = `https://${candidate}`;

  // Handle shorteners typed without scheme: "bit.ly/abc"
  if (!/^https?:\/\//i.test(candidate)) {
    const maybeHost = candidate.split('/')[0]?.toLowerCase?.() || '';
    if (URL_SHORTENERS.has(maybeHost)) {
      candidate = `https://${candidate}`;
    } else if (!candidate.includes('@') && /^[a-z0-9.-]+\.[a-z]{2,}(?:[/:]|$)/i.test(candidate)) {
      // Common "example.com/path" form typed without a scheme.
      candidate = `https://${candidate}`;
    }
  }

  try {
    const u = new URL(candidate);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    // Drop URL fragments to reduce duplicates.
    u.hash = '';
    return u.toString();
  } catch {
    return null;
  }
}

function hasManyEncodedChars(url) {
  const s = String(url || '');
  const matches = s.match(/%[0-9a-f]{2}/gi) || [];
  if (s.length === 0) return false;
  return matches.length >= 6;
}

function countDigits(str) {
  const m = String(str || '').match(/\d/g);
  return m ? m.length : 0;
}

function countHyphens(str) {
  const m = String(str || '').match(/-/g);
  return m ? m.length : 0;
}

function includesSuspiciousKeyword(pathAndQuery) {
  const s = String(pathAndQuery || '').toLowerCase();
  return SUSPICIOUS_KEYWORDS.some((k) => s.includes(k));
}

function includesSuspiciousKeywordInHost(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h) return false;
  return HOST_SUSPICIOUS_KEYWORDS.some((k) => h.includes(k));
}

function includesRedirectParams(urlObj) {
  const params = urlObj.searchParams;
  return REDIRECT_PARAMS.some((k) => params.has(k));
}

function verdictFromScore(score) {
  if (score >= 80) return 'malicious';
  if (score >= 40) return 'suspicious';
  return 'safe';
}

/**
 * @param {string} inputUrl
 * @returns {{
 *   originalUrl: string,
 *   normalizedUrl: string|null,
 *   score: number,
 *   verdict: 'safe'|'suspicious'|'malicious'|'unknown',
 *   hostname: string|null,
 *   tld: string|null,
 *   reasons: string[],
 *   signals: Record<string, any>
 * }}
 */
function analyzeUrl(inputUrl) {
  const originalUrl = String(inputUrl || '').trim();
  let normalizedUrl = normalizeUrl(originalUrl);
  if (!normalizedUrl) {
    return {
      originalUrl,
      normalizedUrl: null,
      score: 0,
      verdict: 'unknown',
      hostname: null,
      tld: null,
      reasons: ['Unparseable or unsupported URL format'],
      signals: { parseFailed: true }
    };
  }

  let u = new URL(normalizedUrl);
  const wrapperHost = u.hostname || null;
  const wrapped = unwrapKnownRedirectors(u);
  if (wrapped) {
    const unwrapped = normalizeUrl(wrapped);
    if (unwrapped) {
      normalizedUrl = unwrapped;
      u = new URL(normalizedUrl);
    }
  }
  const hostname = (u.hostname || '').toLowerCase();
  const tld = getTld(hostname) || null;

  const signals = {
    wrappedBy: wrapped ? wrapperHost : null,
    isHttps: u.protocol === 'https:',
    isIpHost: looksLikeIp(hostname),
    hasPunycode: hostname.includes('xn--'),
    hasUserInfo: normalizedUrl.includes('@') && u.username.length > 0,
    isShortener: URL_SHORTENERS.has(hostname),
    tldSuspicious: tld ? SUSPICIOUS_TLDS.has(tld) : false,
    longUrl: normalizedUrl.length > 140,
    veryLongUrl: normalizedUrl.length > 220,
    manySubdomains: countSubdomainParts(hostname) >= 3,
    lotsOfDigits: countDigits(hostname) >= 6,
    manyHyphens: countHyphens(hostname) >= 4,
    encodedHeavy: hasManyEncodedChars(normalizedUrl),
    hasRedirectParam: includesRedirectParams(u),
    hasSuspiciousKeyword: includesSuspiciousKeyword(`${u.pathname}?${u.search}`),
    hostHasSuspiciousKeyword: includesSuspiciousKeywordInHost(hostname)
  };

  let score = 0;
  const reasons = [];

  if (!signals.isHttps) { score += 15; reasons.push('Non-HTTPS link'); }
  if (signals.isIpHost) { score += 25; reasons.push('IP address used as hostname'); }
  if (signals.hasPunycode) { score += 25; reasons.push('Punycode domain (possible lookalike)'); }
  if (signals.hasUserInfo) { score += 25; reasons.push('URL contains userinfo (@)'); }
  // Shorteners are common in scams because they hide the final destination.
  if (signals.isShortener) { score += 40; reasons.push('URL shortener hides destination'); }
  if (signals.tldSuspicious) { score += 15; reasons.push(`Uncommon/suspicious TLD (.${tld})`); }
  if (signals.veryLongUrl) { score += 18; reasons.push('Very long URL'); }
  else if (signals.longUrl) { score += 10; reasons.push('Long URL'); }
  if (signals.manySubdomains) { score += 10; reasons.push('Many subdomains'); }
  if (signals.lotsOfDigits) { score += 8; reasons.push('Many digits in domain'); }
  if (signals.manyHyphens) { score += 8; reasons.push('Many hyphens in domain'); }
  if (signals.encodedHeavy) { score += 10; reasons.push('Heavy URL encoding'); }
  if (signals.hasRedirectParam) { score += 10; reasons.push('Redirect parameter present'); }
  if (signals.hasSuspiciousKeyword) { score += 10; reasons.push('Phishing-like keywords in path/query'); }
  if (signals.hostHasSuspiciousKeyword) { score += 12; reasons.push('Phishing-like keyword in domain'); }

  // Combination boosts (common in scam links)
  if (signals.tldSuspicious && signals.hostHasSuspiciousKeyword) {
    score += 10;
    reasons.push('Suspicious TLD + phishing keyword combination');
  }
  if (signals.hostHasSuspiciousKeyword && signals.hasSuspiciousKeyword) {
    score += 8;
    reasons.push('Phishing keywords in domain and path/query');
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const verdict = verdictFromScore(score);

  return {
    originalUrl,
    normalizedUrl,
    score,
    verdict,
    hostname: hostname || null,
    tld,
    reasons: reasons.length ? reasons : ['No risky patterns detected'],
    signals
  };
}

export { analyzeUrl, normalizeUrl };
