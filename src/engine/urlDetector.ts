/**
 * URL Threat Detection Client-Side Edge Detection Engine
 * Matches Python research model with redirect resolution, URL canonicalization,
 * and advanced lexical/structural/obfuscation feature extraction.
 */

import type { RedirectResolutionResult } from '../server/urlResolver';

export interface BrandEntry {
  name: string;
  domains: string[];
  aliases: string[];
  category: string;
}

export const KNOWN_BRANDS: BrandEntry[] = [
  {
    name: "Google",
    domains: ["google.com", "google.co.uk", "google.co.in", "accounts.google.com", "youtube.com"],
    aliases: ["google", "googl", "gmail", "googledrive", "youtube"],
    category: "Technology & Identity"
  },
  {
    name: "PayPal",
    domains: ["paypal.com", "paypal.me"],
    aliases: ["paypal", "pay-pal", "paypa1"],
    category: "Financial Services"
  },
  {
    name: "Microsoft",
    domains: ["microsoft.com", "live.com", "office.com", "outlook.com", "login.microsoftonline.com", "github.com"],
    aliases: ["microsoft", "office365", "outlook", "msft", "onedrive"],
    category: "Enterprise & Cloud"
  },
  {
    name: "Apple",
    domains: ["apple.com", "icloud.com", "appleid.apple.com"],
    aliases: ["apple", "icloud", "appleid", "itunes"],
    category: "Consumer Technology"
  },
  {
    name: "Amazon",
    domains: ["amazon.com", "amazon.co.uk", "amazon.in", "aws.amazon.com"],
    aliases: ["amazon", "primevideo", "amazn"],
    category: "E-Commerce"
  },
  {
    name: "Facebook / Meta",
    domains: ["facebook.com", "meta.com", "instagram.com", "whatsapp.com"],
    aliases: ["facebook", "faceb00k", "instagram", "whatsapp"],
    category: "Social Media"
  },
  {
    name: "Netflix",
    domains: ["netflix.com"],
    aliases: ["netflix", "netflx", "netf1ix"],
    category: "Streaming Entertainment"
  },
  {
    name: "Chase",
    domains: ["chase.com"],
    aliases: ["chase", "chasebank"],
    category: "Banking"
  },
  {
    name: "Bank of America",
    domains: ["bankofamerica.com", "bofa.com"],
    aliases: ["bankofamerica", "bofa"],
    category: "Banking"
  },
  {
    name: "Coinbase",
    domains: ["coinbase.com"],
    aliases: ["coinbase", "c0inbase"],
    category: "Cryptocurrency"
  }
];

export const SUSPICIOUS_KEYWORDS = [
  "login", "signin", "verify", "secure", "account", "banking", "update",
  "password", "credential", "auth", "confirm", "wallet", "support", "kyc",
  "free", "gift", "airdrop", "claim", "billing", "recover"
];

export const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "club", "info", "cc", "pw", "work", "loan", "site", "online",
  "vip", "click", "rest", "buzz", "gq", "ml", "cf", "tk", "ga"
]);

export const KNOWN_SHORTENERS = new Set([
  "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
  "is.gd", "v.gd", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "adf.ly",
  "rb.gy", "lnkd.in", "youtu.be", "amzn.to", "fb.me", "g.co", "aka.ms", "s.id",
  "clck.ru", "x.co", "short.io", "bl.ink", "t.ly", "dub.sh", "shrtco.de",
  "qr.ae", "mcaf.ee", "tr.im", "wp.me", "po.st", "urlz.fr", "tiny.one",
  "soo.gd", "surl.li", "u.to", "zpr.io", "t2m.io", "short.gy", "bc.vc",
  "ouo.io", "gestyy.com", "linktr.ee", "l.facebook.com", "l.instagram.com",
  "lm.facebook.com", "j.mp", "q.gs", "url.ie"
]);

const TRACKING_QUERY_PARAMS = new Set([
  "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
  "utm_id", "fbclid", "gclid", "mc_cid", "mc_eid", "si", "_hsenc", "_hsmi",
  "ref_src", "ref_url"
]);

const REDIRECT_PARAM_NAMES = new Set([
  "url", "redirect", "redirect_url", "redirect_uri", "dest", "destination",
  "target", "link", "next", "return", "return_url", "goto", "continue", "u", "q"
]);

const PHISHING_NGRAM_TOKENS = [
  "-login", "login-", "-verify", "verify-", "-secure", "secure-", "auth-",
  "-auth", "account-", "-account", "update-", "-update", ".com-", ".net-",
  "support-", "webscr", "signin-", "-signin", "cmd=", "session="
];

const OFFICIAL_MAJOR_DOMAINS = [
  "google.com", "github.com", "wikipedia.org", "python.org", "mozilla.org",
  "amazon.com", "amazon.in", "apple.com", "microsoft.com", "paypal.com",
  "youtube.com", "linkedin.com", "stackoverflow.com", "cloudflare.com",
  "vercel.com", "npmjs.com", "adobe.com", "dropbox.com", "zoom.us",
  "slack.com", "stripe.com", "shopify.com", "openai.com", "bbc.com",
  "nytimes.com", "arxiv.org", "ieee.org", "acm.org"
];

export const CONFUSABLE_MAP: Record<string, string> = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
  'α': 'a', 'β': 'b', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't', 'ω': 'w'
};

export function calculateEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 10000) / 10000;
}

export function isKnownShortenerHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^www\./, "");
  if (KNOWN_SHORTENERS.has(host)) return true;
  for (const s of KNOWN_SHORTENERS) {
    if (host.endsWith(`.${s}`)) return true;
  }
  return false;
}

export function parseURL(url: string) {
  const clean = url.trim();
  const withScheme = clean.includes("://") ? clean : `http://${clean}`;
  try {
    const parsed = new URL(withScheme);
    return {
      hostname: parsed.hostname.toLowerCase(),
      pathname: parsed.pathname,
      search: parsed.search,
      port: parsed.port,
      username: parsed.username,
      raw: clean,
      protocol: parsed.protocol
    };
  } catch {
    const host = clean.split("/")[0].toLowerCase();
    return {
      hostname: host,
      pathname: "",
      search: "",
      port: "",
      username: "",
      raw: clean,
      protocol: "http:"
    };
  }
}

export function canonicalizeUrl(url: string): string {
  const clean = (url || "").trim();
  if (!clean) return "";
  const withScheme = clean.includes("://") ? clean : `http://${clean}`;
  try {
    const parsed = new URL(withScheme);
    parsed.hostname = parsed.hostname.toLowerCase();
    parsed.hash = "";
    if ((parsed.protocol === "http:" && parsed.port === "80") ||
        (parsed.protocol === "https:" && parsed.port === "443")) {
      parsed.port = "";
    }
    const filteredParams = new URLSearchParams();
    parsed.searchParams.forEach((value, key) => {
      if (!TRACKING_QUERY_PARAMS.has(key.toLowerCase())) {
        filteredParams.append(key, value);
      }
    });
    const qs = filteredParams.toString();
    parsed.search = qs ? `?${qs}` : "";
    let out = parsed.toString();
    if (parsed.pathname === "/" && !parsed.search && out.endsWith("/")) {
      out = out.slice(0, -1);
    }
    return out;
  } catch {
    return clean;
  }
}

export function extractEmbeddedRedirectTarget(url: string): string | null {
  const withScheme = url.includes("://") ? url.trim() : `http://${url.trim()}`;
  try {
    const parsed = new URL(withScheme);
    for (const [k, v] of parsed.searchParams.entries()) {
      if (!REDIRECT_PARAM_NAMES.has(k.toLowerCase())) continue;
      const trimmed = v.trim();
      if (/^https?:\/\//i.test(trimmed)) return trimmed;
      try {
        const decoded = decodeURIComponent(trimmed);
        if (/^https?:\/\//i.test(decoded)) return decoded;
      } catch { /* ignore */ }
      if (trimmed.length >= 12 && /^[A-Za-z0-9+/=_-]+$/.test(trimmed)) {
        try {
          const b64 = trimmed.replace(/-/g, "+").replace(/_/g, "/");
          const decodedB64 = atob(b64).trim();
          if (/^https?:\/\//i.test(decodedB64)) return decodedB64;
        } catch { /* ignore */ }
      }
    }
  } catch { /* ignore */ }
  return null;
}

export function isShortenerOrRedirectUrl(url: string): boolean {
  const parsed = parseURL(url);
  if (isKnownShortenerHost(parsed.hostname)) return true;
  if (extractEmbeddedRedirectTarget(url) !== null) return true;
  return false;
}

export async function resolveUrlViaApi(url: string): Promise<RedirectResolutionResult | null> {
  try {
    const res = await fetch('/api/resolve-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(6500)
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data as RedirectResolutionResult;
  } catch {
    return null;
  }
}

export function stringSimilarity(s1: string, s2: string): number {
  const longer = s1.length >= s2.length ? s1.toLowerCase() : s2.toLowerCase();
  const shorter = s1.length < s2.length ? s1.toLowerCase() : s2.toLowerCase();
  if (longer.length === 0) return 1.0;
  let matches = 0;
  for (let i = 0; i < shorter.length; i++) {
    if (longer.includes(shorter[i])) matches++;
  }
  return matches / longer.length;
}

export function detectBrandImpersonation(hostname: string, fullUrl: string) {
  const host = hostname.replace(/^www\./, "");
  const labels = host.split(".");
  const core = labels.length >= 2 ? labels[labels.length - 2] : labels[0];
  const coreTokens = [core, ...core.split("-"), ...core.split("_")];
  const urlLower = fullUrl.toLowerCase();

  for (const brand of KNOWN_BRANDS) {
    const isOfficial = brand.domains.some(d => host === d || host.endsWith(`.${d}`));
    if (isOfficial) continue;

    for (const alias of brand.aliases) {
      if (core.includes(alias)) {
        return { isImpersonating: true, brand: brand.name, similarity: 1.0 };
      }
      for (const tok of coreTokens) {
        const sim = stringSimilarity(alias, tok);
        if (sim >= 0.75) {
          return { isImpersonating: true, brand: brand.name, similarity: sim };
        }
      }
      const sub = labels.slice(0, Math.max(0, labels.length - 2)).join(".");
      if (sub.includes(alias)) {
        return { isImpersonating: true, brand: brand.name, similarity: 0.9 };
      }
      if (urlLower.includes(`/${alias}/`) || urlLower.includes(`/${alias}.`)) {
        return { isImpersonating: true, brand: brand.name, similarity: 0.85 };
      }
    }
  }

  return { isImpersonating: false, brand: null, similarity: 0.0 };
}

export interface DetectionResult {
  url: string;
  effective_url: string;
  classification: "legitimate" | "malicious" | "uncertain";
  risk_percentage: number;
  benign_percentage: number;
  prediction_confidence: "high" | "medium" | "low";
  conformal_prediction_set: string[];
  uncertainty_status: "low" | "medium" | "high";
  out_of_distribution: boolean;
  available_modalities: string[];
  top_reasons: { factor: string; text: string; severity: "critical" | "high" | "medium" | "low" | "safe" }[];
  redirect_info: RedirectResolutionResult | null;
  features: {
    url_length: number;
    hostname_length: number;
    entropy: number;
    max_path_token_entropy: number;
    num_keywords: number;
    num_subdomains: number;
    is_ip: boolean;
    is_punycode: boolean;
    homoglyphs_count: number;
    is_shortener: boolean;
    shortener_resolved: boolean;
    is_suspicious_tld: boolean;
    has_encoded_payload: boolean;
    consonant_cluster_anomaly: boolean;
    has_port_obfuscation: boolean;
    has_double_extension: boolean;
    has_userinfo_at: boolean;
    char_ngram_score: number;
    redirect_hop_count: number;
    cross_domain_redirects: number;
    protocol_downgrade: boolean;
    impersonated_brand: string | null;
  };
  model_version: string;
  timestamp: string;
}

function extractAdvancedFeatures(url: string, redirectInfo?: RedirectResolutionResult | null) {
  const parsed = parseURL(url);
  const host = parsed.hostname;
  const path = parsed.pathname || "";
  const query = parsed.search || "";
  const urlLower = url.toLowerCase();

  const segments = path.split("/").filter(Boolean);
  const segmentEntropies = segments.map(s => calculateEntropy(s));
  const maxPathTokenEntropy = segmentEntropies.length > 0 ? Math.max(...segmentEntropies) : 0;

  const pathQuery = `${path}${query}`;
  const hasHexBlob = /[0-9a-f]{24,}/i.test(pathQuery);
  const hasB64Blob = /(eyJ[A-Za-z0-9_-]{10,}|aHR0c[A-Za-z0-9_-]{8,}|[A-Za-z0-9+/]{28,}={1,2})/.test(pathQuery);
  const hasEncodedPayload = hasHexBlob || hasB64Blob;

  const hostLabels = host.split(".").filter(l => l && l !== "www");
  const coreDomain = hostLabels.length >= 2 ? hostLabels[hostLabels.length - 2] : (hostLabels[0] || "");
  const alphaChars = coreDomain.replace(/[^a-z]/g, "");
  const hasConsonantRun = /[bcdfghjklmnpqrstvwxyz]{5,}/.test(alphaChars);
  const vowelCount = (alphaChars.match(/[aeiou]/g) || []).length;
  const vowelRatio = alphaChars.length > 0 ? vowelCount / alphaChars.length : 0.4;
  const consonantClusterAnomaly = hasConsonantRun || (alphaChars.length >= 8 && vowelRatio < 0.15);

  const hasPortObfuscation = Boolean(parsed.port && parsed.port !== "80" && parsed.port !== "443");
  const hasUserinfoAt = Boolean(parsed.username) || url.split("/")[2]?.includes("@") || false;
  const hasDoubleExtension = /\.(com|net|org|pdf|doc|docx)\.(php|html|htm|exe|apk|zip|js)\b|\/(login|signin|verify|auth)\.(php|asp|aspx|jsp)\b/i.test(urlLower);

  const ngramHits = PHISHING_NGRAM_TOKENS.filter(tok => urlLower.includes(tok)).length;
  const charNgramScore = Math.min(1.0, ngramHits * 0.25);

  return {
    maxPathTokenEntropy: Math.round(maxPathTokenEntropy * 10000) / 10000,
    hasEncodedPayload,
    consonantClusterAnomaly,
    hasPortObfuscation,
    hasUserinfoAt,
    hasDoubleExtension,
    charNgramScore,
    redirectHopCount: redirectInfo?.hop_count ?? 0,
    crossDomainRedirects: redirectInfo?.cross_domain_redirects ?? 0,
    protocolDowngrade: Boolean(redirectInfo?.protocol_downgrade),
  };
}

export function analyzeUrlClient(
  url: string,
  messageText?: string,
  redirectInfo?: RedirectResolutionResult | null
): DetectionResult {
  const inputClean = url.trim();
  const inputParsed = parseURL(inputClean);
  const isInputShortener = isKnownShortenerHost(inputParsed.hostname);

  const embeddedTarget = extractEmbeddedRedirectTarget(inputClean);
  let effectiveRaw = inputClean;
  let shortenerResolved = false;

  if (redirectInfo && redirectInfo.resolved && redirectInfo.final_url) {
    effectiveRaw = redirectInfo.final_url;
    shortenerResolved = true;
  } else if (embeddedTarget) {
    effectiveRaw = embeddedTarget;
    shortenerResolved = true;
  }

  const effectiveCanonical = canonicalizeUrl(effectiveRaw) || effectiveRaw;
  const parsed = parseURL(effectiveCanonical);
  const host = parsed.hostname;
  const urlLower = effectiveCanonical.toLowerCase();

  // Base Features computed on effective canonical destination URL
  const urlLen = effectiveCanonical.length;
  const hostLen = host.length;
  const entropy = calculateEntropy(effectiveCanonical);
  const numKeywords = SUSPICIOUS_KEYWORDS.filter(k => urlLower.includes(k)).length;
  const labels = host.split(".").filter(Boolean);
  const numSubdomains = Math.max(0, labels.length - 2);
  const isIp = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(host);
  const isPunycode = host.includes("xn--");
  let homoglyphsCount = 0;
  for (const ch of host) {
    if (CONFUSABLE_MAP[ch]) homoglyphsCount++;
  }
  const tld = labels.length > 0 ? labels[labels.length - 1] : "";
  const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
  const isEffectiveShortener = isKnownShortenerHost(host);
  const brandCheck = detectBrandImpersonation(host, effectiveCanonical);
  const adv = extractAdvancedFeatures(effectiveCanonical, redirectInfo);

  // Calibrated Hybrid Scoring
  let baseScore = 0.02;
  if (brandCheck.isImpersonating) baseScore += 0.50;
  if (isIp) baseScore += 0.45;
  if (isPunycode || homoglyphsCount > 0) baseScore += 0.40;
  if (adv.hasUserinfoAt) baseScore += 0.35;
  if (isSuspiciousTld) baseScore += 0.28;
  if (adv.protocolDowngrade) baseScore += 0.24;
  if (adv.hasEncodedPayload) baseScore += 0.20;
  if (adv.hasDoubleExtension) baseScore += 0.18;
  if (adv.hasPortObfuscation) baseScore += 0.16;
  if (adv.consonantClusterAnomaly) baseScore += 0.16;
  if (adv.charNgramScore >= 0.25) baseScore += 0.22 * adv.charNgramScore;
  if (numKeywords >= 2) baseScore += 0.24;
  else if (numKeywords === 1 && (isSuspiciousTld || brandCheck.isImpersonating || adv.hasDoubleExtension)) baseScore += 0.12;
  if (numSubdomains >= 3) baseScore += 0.18;
  if (entropy >= 4.65) baseScore += 0.14;
  if (urlLen >= 135) baseScore += 0.08;
  if (adv.crossDomainRedirects >= 3 || adv.redirectHopCount >= 4) baseScore += 0.12;

  // Shortener resolution handling:
  // If shortener was resolved to final destination, evaluate destination directly;
  // If shortener could NOT be resolved, flag opaque/unverified destination risk.
  if ((isInputShortener || isEffectiveShortener) && !shortenerResolved) {
    baseScore = Math.max(baseScore + 0.28, 0.42);
  } else if (isInputShortener && shortenerResolved) {
    // Cleanly resolved shortener: keep tiny 0.01 transparency nudge only if destination had flags
    if (baseScore > 0.30) {
      baseScore = Math.min(0.99, baseScore + 0.03);
    }
  }

  // Verified official/authority domain check (on resolved destination host)
  const isOfficialMajor =
    OFFICIAL_MAJOR_DOMAINS.some(d => host === d || host.endsWith(`.${d}`)) ||
    tld === "edu" ||
    tld === "gov";

  if (
    isOfficialMajor &&
    !isPunycode &&
    homoglyphsCount === 0 &&
    !adv.hasUserinfoAt &&
    !adv.protocolDowngrade &&
    !embeddedTarget
  ) {
    baseScore = 0.01;
  }

  // Message context influence
  const modalities = ["url"];
  if (shortenerResolved) modalities.push("redirect_resolution");
  if (messageText && messageText.trim()) {
    modalities.push("message_context");
    const msgLower = messageText.toLowerCase();
    const hasUrgent = ["urgent", "immediately", "suspended", "locked", "expire"].some(w => msgLower.includes(w));
    const hasCred = ["password", "verify", "otp", "pin", "credentials"].some(w => msgLower.includes(w));
    const hasPrize = ["won", "winner", "prize", "refund", "claim"].some(w => msgLower.includes(w));
    if (hasUrgent || hasCred || hasPrize) {
      baseScore = Math.min(0.99, baseScore + 0.20);
    }
  }

  const calibratedRisk = Math.min(Math.max(baseScore, 0.01), 0.99);
  const riskPercentage = Math.round(calibratedRisk * 1000) / 10;
  const benignPercentage = Math.round((100 - riskPercentage) * 10) / 10;

  // Split Conformal Prediction Set (q_hat = 0.62)
  const qHat = 0.62;
  const conformalSet: string[] = [];
  if ((1.0 - benignPercentage / 100) <= qHat) conformalSet.push("legitimate");
  if ((1.0 - riskPercentage / 100) <= qHat) conformalSet.push("malicious");
  if (conformalSet.length === 0) {
    conformalSet.push(riskPercentage >= 50 ? "malicious" : "legitimate");
  }

  // Decision & Confidence
  let classification: "legitimate" | "malicious" | "uncertain" = "uncertain";
  let confidence: "high" | "medium" | "low" = "medium";
  let uncertaintyStatus: "low" | "medium" | "high" = "low";

  if (conformalSet.length > 1) {
    classification = "uncertain";
    uncertaintyStatus = "high";
    confidence = "low";
  } else if (conformalSet.includes("malicious") && riskPercentage >= 65.0) {
    classification = "malicious";
    uncertaintyStatus = "low";
    confidence = riskPercentage >= 80.0 ? "high" : "medium";
  } else if (conformalSet.includes("legitimate") && riskPercentage <= 35.0) {
    classification = "legitimate";
    uncertaintyStatus = "low";
    confidence = riskPercentage <= 15.0 ? "high" : "medium";
  } else {
    classification = "uncertain";
    uncertaintyStatus = "medium";
    confidence = "medium";
  }

  // Top Explainable Factors
  const topReasons: { factor: string; text: string; severity: "critical" | "high" | "medium" | "low" | "safe" }[] = [];

  if (shortenerResolved && isInputShortener && riskPercentage >= 65.0) {
    topReasons.push({
      factor: "shortener_malicious_target",
      text: `Masked Malicious Destination: Shortened URL redirected (${adv.redirectHopCount || 1} hop) to high-risk host '${host}'.`,
      severity: "critical"
    });
  }
  if (brandCheck.isImpersonating) {
    topReasons.push({
      factor: "brand_impersonation",
      text: `Potential Brand Impersonation: Domain closely mimics '${brandCheck.brand}' while registered on an unrelated third-party host.`,
      severity: "critical"
    });
  }
  if (adv.hasUserinfoAt) {
    topReasons.push({
      factor: "userinfo_masking",
      text: "Credential '@' Host Masking: URL embeds a userinfo prefix before '@' to disguise the actual target domain.",
      severity: "high"
    });
  }
  if (adv.protocolDowngrade) {
    topReasons.push({
      factor: "protocol_downgrade",
      text: "TLS Protocol Downgrade: Redirect chain transitioned from encrypted HTTPS to unencrypted HTTP.",
      severity: "high"
    });
  }
  if (isIp) {
    topReasons.push({
      factor: "ip_address",
      text: "Direct IP Hostname: Bypasses DNS resolution using a raw IP address, typical of illicit phishing infrastructure.",
      severity: "high"
    });
  }
  if (isPunycode || homoglyphsCount > 0) {
    topReasons.push({
      factor: "homoglyph",
      text: "Internationalized / Confusable Homoglyphs: Uses Cyrillic or Punycode character transformations to deceive users.",
      severity: "high"
    });
  }
  if (adv.hasEncodedPayload) {
    topReasons.push({
      factor: "encoded_payload",
      text: "Encoded Payload Blob: Path or query contains long Base64 or Hex encoded payloads typical of URL obfuscation.",
      severity: "high"
    });
  }
  if ((isInputShortener || isEffectiveShortener) && !shortenerResolved) {
    topReasons.push({
      factor: "unresolved_shortener",
      text: "Unresolved URL Shortener: Shortener domain conceals its true landing destination and could not be expanded.",
      severity: "medium"
    });
  }
  if (adv.hasDoubleExtension) {
    topReasons.push({
      factor: "double_extension",
      text: "Deceptive Script / Double Extension: Uses misleading multi-extension or credential-handler scripts in path.",
      severity: "medium"
    });
  }
  if (adv.hasPortObfuscation) {
    topReasons.push({
      factor: "port_obfuscation",
      text: `Non-Standard Port (${parsed.port}): Targets non-standard service port often used by transient phishing servers.`,
      severity: "medium"
    });
  }
  if (adv.consonantClusterAnomaly) {
    topReasons.push({
      factor: "dga_consonant_anomaly",
      text: "Algorithmic Domain Anomaly (DGA): Hostname contains abnormal consonant sequences indicative of generated domains.",
      severity: "medium"
    });
  }
  if (isSuspiciousTld) {
    topReasons.push({
      factor: "suspicious_tld",
      text: `High-Risk TLD (.${tld}): Domain registered under a top-level domain frequently utilized in mass phishing campaigns.`,
      severity: "medium"
    });
  }
  if (numKeywords >= 2) {
    topReasons.push({
      factor: "keywords",
      text: `Targeted Security Tokens: URL contains ${numKeywords} sensitive keywords ('login', 'verify', 'update').`,
      severity: "medium"
    });
  }
  if (entropy >= 4.65) {
    topReasons.push({
      factor: "entropy",
      text: `Elevated Shannon Entropy (${entropy}): High algorithmic randomness across path and query segments.`,
      severity: "low"
    });
  }

  if (riskPercentage < 35.0) {
    if (shortenerResolved && isInputShortener) {
      topReasons.push({
        factor: "resolved_safe_target",
        text: `Resolved Shortener Destination: Unshortened via ${adv.redirectHopCount || 1} hop(s) to verified host '${host}'.`,
        severity: "safe"
      });
    }
    topReasons.push({
      factor: "clean_domain",
      text: "Standard Domain Structure: Registered with authorized hierarchical depth and legitimate domain identity.",
      severity: "safe"
    });
    topReasons.push({
      factor: "no_obfuscation",
      text: "No Obfuscation Detected: Free of homoglyphic replacements, punycode prefixes, and malicious redirects.",
      severity: "safe"
    });
  }

  return {
    url: inputClean,
    effective_url: effectiveCanonical,
    classification,
    risk_percentage: riskPercentage,
    benign_percentage: benignPercentage,
    prediction_confidence: confidence,
    conformal_prediction_set: conformalSet,
    uncertainty_status: uncertaintyStatus,
    out_of_distribution: urlLen > 250 || entropy > 5.5 || ((isInputShortener || isEffectiveShortener) && !shortenerResolved),
    available_modalities: modalities,
    top_reasons: topReasons.slice(0, 4),
    redirect_info: redirectInfo || null,
    features: {
      url_length: urlLen,
      hostname_length: hostLen,
      entropy,
      max_path_token_entropy: adv.maxPathTokenEntropy,
      num_keywords: numKeywords,
      num_subdomains: numSubdomains,
      is_ip: isIp,
      is_punycode: isPunycode,
      homoglyphs_count: homoglyphsCount,
      is_shortener: isInputShortener || isEffectiveShortener,
      shortener_resolved: shortenerResolved,
      is_suspicious_tld: isSuspiciousTld,
      has_encoded_payload: adv.hasEncodedPayload,
      consonant_cluster_anomaly: adv.consonantClusterAnomaly,
      has_port_obfuscation: adv.hasPortObfuscation,
      has_double_extension: adv.hasDoubleExtension,
      has_userinfo_at: adv.hasUserinfoAt,
      char_ngram_score: adv.charNgramScore,
      redirect_hop_count: adv.redirectHopCount,
      cross_domain_redirects: adv.crossDomainRedirects,
      protocol_downgrade: adv.protocolDowngrade,
      impersonated_brand: brandCheck.brand
    },
    model_version: "1.1.0",
    timestamp: new Date().toISOString()
  };
}
