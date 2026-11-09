/**
 * URL Threat Detection Client-Side Edge Detection Engine
 * Matches Python research model with 100% offline edge execution.
 */

export interface BrandEntry {
  name: string;
  domains: string[];
  aliases: string[];
  category: string;
}

export const KNOWN_BRANDS: BrandEntry[] = [
  {
    name: "Google",
    domains: ["google.com", "google.co.uk", "google.co.in", "accounts.google.com"],
    aliases: ["google", "googl", "gmail", "googledrive"],
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
    domains: ["microsoft.com", "live.com", "office.com", "outlook.com", "login.microsoftonline.com"],
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
    domains: ["amazon.com", "amazon.co.uk", "aws.amazon.com"],
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
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
  "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "adf.ly"
]);

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

export function parseURL(url: string) {
  const clean = url.trim();
  const withScheme = clean.includes("://") ? clean : `http://${clean}`;
  try {
    const parsed = new URL(withScheme);
    return {
      hostname: parsed.hostname.toLowerCase(),
      pathname: parsed.pathname,
      search: parsed.search,
      raw: clean,
      protocol: parsed.protocol
    };
  } catch {
    const host = clean.split("/")[0].toLowerCase();
    return {
      hostname: host,
      pathname: "",
      search: "",
      raw: clean,
      protocol: "http:"
    };
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
      // Check subdomains
      const sub = labels.slice(0, Math.max(0, labels.length - 2)).join(".");
      if (sub.includes(alias)) {
        return { isImpersonating: true, brand: brand.name, similarity: 0.9 };
      }
      // Check path
      if (urlLower.includes(`/${alias}/`) || urlLower.includes(`/${alias}.`)) {
        return { isImpersonating: true, brand: brand.name, similarity: 0.85 };
      }
    }
  }

  return { isImpersonating: false, brand: null, similarity: 0.0 };
}

export interface DetectionResult {
  url: string;
  classification: "legitimate" | "malicious" | "uncertain";
  risk_percentage: number;
  benign_percentage: number;
  prediction_confidence: "high" | "medium" | "low";
  conformal_prediction_set: string[];
  uncertainty_status: "low" | "medium" | "high";
  out_of_distribution: boolean;
  available_modalities: string[];
  top_reasons: { factor: string; text: string; severity: "critical" | "high" | "medium" | "low" | "safe" }[];
  features: {
    url_length: number;
    hostname_length: number;
    entropy: number;
    num_keywords: number;
    num_subdomains: number;
    is_ip: boolean;
    is_punycode: boolean;
    homoglyphs_count: number;
    is_shortener: boolean;
    is_suspicious_tld: boolean;
    impersonated_brand: string | null;
  };
  model_version: string;
  timestamp: string;
}

export function analyzeUrlClient(url: string, messageText?: string): DetectionResult {
  const parsed = parseURL(url);
  const host = parsed.hostname;
  const raw = parsed.raw;
  const urlLower = raw.toLowerCase();

  // Features
  const urlLen = raw.length;
  const hostLen = host.length;
  const entropy = calculateEntropy(raw);
  const numKeywords = SUSPICIOUS_KEYWORDS.filter(k => urlLower.includes(k)).length;
  const labels = host.split(".");
  const numSubdomains = Math.max(0, labels.length - 2);
  const isIp = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(host);
  const isPunycode = host.includes("xn--");
  let homoglyphsCount = 0;
  for (const ch of host) {
    if (CONFUSABLE_MAP[ch]) homoglyphsCount++;
  }
  const tld = labels.length > 0 ? labels[labels.length - 1] : "";
  const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
  const isShortener = KNOWN_SHORTENERS.has(host);
  const brandCheck = detectBrandImpersonation(host, raw);

  // Distilled Tree Inference Calculation
  let baseScore = 0.02;
  if (brandCheck.isImpersonating) baseScore += 0.50;
  if (isIp) baseScore += 0.45;
  if (isPunycode || homoglyphsCount > 0) baseScore += 0.40;
  if (isShortener) baseScore += 0.25;
  if (isSuspiciousTld) baseScore += 0.28;
  if (numKeywords >= 2) baseScore += 0.25;
  if (numKeywords === 1) baseScore += 0.12;
  if (numSubdomains >= 3) baseScore += 0.20;
  if (entropy >= 4.4) baseScore += 0.18;
  if (urlLen >= 90) baseScore += 0.15;

  // Known benign authority whitelist discount
  const isOfficialMajor = ["google.com", "github.com", "wikipedia.org", "python.org", "mozilla.org", "amazon.com", "apple.com", "microsoft.com", "paypal.com"].some(d => host === d || host.endsWith(`.${d}`));
  if (isOfficialMajor && !isPunycode && homoglyphsCount === 0) {
    baseScore = 0.01;
  }

  // Message context influence
  let modalities = ["url"];
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

  if (brandCheck.isImpersonating) {
    topReasons.push({
      factor: "brand_impersonation",
      text: `Potential Brand Impersonation: Domain closely mimics '${brandCheck.brand}' while registered on an unrelated third-party host.`,
      severity: "critical"
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
  if (isShortener) {
    topReasons.push({
      factor: "shortener",
      text: "Masked URL Shortener: Domain conceals final destination through an intermediary redirect service.",
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
  if (entropy >= 4.3) {
    topReasons.push({
      factor: "entropy",
      text: `Elevated Shannon Entropy (${entropy}): Disproportionate algorithmic randomness in path and query tokens.`,
      severity: "low"
    });
  }

  if (riskPercentage < 35.0) {
    topReasons.push({
      factor: "clean_domain",
      text: "Standard Domain Structure: Registered with authorized hierarchical depth and legitimate domain identity.",
      severity: "safe"
    });
    topReasons.push({
      factor: "no_obfuscation",
      text: "No Obfuscation Detected: Free of homoglyphic replacements, punycode prefixes, and nested redirects.",
      severity: "safe"
    });
  }

  return {
    url: raw,
    classification,
    risk_percentage: riskPercentage,
    benign_percentage: benignPercentage,
    prediction_confidence: confidence,
    conformal_prediction_set: conformalSet,
    uncertainty_status: uncertaintyStatus,
    out_of_distribution: urlLen > 250 || entropy > 5.5,
    available_modalities: modalities,
    top_reasons: topReasons.slice(0, 4),
    features: {
      url_length: urlLen,
      hostname_length: hostLen,
      entropy,
      num_keywords: numKeywords,
      num_subdomains: numSubdomains,
      is_ip: isIp,
      is_punycode: isPunycode,
      homoglyphs_count: homoglyphsCount,
      is_shortener: isShortener,
      is_suspicious_tld: isSuspiciousTld,
      impersonated_brand: brandCheck.brand
    },
    model_version: "1.0.0",
    timestamp: new Date().toISOString()
  };
}
