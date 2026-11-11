import dns from 'node:dns/promises';
import net from 'node:net';

export interface RedirectHop {
  hop: number;
  url: string;
  hostname: string;
  protocol: string;
  status_code: number | null;
}

export interface RedirectResolutionResult {
  original_url: string;
  final_url: string;
  resolved: boolean;
  hop_count: number;
  cross_domain_redirects: number;
  protocol_downgrade: boolean;
  chain: RedirectHop[];
  error?: string;
}

function isPrivateOrReservedIP(ip: string): boolean {
  const clean = ip.replace(/^\[|\]$/g, '').split('%')[0];
  if (net.isIPv4(clean)) {
    const parts = clean.split('.').map(Number);
    if (parts.length !== 4 || parts.some(Number.isNaN)) return true;
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast / reserved
    return false;
  }
  if (net.isIPv6(clean)) {
    const lower = clean.toLowerCase();
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // ULA
    if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true; // link-local
    if (lower.startsWith('::ffff:')) {
      return isPrivateOrReservedIP(lower.slice(7));
    }
    return false;
  }
  return true;
}

async function isPublicHost(hostname: string): Promise<boolean> {
  if (!hostname) return false;
  const clean = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(clean)) {
    return !isPrivateOrReservedIP(clean);
  }
  try {
    const records = await dns.lookup(clean, { all: true });
    if (!records || records.length === 0) return false;
    return records.every((rec) => !isPrivateOrReservedIP(rec.address));
  } catch {
    return false;
  }
}

function extractClientRedirectFromHtml(html: string, baseUrl: string): string | null {
  const metaMatch = html.match(
    /<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["']?\d+\s*;\s*url=([^"'>\s]+)/i
  );
  if (metaMatch && metaMatch[1]) {
    try {
      return new URL(metaMatch[1].trim(), baseUrl).toString();
    } catch {
      return null;
    }
  }
  const jsLocMatch = html.match(
    /(?:window\.location(?:\.href)?|location\.replace)\s*(?:=|\()\s*["'](https?:\/\/[^"']+)["']/i
  );
  if (jsLocMatch && jsLocMatch[1]) {
    try {
      return new URL(jsLocMatch[1].trim(), baseUrl).toString();
    } catch {
      return null;
    }
  }
  return null;
}

export async function resolveRedirectChainNode(
  rawUrl: string,
  maxHops = 8,
  timeoutMs = 4000
): Promise<RedirectResolutionResult> {
  const trimmed = (rawUrl || '').trim();
  const startUrl = trimmed.includes('://') ? trimmed : `https://${trimmed}`;

  let parsedStart: URL;
  try {
    parsedStart = new URL(startUrl);
  } catch {
    return {
      original_url: startUrl,
      final_url: startUrl,
      resolved: false,
      hop_count: 0,
      cross_domain_redirects: 0,
      protocol_downgrade: false,
      chain: [{ hop: 0, url: startUrl, hostname: '', protocol: 'http', status_code: null }],
      error: 'Invalid URL syntax'
    };
  }

  if (parsedStart.protocol !== 'http:' && parsedStart.protocol !== 'https:') {
    return {
      original_url: startUrl,
      final_url: startUrl,
      resolved: false,
      hop_count: 0,
      cross_domain_redirects: 0,
      protocol_downgrade: false,
      chain: [{
        hop: 0,
        url: startUrl,
        hostname: parsedStart.hostname.toLowerCase(),
        protocol: parsedStart.protocol.replace(':', ''),
        status_code: null
      }],
      error: 'Unsupported protocol'
    };
  }

  const chain: RedirectHop[] = [{
    hop: 0,
    url: startUrl,
    hostname: parsedStart.hostname.toLowerCase(),
    protocol: parsedStart.protocol.replace(':', ''),
    status_code: null
  }];

  let currentUrl = startUrl;
  let resolvedAny = false;
  let errorMsg: string | undefined;
  const visited = new Set<string>([startUrl]);

  for (let hop = 1; hop <= maxHops; hop++) {
    let parsedCurr: URL;
    try {
      parsedCurr = new URL(currentUrl);
    } catch {
      errorMsg = 'Invalid redirect URL';
      break;
    }

    const host = parsedCurr.hostname.toLowerCase();
    const allowed = await isPublicHost(host);
    if (!allowed) {
      errorMsg = 'Blocked private or unresolvable host';
      break;
    }

    let nextUrl: string | null = null;
    let statusCode: number | null = null;

    for (const method of ['HEAD', 'GET'] as const) {
      try {
        const res = await fetch(currentUrl, {
          method,
          redirect: 'manual',
          signal: AbortSignal.timeout(timeoutMs),
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
          }
        });
        statusCode = res.status;
        const location = res.headers.get('location');
        if (location && statusCode >= 300 && statusCode < 400) {
          nextUrl = new URL(location.trim(), currentUrl).toString();
          break;
        }
        if (method === 'HEAD' && (statusCode === 403 || statusCode === 405 || statusCode === 501 || statusCode === 200)) {
          // If HEAD returns 200 without Location, check brief GET for meta-refresh or JS redirect
          if (statusCode === 200) {
            // Fall through to GET check for client redirect in first 8KB
            continue;
          }
          continue;
        }
        if (method === 'GET' && statusCode === 200) {
          const text = (await res.text()).slice(0, 8192);
          const clientRedirect = extractClientRedirectFromHtml(text, currentUrl);
          if (clientRedirect) {
            nextUrl = clientRedirect;
          }
        }
        break;
      } catch (err) {
        if (method === 'HEAD') continue;
        errorMsg = err instanceof Error ? err.message : 'Network error';
        break;
      }
    }

    chain[chain.length - 1].status_code = statusCode;

    if (!nextUrl || visited.has(nextUrl)) {
      if (statusCode !== null && statusCode >= 200 && statusCode < 400 && chain.length > 1) {
        resolvedAny = true;
      }
      break;
    }

    visited.add(nextUrl);
    let parsedNext: URL;
    try {
      parsedNext = new URL(nextUrl);
    } catch {
      break;
    }
    chain.push({
      hop,
      url: nextUrl,
      hostname: parsedNext.hostname.toLowerCase(),
      protocol: parsedNext.protocol.replace(':', ''),
      status_code: null
    });
    currentUrl = nextUrl;
    resolvedAny = true;
  }

  const distinctHosts = new Set(chain.map((c) => c.hostname).filter(Boolean));
  let seenHttps = false;
  let protocolDowngrade = false;
  for (const step of chain) {
    if (step.protocol === 'https') seenHttps = true;
    else if (seenHttps && step.protocol === 'http') protocolDowngrade = true;
  }

  const finalUrl = chain[chain.length - 1].url;
  const hopCount = Math.max(0, chain.length - 1);

  return {
    original_url: startUrl,
    final_url: finalUrl,
    resolved: resolvedAny && (finalUrl !== startUrl || hopCount > 0),
    hop_count: hopCount,
    cross_domain_redirects: Math.max(0, distinctHosts.size - 1),
    protocol_downgrade: protocolDowngrade,
    chain,
    error: errorMsg
  };
}
