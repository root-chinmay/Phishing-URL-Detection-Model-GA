import re
import ssl
import base64
import socket
import ipaddress
import urllib.request
import urllib.error
from urllib.parse import urlparse, urljoin, unquote, parse_qsl, urlencode, urlunparse
from src.features.domain_features import KNOWN_SHORTENERS

TRACKING_QUERY_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "fbclid", "gclid", "mc_cid", "mc_eid", "si", "_hsenc", "_hsmi",
    "ref_src", "ref_url"
}

REDIRECT_PARAM_NAMES = [
    "url", "redirect", "redirect_url", "redirect_uri", "dest", "destination",
    "target", "link", "next", "return", "return_url", "goto", "continue", "u", "q"
]


def _is_public_ip_for_host(hostname: str) -> bool:
    """Resolve hostname and verify all IPs are public (SSRF protection)."""
    if not hostname:
        return False
    clean_host = hostname.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(clean_host, None)
        if not addr_info:
            return False
        for entry in addr_info:
            ip_str = entry[4][0].split("%")[0]
            ip_obj = ipaddress.ip_address(ip_str)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                return False
        return True
    except (socket.gaierror, ValueError):
        return False


def canonicalize_url_for_comparison(url: str) -> str:
    """
    Canonicalize a URL so equivalent destinations (with/without trailing slash,
    default ports, uppercase hosts, or harmless marketing tracking params)
    produce consistent feature vectors and risk scores.
    """
    raw = (url or "").strip()
    if not raw:
        return ""
    with_scheme = raw if "://" in raw else f"http://{raw}"
    try:
        parsed = urlparse(with_scheme)
        scheme = (parsed.scheme or "http").lower()
        host = (parsed.hostname or "").lower()
        if not host:
            return raw

        port = parsed.port
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = host
        elif port:
            netloc = f"{host}:{port}"
        else:
            netloc = host

        if parsed.username:
            auth = parsed.username + (f":{parsed.password}" if parsed.password else "")
            netloc = f"{auth}@{netloc}"

        path = parsed.path or ""
        if path == "/":
            path = ""

        # Filter harmless analytics/tracking parameters while keeping functional/redirect params
        kept_params = []
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            if k.lower() not in TRACKING_QUERY_PARAMS:
                kept_params.append((k, v))
        query = urlencode(kept_params, doseq=True)

        return urlunparse((scheme, netloc, path, parsed.params, query, ""))
    except Exception:
        return raw


def _try_extract_embedded_url(value: str) -> str | None:
    """Decode percent-encoded or base64-encoded embedded URLs from redirect query params."""
    if not value:
        return None
    decoded = unquote(value).strip()
    if re.match(r"^https?://", decoded, re.IGNORECASE):
        return decoded
    # Try Base64 decoding if value looks base64-encoded
    if len(decoded) >= 12 and re.match(r"^[A-Za-z0-9+/=_-]+$", decoded):
        try:
            padded = decoded + "=" * ((4 - len(decoded) % 4) % 4)
            b64_str = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", errors="ignore").strip()
            if re.match(r"^https?://", b64_str, re.IGNORECASE):
                return b64_str
        except Exception:
            pass
    return None


def analyze_redirect_risk_offline(url: str) -> dict:
    """
    Offline analysis of redirect risks: detects known URL shorteners,
    suspicious open redirect parameters (url=, redirect=, dest=, target=, link=),
    Base64/percent-encoded destination URLs, and cross-domain forwarding patterns
    without sending network requests.
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = (parsed.hostname or "").lower()

    is_shortener = hostname in KNOWN_SHORTENERS or any(
        hostname.endswith(f".{s}") for s in KNOWN_SHORTENERS
    )

    found_params = []
    embedded_urls = []
    embedded_target = None

    for k, v in parse_qsl(parsed.query, keep_blank_values=False):
        if k.lower() in REDIRECT_PARAM_NAMES:
            candidate = _try_extract_embedded_url(v)
            if candidate or k.lower() != "q":
                found_params.append(k)
                target_val = candidate or unquote(v)
                embedded_urls.append(target_val)
                if embedded_target is None:
                    embedded_target = target_val

    has_redirect_lure = len(found_params) > 0

    return {
        "is_shortener": is_shortener,
        "is_known_shortener": is_shortener,
        "has_redirect_parameters": has_redirect_lure,
        "has_redirect_param": has_redirect_lure,
        "redirect_parameters_found": found_params,
        "potential_embedded_target": embedded_target,
        "embedded_urls": embedded_urls,
        "risk_explanation": (
            "URL uses a known link shortener which masks the final destination." if is_shortener
            else ("URL contains potential open-redirect parameters." if has_redirect_lure
            else "No suspicious redirect parameters identified in URL structure.")
        )
    }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def resolve_redirect_chain(url: str, max_hops: int = 8, timeout: float = 4.0) -> dict:
    """
    Safely trace HTTP redirects (301/302/303/307/308) and shortener meta-refresh
    headers with strict SSRF IP validation and zero script execution.
    """
    raw = (url or "").strip()
    start_url = raw if "://" in raw else f"https://{raw}"
    parsed_start = urlparse(start_url)

    chain = [{
        "hop": 0,
        "url": start_url,
        "hostname": (parsed_start.hostname or "").lower(),
        "protocol": (parsed_start.scheme or "http").lower(),
        "status_code": None
    }]

    if parsed_start.scheme not in ("http", "https"):
        return {
            "original_url": start_url,
            "final_url": start_url,
            "resolved_successfully": False,
            "hop_count": 0,
            "cross_domain_redirects": 0,
            "protocol_downgrade": False,
            "redirect_chain": chain,
            "resolution_error": "Unsupported scheme"
        }

    current_url = start_url
    opener = urllib.request.build_opener(_NoRedirectHandler())
    ssl_ctx = ssl.create_default_context()
    resolved_any = False
    resolution_error = None
    visited = {start_url}

    for hop_idx in range(1, max_hops + 1):
        parsed_curr = urlparse(current_url)
        curr_host = (parsed_curr.hostname or "").lower()

        if parsed_curr.scheme not in ("http", "https") or not _is_public_ip_for_host(curr_host):
            resolution_error = "Blocked non-public or invalid target host"
            break

        next_url = None
        status_code = None

        for method in ("HEAD", "GET"):
            req = urllib.request.Request(
                current_url,
                method=method,
                headers={"User-Agent": "Mozilla/5.0 (compatible; URLThreatInspector/1.0)"}
            )
            try:
                with opener.open(req, timeout=timeout) as resp:
                    status_code = resp.getcode()
                    loc = resp.headers.get("Location")
                    if loc:
                        next_url = urljoin(current_url, loc.strip())
                    elif method == "GET" and status_code == 200:
                        # Check first 8KB for static <meta http-equiv="refresh"> redirect
                        body_chunk = resp.read(8192).decode("utf-8", errors="ignore")
                        meta_match = re.search(
                            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+\s*;\s*url=([^"\'>\s]+)',
                            body_chunk,
                            re.IGNORECASE
                        )
                        if meta_match:
                            next_url = urljoin(current_url, meta_match.group(1).strip())
                    break
            except urllib.error.HTTPError as http_err:
                status_code = http_err.code
                loc = http_err.headers.get("Location") if http_err.headers else None
                if status_code in (301, 302, 303, 307, 308) and loc:
                    next_url = urljoin(current_url, loc.strip())
                    break
                if method == "HEAD" and status_code in (403, 405, 501):
                    continue
                resolution_error = f"HTTP {status_code}"
                break
            except Exception as exc:
                if method == "HEAD":
                    continue
                resolution_error = str(exc)[:120]
                break

        chain[-1]["status_code"] = status_code

        if not next_url or next_url in visited:
            if status_code is not None and 200 <= status_code < 400 and len(chain) > 1:
                resolved_any = True
            elif status_code is not None and 200 <= status_code < 400 and curr_host not in KNOWN_SHORTENERS:
                resolved_any = True
            break

        visited.add(next_url)
        parsed_next = urlparse(next_url)
        chain.append({
            "hop": hop_idx,
            "url": next_url,
            "hostname": (parsed_next.hostname or "").lower(),
            "protocol": (parsed_next.scheme or "http").lower(),
            "status_code": None
        })
        current_url = next_url
        resolved_any = True

    distinct_hosts = []
    protocol_downgrade = False
    seen_https = False
    for step in chain:
        h = step["hostname"]
        if h and (not distinct_hosts or distinct_hosts[-1] != h):
            distinct_hosts.append(h)
        if step["protocol"] == "https":
            seen_https = True
        elif seen_https and step["protocol"] == "http":
            protocol_downgrade = True

    hop_count = max(0, len(chain) - 1)
    cross_domain_redirects = max(0, len(set(distinct_hosts)) - 1)
    final_url = chain[-1]["url"]

    return {
        "original_url": start_url,
        "final_url": final_url,
        "resolved_successfully": resolved_any and (final_url != start_url or hop_count > 0),
        "hop_count": hop_count,
        "cross_domain_redirects": cross_domain_redirects,
        "protocol_downgrade": protocol_downgrade,
        "redirect_chain": chain,
        "resolution_error": resolution_error
    }
