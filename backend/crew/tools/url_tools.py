"""
URL pattern analysis and HTTP header inspection tools.
Functions are called directly by the agent pipeline (no CrewAI dependency).
"""
import re
import requests
from urllib.parse import urlparse

def tool(name):
    """No-op decorator — tools are called directly, not via CrewAI."""
    def decorator(fn):
        return fn
    return decorator

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
    '.download', '.loan', '.win', '.bid', '.stream', '.gdn',
    '.racing', '.accountant', '.review', '.party', '.date', '.faith',
}

TOP_BRANDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'instagram', 'twitter', 'netflix', 'linkedin', 'dropbox', 'adobe',
    'chase', 'wellsfargo', 'citibank', 'bankofamerica', 'ebay', 'dhl',
]

PHISHING_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'secure', 'account',
    'update', 'confirm', 'banking', 'password', 'credential',
    'authenticate', 'validation', 'reset', 'recovery', 'unlock',
    'suspended', 'blocked', 'urgent', 'limited',
]

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'cutt.ly', 'rebrand.ly', 'short.link',
}

SECURITY_HEADERS = {
    'strict-transport-security': 'HSTS',
    'content-security-policy': 'CSP',
    'x-frame-options': 'X-Frame-Options',
    'x-content-type-options': 'X-Content-Type-Options',
    'referrer-policy': 'Referrer-Policy',
}


@tool("URL Pattern Analyzer")
def analyze_url_patterns(url: str) -> str:
    """
    Analyzes a URL for suspicious structural patterns: length, IP-based hosting,
    suspicious TLDs, phishing keywords, brand impersonation in subdomains,
    Punycode, and URL shorteners. Returns a threat assessment string.
    """
    findings = []
    risk = 0

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        domain_clean = domain.split(':')[0]
        parts = domain_clean.split('.')

        # 1. URL length
        if len(url) > 100:
            findings.append(f"ALERT: Very long URL ({len(url)} chars) — classic phishing indicator")
            risk += 2
        elif len(url) > 75:
            findings.append(f"WARN: Moderately long URL ({len(url)} chars)")
            risk += 1
        else:
            findings.append(f"OK: URL length is normal ({len(url)} chars)")

        # 2. HTTPS
        if parsed.scheme != 'https':
            findings.append("ALERT: Not using HTTPS — traffic unencrypted")
            risk += 2
        else:
            findings.append("OK: Uses HTTPS")

        # 3. IP-based host
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain_clean):
            findings.append(f"ALERT: IP address used as host ({domain_clean}) — legitimate sites use domain names")
            risk += 3

        # 4. @ symbol
        if '@' in url:
            findings.append("ALERT: @ symbol in URL — used to deceive users about the real destination")
            risk += 3

        # 5. Suspicious TLD
        tld = '.' + parts[-1] if parts else ''
        if tld in SUSPICIOUS_TLDS:
            findings.append(f"ALERT: High-risk free TLD ({tld}) — disproportionately used for malicious sites")
            risk += 2
        else:
            findings.append(f"OK: TLD '{tld}' appears standard")

        # 6. Subdomain count
        sub_count = len(parts) - 2
        if sub_count > 3:
            findings.append(f"ALERT: Excessive subdomain depth ({sub_count}) — obfuscation technique")
            risk += 2
        elif sub_count > 1:
            findings.append(f"WARN: Multiple subdomains ({sub_count}) — verify legitimacy")
            risk += 1

        # 7. Brand in subdomain (not apex)
        apex = '.'.join(parts[-2:]) if len(parts) >= 2 else domain_clean
        sub_str = '.'.join(parts[:-2])
        for brand in TOP_BRANDS:
            if brand in sub_str and brand not in apex:
                findings.append(f"ALERT: Brand '{brand}' in subdomain but apex is '{apex}' — impersonation attack")
                risk += 3
                break

        # 8. Phishing keywords in path
        hits = [kw for kw in PHISHING_KEYWORDS if kw in path]
        if len(hits) >= 3:
            findings.append(f"ALERT: Multiple phishing keywords in path: {', '.join(hits)}")
            risk += 2
        elif hits:
            findings.append(f"WARN: Phishing keyword(s) in path: {', '.join(hits)}")
            risk += 1

        # 9. URL shortener
        if domain_clean in URL_SHORTENERS:
            findings.append(f"WARN: URL shortener ({domain_clean}) hides true destination")
            risk += 1

        # 10. Punycode
        if 'xn--' in domain_clean:
            findings.append("ALERT: Punycode domain — possible homoglyph impersonation (e.g. аmazon.com)")
            risk += 3

        # 11. Excessive hyphens
        apex_name = parts[-2] if len(parts) >= 2 else ''
        if apex_name.count('-') >= 3:
            findings.append(f"WARN: Many hyphens in domain name — phishing pattern (secure-login-paypal.com)")
            risk += 1

        score = min(100, risk * 10)
        return (
            f"URL PATTERN ANALYSIS for: {url}\n"
            f"Risk indicators: {risk} | Estimated static score: {score}/100\n"
            "Findings:\n" + "\n".join(f"  - {f}" for f in findings)
        )
    except Exception as e:
        return f"ERROR in URL pattern analysis: {e}"


@tool("HTTP Security Header Inspector")
def inspect_http_headers(url: str) -> str:
    """
    Makes an HTTP GET request to the URL and inspects security response headers,
    SSL certificate validity, redirect chain, and server banner leakage.
    Returns a detailed header security assessment string.
    """
    findings = []
    risk = 0

    try:
        ua = (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        )
        resp = requests.get(
            url, headers={'User-Agent': ua},
            timeout=10, allow_redirects=True, verify=True
        )
        h = {k.lower(): v for k, v in resp.headers.items()}

        # Status
        if resp.status_code == 200:
            findings.append("OK: Server responds 200 OK")
        else:
            findings.append(f"WARN: Non-200 status code ({resp.status_code})")
            risk += 1

        # Redirects
        if len(resp.history) > 2:
            chain = " → ".join(r.url[:60] for r in resp.history)
            findings.append(f"WARN: Long redirect chain ({len(resp.history)} hops): {chain}")
            risk += 1
        if resp.history:
            orig = urlparse(url).netloc
            final = urlparse(resp.url).netloc
            if orig != final:
                findings.append(f"ALERT: Final destination domain differs: {orig} → {final}")
                risk += 2

        # Security headers
        missing = []
        for key, name in SECURITY_HEADERS.items():
            if key in h:
                findings.append(f"OK: {name} header present")
            else:
                missing.append(name)

        if len(missing) >= 4:
            findings.append(f"ALERT: Most security headers absent: {', '.join(missing)}")
            risk += 2
        elif missing:
            findings.append(f"WARN: Missing headers: {', '.join(missing)}")
            risk += 1

        # Server banner
        if 'server' in h:
            sv = h['server']
            if any(v in sv.lower() for v in ['apache/2.', 'nginx/1.', 'php/', 'iis/']):
                findings.append(f"WARN: Server version exposed ({sv}) — information leakage")
                risk += 1
            else:
                findings.append(f"OK: Server header present but version not disclosed")

        # Content type
        ct = h.get('content-type', '')
        if 'html' in ct:
            findings.append("OK: Content-Type is HTML")
        elif 'javascript' in ct or 'octet-stream' in ct:
            findings.append("ALERT: Response delivers executable content")
            risk += 2

        score = min(100, risk * 12)
        return (
            f"HTTP HEADER INSPECTION for: {url}\n"
            f"Status: {resp.status_code} | Redirects: {len(resp.history)} | "
            f"Final URL: {resp.url[:80]}\n"
            f"Risk indicators: {risk} | Estimated header score: {score}/100\n"
            "Findings:\n" + "\n".join(f"  - {f}" for f in findings)
        )

    except requests.exceptions.SSLError as e:
        return (
            f"HTTP HEADER INSPECTION for: {url}\n"
            f"ALERT: SSL certificate validation FAILED — {str(e)[:150]}\n"
            "Risk indicators: 5 (critical)"
        )
    except requests.exceptions.Timeout:
        return (
            f"HTTP HEADER INSPECTION for: {url}\n"
            "WARN: Request timed out after 10 s\nRisk indicators: 1"
        )
    except requests.exceptions.ConnectionError as e:
        return (
            f"HTTP HEADER INSPECTION for: {url}\n"
            f"WARN: Connection failed — {str(e)[:120]}\nRisk indicators: 0"
        )
    except Exception as e:
        return f"ERROR in HTTP header inspection: {e}"
