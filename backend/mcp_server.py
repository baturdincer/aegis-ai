# backend/mcp_server.py

import re
import socket
import ipaddress
import requests
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from mcp.server.fastmcp import FastMCP

# MCP Sunucusunu Başlat
mcp = FastMCP("Aegis-Threat-Intel")

# ==========================================
# GLOABAL DEĞİŞKENLER VE LİSTELER
# ==========================================

TOP_BRANDS = {
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'instagram', 'twitter', 'netflix', 'linkedin', 'dropbox', 'adobe',
    'chase', 'wellsfargo', 'citibank', 'bankofamerica', 'ebay', 'dhl',
    'fedex', 'usps', 'irs',
}

FREE_HOSTING = {
    '000webhostapp.com', 'weebly.com', 'wix.com', 'jimdo.com',
    'wordpress.com', 'blogspot.com', 'tumblr.com', 'ucoz.com',
    'yolasite.com', 'atwebpages.com', 'freewha.com', 'x10host.com',
    'altervista.org', 'byethost.com', 'biz.nf', 'co.nf',
}

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
    '.download', '.loan', '.win', '.bid', '.stream', '.gdn',
    '.racing', '.accountant', '.review', '.party', '.date', '.faith',
}

SUSPICIOUS_JS = [
    (r'eval\s*\(', 'eval() — common obfuscation technique'),
    (r'document\.write\s*\(', 'document.write() — injection vector'),
    (r'unescape\s*\(', 'unescape() — decoding obfuscated payloads'),
    (r'fromCharCode', 'String.fromCharCode() — character-code obfuscation'),
    (r'atob\s*\(', 'atob() base64 decode — hiding malicious payloads'),
    (r'window\.location\s*=', 'Forced redirect via window.location'),
    (r'\.submit\s*\(\)', 'Auto-form submission — credential theft'),
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

_MULTI_LABEL_SUFFIXES = {
    'co.uk', 'org.uk', 'gov.uk',
    'com.tr', 'org.tr', 'gov.tr',
    'com.au', 'com.br', 'com.mx', 'com.ar',
    'co.jp', 'co.kr', 'co.in', 'co.id',
    'com.sg', 'com.hk',
}

_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}

_PHISH_DB_CACHE = set()
_PHISH_DB_LAST_FETCH = 0


# ==========================================
# YARDIMCI FONKSİYONLAR
# ==========================================

def _split_registered_domain(domain: str) -> tuple[str, str]:
    """Return (registered_domain, subdomain) for a given hostname."""
    labels = [label for label in domain.split('.') if label]
    if len(labels) < 2:
        return domain, ''

    last_two = '.'.join(labels[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        registered = '.'.join(labels[-3:])
        subdomain = '.'.join(labels[:-3])
        return registered, subdomain

    registered = '.'.join(labels[-2:])
    subdomain = '.'.join(labels[:-2])
    return registered, subdomain


# ==========================================
# MCP ARAÇLARI (TOOLS)
# ==========================================

@mcp.tool()
def analyze_page_content(url: str) -> str:
    """
    Downloads and analyzes the HTML content of a web page. Inspects login forms
    pointing to external domains, auto-submit forms, hidden iframes, meta-refresh
    redirects, obfuscated JavaScript, and brand impersonation in the page title.
    Returns a comprehensive content analysis string.
    """
    findings = []
    risk = 0

    try:
        resp = requests.get(url, headers=_HEADERS, timeout=12, allow_redirects=True)
        soup = BeautifulSoup(resp.text, 'html.parser')
        base_domain = urlparse(resp.url).netloc

        # 1. Forms with password fields
        forms = soup.find_all('form')
        pw_forms, ext_forms = [], []
        for form in forms:
            has_pw = bool(form.find('input', {'type': 'password'}))
            action = form.get('action', '')
            if has_pw:
                pw_forms.append(form)
                if action.startswith('http'):
                    action_dom = urlparse(action).netloc
                    if action_dom and action_dom != base_domain:
                        ext_forms.append(action_dom)
                        findings.append(
                            f"ALERT: Password form POSTs to external domain ({action_dom}) — credential harvesting"
                        )
                        risk += 4
                form_html = str(form).lower()
                if 'onload' in form_html and 'submit' in form_html:
                    findings.append("ALERT: Auto-submitting form detected — credential theft technique")
                    risk += 3

        if pw_forms and not ext_forms:
            findings.append(f"WARN: {len(pw_forms)} password form(s) — verify this is a legitimate login page")
            risk += 1
        elif not pw_forms:
            findings.append("OK: No password input forms detected")

        # 2. Hidden iframes
        iframes = soup.find_all('iframe')
        hidden = []
        hidden_external = 0
        for iframe in iframes:
            style = iframe.get('style', '').replace(' ', '').lower()
            is_hidden = (
                'display:none' in style
                or iframe.get('width') in ('0', '1')
                or iframe.get('height') in ('0', '1')
            )
            if is_hidden:
                hidden.append(iframe)
                src = (iframe.get('src') or '').strip()
                if src.startswith('http'):
                    src_domain = urlparse(src).netloc
                    if src_domain and src_domain != base_domain:
                        hidden_external += 1

        if hidden_external >= 2:
            findings.append(f"ALERT: {hidden_external} hidden iframe(s) load external domains — potential injection risk")
            risk += 3
        elif hidden_external == 1:
            findings.append("WARN: 1 hidden iframe loads an external domain — often legitimate, verify purpose")
            risk += 1
        elif hidden:
            findings.append(f"WARN: {len(hidden)} hidden iframe(s) detected — often used for analytics/consent, verify purpose")
            risk += 1
        else:
            findings.append("OK: No hidden iframes detected")

        # 3. Meta refresh redirect
        meta = soup.find('meta', attrs={'http-equiv': lambda v: v and 'refresh' in v.lower()})
        if meta:
            findings.append(f"ALERT: Meta-refresh redirect: {meta.get('content', '')[:80]}")
            risk += 2

        # 4. External scripts count
        ext_scripts = [
            s['src'] for s in soup.find_all('script', src=True)
            if s.get('src', '').startswith('http') and base_domain not in s['src']
        ]
        if len(ext_scripts) > 10:
            findings.append(f"WARN: {len(ext_scripts)} external scripts loaded — large attack surface")
            risk += 1
        else:
            findings.append(f"OK: {len(ext_scripts)} external scripts (acceptable)")

        # 5. Suspicious inline JavaScript
        inline = ' '.join(s.get_text() for s in soup.find_all('script', src=False))
        js_hits = 0
        for pattern, desc in SUSPICIOUS_JS:
            if re.search(pattern, inline):
                findings.append(f"ALERT: Suspicious JS: {desc}")
                risk += 2
                js_hits += 1
        if js_hits == 0:
            findings.append("OK: No obfuscated JavaScript patterns in inline code")

        # 6. Page title brand impersonation
        title_el = soup.find('title')
        title = title_el.get_text().lower() if title_el else ''
        for brand in TOP_BRANDS:
            if brand in title and brand not in base_domain.lower():
                findings.append(f"ALERT: Title references '{brand}' but domain is '{base_domain}' — brand impersonation")
                risk += 3
                break

        # 7. Urgency language
        text = soup.get_text().lower()
        urgent = [w for w in ['urgent', 'suspended', 'verify now', 'act now', 'limited time'] if w in text]
        if len(urgent) >= 2:
            findings.append(f"WARN: Urgency language found: {', '.join(urgent)}")
            risk += 1

        score = min(100, risk * 10)
        return (
            f"PAGE CONTENT ANALYSIS for: {url}\n"
            f"Base domain: {base_domain} | Forms: {len(forms)} | "
            f"Ext scripts: {len(ext_scripts)} | JS alerts: {js_hits}\n"
            f"Risk indicators: {risk} | Estimated dynamic score: {score}/100\n"
            "Findings:\n" + "\n".join(f"  - {f}" for f in findings)
        )

    except requests.exceptions.Timeout:
        return f"PAGE CONTENT ANALYSIS for: {url}\nWARN: Timed out. Risk indicators: 1"
    except requests.exceptions.ConnectionError:
        return f"PAGE CONTENT ANALYSIS for: {url}\nWARN: Could not connect. Risk indicators: 0"
    except Exception as e:
        return f"ERROR in page content analysis: {e}"


@mcp.tool()
def check_domain_reputation(url: str) -> str:
    """
    Heuristic domain reputation analysis: checks for free hosting abuse, DNS
    resolution, numeric-heavy domains, brand squatting, Punycode attacks,
    suspicious TLDs, and excessive hyphens. Returns a reputation assessment string.
    """
    findings = []
    risk = 0

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(':')[0]
        parts = domain.split('.')
        apex_name = parts[-2] if len(parts) >= 2 else parts[0]
        tld = '.' + parts[-1] if parts else ''

        # 1. Free hosting
        for fh in FREE_HOSTING:
            if domain.endswith(fh):
                findings.append(f"WARN: Free hosting provider ({fh}) — commonly abused for phishing")
                risk += 2
                break
        else:
            findings.append("OK: Not using known free/abused hosting service")

        # 2. DNS resolution
        try:
            ip = socket.gethostbyname(domain)
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                findings.append(f"ALERT: Domain resolves to private IP {ip} — highly suspicious")
                risk += 3
            else:
                findings.append(f"OK: Domain resolves to public IP {ip}")
        except socket.gaierror:
            findings.append("WARN: Domain does not resolve via DNS — may be down or fake")
            risk += 1

        # 3. TLD risk
        if tld in SUSPICIOUS_TLDS:
            findings.append(f"ALERT: High-risk TLD ({tld}) — free TLDs abused for malicious activity")
            risk += 2
        else:
            findings.append(f"OK: TLD '{tld}' is standard")

        # 4. Long domain name
        if len(apex_name) > 25:
            findings.append(f"WARN: Long domain name ({len(apex_name)} chars) — phishing indicator")
            risk += 1

        # 5. Digit-heavy domain
        digit_ratio = sum(c.isdigit() for c in apex_name) / max(len(apex_name), 1)
        if digit_ratio > 0.4:
            findings.append(f"WARN: Domain is {int(digit_ratio*100)}% digits — spam/malware pattern")
            risk += 1

        # 6. Punycode homoglyph
        if 'xn--' in domain:
            findings.append("ALERT: Punycode domain — possible homoglyph brand attack")
            risk += 3

        # 7. Excessive hyphens
        if apex_name.count('-') >= 3:
            findings.append(f"WARN: {apex_name.count('-')} hyphens in domain — phishing pattern")
            risk += 1

        # 8. Brand squatting
        for brand in TOP_BRANDS:
            if brand in apex_name and brand != apex_name:
                findings.append(f"ALERT: Brand '{brand}' embedded in domain '{domain}' — brand squatting")
                risk += 3
                break

        score = min(100, risk * 12)
        return (
            f"DOMAIN REPUTATION for: {url}\n"
            f"Domain: {domain} | Apex name: {apex_name} | TLD: {tld}\n"
            f"Risk indicators: {risk} | Estimated intel score: {score}/100\n"
            "Findings:\n" + "\n".join(f"  - {f}" for f in findings)
        )

    except Exception as e:
        return f"ERROR in domain reputation check: {e}"


@mcp.tool()
def check_phishing_databases(url: str) -> str:
    """
    Checks if the URL is present in recognized public phishing databases (e.g., OpenPhish feed).
    Returns an assessment indicating if the URL is blacklisted.
    """
    global _PHISH_DB_CACHE, _PHISH_DB_LAST_FETCH
    
    current_time = time.time()
    if current_time - _PHISH_DB_LAST_FETCH > 3600 or not _PHISH_DB_CACHE:
        try:
            response = requests.get('https://openphish.com/feed.txt', timeout=15)
            if response.status_code == 200:
                _PHISH_DB_CACHE = set(line.strip() for line in response.text.splitlines() if line.strip())
                _PHISH_DB_LAST_FETCH = current_time
        except Exception as e:
            return f"WARN: Failed to reach OpenPhish database for verification: {e}"

    if url in _PHISH_DB_CACHE:
        return (
            f"PHISHING DATABASE CHECK for: {url}\n"
            "ALERT: URL IS PRESENT IN OPENPHISH DATABASE!\n"
            "Risk indicators: 10 | Estimated intel score: 100/100\n"
            "Findings:\n  - ALERT: URL confirmed as an active phishing link in public databases."
        )
    
    clean_url = url.split("://")[-1].rstrip('/')
    for db_url in _PHISH_DB_CACHE:
        db_clean = db_url.split("://")[-1].rstrip('/')
        if clean_url == db_clean:
            return (
                f"PHISHING DATABASE CHECK for: {url}\n"
                "ALERT: URL MATCHES ENTRY IN OPENPHISH DATABASE!\n"
                "Risk indicators: 10 | Estimated intel score: 100/100\n"
                "Findings:\n  - ALERT: URL confirmed as an active phishing link in public databases."
            )

    return (
        f"PHISHING DATABASE CHECK for: {url}\n"
        "OK: URL is not listed in the current OpenPhish database.\n"
        "Risk indicators: 0 | Estimated intel score: 0/100\n"
        "Findings:\n  - OK: URL is not listed in open phishing databases."
    )


@mcp.tool()
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
        registered_domain, subdomain = _split_registered_domain(domain_clean)

        # 1. URL length
        canonical_len = len(f"{parsed.scheme}://{domain_clean}{parsed.path}")
        query_len = len(parsed.query or '')
        if canonical_len > 120:
            findings.append(f"ALERT: Very long canonical URL ({canonical_len} chars) — phishing indicator")
            risk += 2
        elif canonical_len > 90:
            findings.append(f"WARN: Moderately long canonical URL ({canonical_len} chars)")
            risk += 1
        else:
            findings.append(f"OK: Canonical URL length is normal ({canonical_len} chars)")

        if query_len > 250:
            findings.append(f"WARN: Large query string ({query_len} chars) — can be tracking-heavy or obfuscated")
            risk += 1

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
        sub_labels = [p for p in subdomain.split('.') if p and p != 'www']
        sub_count = len(sub_labels)
        if sub_count > 3:
            findings.append(f"ALERT: Excessive subdomain depth ({sub_count}) — obfuscation technique")
            risk += 2
        elif sub_count > 1:
            findings.append(f"WARN: Multiple subdomains ({sub_count}) — verify legitimacy")
            risk += 1
        else:
            findings.append("OK: Subdomain depth is normal")

        # 7. Brand in subdomain (not apex)
        for brand in TOP_BRANDS:
            if brand in subdomain and brand not in registered_domain:
                findings.append(
                    f"ALERT: Brand '{brand}' appears in subdomain while registered domain is "
                    f"'{registered_domain}' — impersonation attack"
                )
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
            findings.append("ALERT: Punycode domain — possible homoglyph impersonation")
            risk += 3

        # 11. Excessive hyphens
        apex_name = parts[-2] if len(parts) >= 2 else ''
        if apex_name.count('-') >= 3:
            findings.append(f"WARN: Many hyphens in domain name — phishing pattern")
            risk += 1

        score = min(100, risk * 10)
        return (
            f"URL PATTERN ANALYSIS for: {url}\n"
            f"Risk indicators: {risk} | Estimated static score: {score}/100\n"
            "Findings:\n" + "\n".join(f"  - {f}" for f in findings)
        )
    except Exception as e:
        return f"ERROR in URL pattern analysis: {e}"


@mcp.tool()
def inspect_http_headers(url: str) -> str:
    """
    Makes an HTTP GET request to the URL and inspects security response headers,
    SSL certificate validity, redirect chain, and server banner leakage.
    Returns a detailed header security assessment string.
    """
    findings = []
    risk = 0

    try:
        resp = requests.get(
            url, headers=_HEADERS,
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

# ==========================================
# SUNUCUYU ÇALIŞTIRMA
# ==========================================

if __name__ == "__main__":
    mcp.run(transport='stdio')