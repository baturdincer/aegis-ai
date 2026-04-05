"""
Web page content analysis and domain reputation tools.
"""
import re
import socket
import ipaddress
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from crewai.tools import tool

TOP_BRANDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'instagram', 'twitter', 'netflix', 'linkedin', 'dropbox', 'adobe',
    'chase', 'wellsfargo', 'citibank', 'bankofamerica', 'ebay', 'dhl',
    'fedex', 'usps', 'irs',
]

FREE_HOSTING = {
    '000webhostapp.com', 'weebly.com', 'wix.com', 'jimdo.com',
    'wordpress.com', 'blogspot.com', 'tumblr.com', 'ucoz.com',
    'yolasite.com', 'atwebpages.com', 'freewha.com', 'x10host.com',
    'altervista.org', 'byethost.com', 'biz.nf', 'co.nf',
}

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
    '.download', '.loan', '.win', '.bid', '.stream', '.gdn',
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

_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}


@tool("Web Page Content Analyzer")
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
                            f"ALERT: Password form POSTs to external domain ({action_dom})"
                            " — credential harvesting"
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
        hidden = [
            f for f in iframes
            if 'display:none' in f.get('style', '').replace(' ', '').lower()
            or f.get('width') in ('0', '1')
            or f.get('height') in ('0', '1')
        ]
        if hidden:
            findings.append(f"ALERT: {len(hidden)} hidden iframe(s) — common drive-by download vector")
            risk += 3
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
                findings.append(
                    f"ALERT: Title references '{brand}' but domain is '{base_domain}'"
                    " — brand impersonation"
                )
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


@tool("Domain Reputation Checker")
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
        for brand in ['paypal', 'amazon', 'apple', 'microsoft', 'google',
                      'facebook', 'netflix', 'instagram', 'chase', 'ebay']:
            if brand in apex_name and brand != apex_name:
                findings.append(
                    f"ALERT: Brand '{brand}' embedded in domain '{domain}' — brand squatting"
                )
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


# Basic caching mechanism for the phishing DB
_PHISH_DB_CACHE = set()
_PHISH_DB_LAST_FETCH = 0

@tool("Check Phishing Databases")
def check_phishing_databases(url: str) -> str:
    """
    Checks if the URL is present in recognized public phishing databases (e.g., OpenPhish feed).
    Returns an assessment indicating if the URL is blacklisted.
    """
    global _PHISH_DB_CACHE, _PHISH_DB_LAST_FETCH
    import time
    
    # Refresh cache if older than 1 hour (3600s)
    current_time = time.time()
    if current_time - _PHISH_DB_LAST_FETCH > 3600 or not _PHISH_DB_CACHE:
        try:
            # Using OpenPhish free feed
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
    
    # Try slightly fuzzier matching (without trailing slashes or scheme differences)
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

