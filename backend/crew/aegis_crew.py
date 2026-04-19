"""
Aegis AI — Agentic analysis pipeline using Groq API (OpenAI-compatible).

Implements a 3-agent sequential crew without the heavy CrewAI ML stack:
  Agent 1 — Static Analyst      (URL patterns + HTTP headers)
  Agent 2 — Dynamic Analyst     (Page content + JS analysis)
  Agent 3 — Intel Specialist    (Domain reputation + final JSON report)

Each agent receives the previous agent's findings as context, mirroring
CrewAI's Process.sequential behaviour.
"""

import os
import re
import json
import math
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional

from openai import OpenAI

from .tools.url_tools import analyze_url_patterns, inspect_http_headers
from .tools.content_tools import analyze_page_content, check_domain_reputation


# ─── Groq client (OpenAI-compatible) ────────────────────────────────────────

def _client() -> OpenAI:
    return OpenAI(
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
    )

MODEL = "llama-3.3-70b-versatile"


def _chat(client: OpenAI, messages: list[dict], temperature: float = 0.05) -> str:
    """Call the Groq LLM and return the response text."""
    resp = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        temperature=temperature,
        max_tokens=4096,
    )
    return resp.choices[0].message.content.strip()


# ─── JSON extraction helper ──────────────────────────────────────────────────

def _extract_json(text: str) -> Optional[dict]:
    """Try multiple strategies to extract a JSON object from LLM output."""
    text = text.strip()

    # 1. Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Markdown code fence
    m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass

    # 3. Largest brace block
    start, end = text.find('{'), text.rfind('}')
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass

    return None


# ─── Agent system prompt ─────────────────────────────────────────────────────

_STATIC_SYSTEM = """You are a senior cybersecurity analyst specializing in URL forensics and HTTP security.
You have been given tool output from automated analysis tools. Your job is to:
1. Read the tool outputs carefully
2. Summarize the key threat indicators you found
3. Estimate a numeric risk score (0-100) for the static phase based on the findings
Be concise, specific, and factual. Only report what the tools actually found."""

_DYNAMIC_SYSTEM = """You are an expert web threat analyst specializing in malicious page behavior detection.
You have been given tool output from automated page content analysis. Your job is to:
1. Read the tool output carefully
2. Summarize the key threat indicators found in the page content and JavaScript
3. Estimate a numeric risk score (0-100) for the dynamic phase based on the findings
Consider how the static analysis findings relate to the dynamic findings.
Be concise, specific, and factual."""

_INTEL_SYSTEM = """You are a principal threat intelligence analyst.
You synthesize multi-phase security findings into structured threat assessments.
You ALWAYS respond with a single valid JSON object and NOTHING else — no markdown fences,
no explanations before or after, just the raw JSON."""


# ─── URL analysis pipeline ───────────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """Run the 3-agent pipeline against a URL and return the report dict."""
    client = _client()

    # ── Agent 1 — Static Analysis ─────────────────────────────────────────────
    print(f"\n[Agent 1] Running static analysis on: {url}")
    url_pattern_output = analyze_url_patterns(url)
    header_output = inspect_http_headers(url)

    static_context = (
        f"=== URL PATTERN ANALYSIS ===\n{url_pattern_output}\n\n"
        f"=== HTTP HEADER INSPECTION ===\n{header_output}"
    )

    static_summary = _chat(client, [
        {"role": "system", "content": _STATIC_SYSTEM},
        {"role": "user", "content": (
            f"The target URL is: {url}\n\n"
            f"Here are the automated tool results:\n\n{static_context}\n\n"
            "Summarize the static phase findings and provide a static risk score (0-100)."
        )},
    ])
    print(f"[Agent 1] Done. Summary length: {len(static_summary)} chars")

    # ── Agent 2 — Dynamic Analysis ────────────────────────────────────────────
    print(f"\n[Agent 2] Running dynamic analysis on: {url}")
    content_output = analyze_page_content(url)

    dynamic_summary = _chat(client, [
        {"role": "system", "content": _DYNAMIC_SYSTEM},
        {"role": "user", "content": (
            f"The target URL is: {url}\n\n"
            f"STATIC ANALYSIS FINDINGS (from Agent 1):\n{static_summary}\n\n"
            f"=== PAGE CONTENT ANALYSIS ===\n{content_output}\n\n"
            "Summarize the dynamic phase findings and provide a dynamic risk score (0-100)."
        )},
    ])
    print(f"[Agent 2] Done. Summary length: {len(dynamic_summary)} chars")

    # ── Agent 3 — Threat Intel + Final Report ────────────────────────────────
    print(f"\n[Agent 3] Synthesizing threat intelligence report for: {url}")
    reputation_output = check_domain_reputation(url)

    schema_example = json.dumps({
        "verdict": "SUSPICIOUS",
        "riskScore": 62,
        "target": url,
        "targetType": "url",
        "scores": {"static": 55, "dynamic": 70, "intel": 50},
        "phases": {
            "static": {
                "name": "Static Analysis",
                "score": 55,
                "findings": [
                    {"label": "URL Length", "detail": "URL is 87 chars — moderately long", "status": "warn"},
                    {"label": "HTTPS", "detail": "Site uses HTTPS correctly", "status": "ok"},
                    {"label": "Security Headers", "detail": "Missing HSTS and CSP headers", "status": "alert"},
                ]
            },
            "dynamic": {
                "name": "Dynamic Analysis",
                "score": 70,
                "findings": [
                    {"label": "Password Form", "detail": "Login form found — verify legitimacy", "status": "warn"},
                    {"label": "Inline JavaScript", "detail": "No obfuscated JS patterns detected", "status": "ok"},
                    {"label": "External Scripts", "detail": "7 external scripts loaded", "status": "ok"},
                ]
            },
            "intel": {
                "name": "Threat Intelligence",
                "score": 50,
                "findings": [
                    {"label": "DNS Resolution", "detail": "Domain resolves to public IP", "status": "ok"},
                    {"label": "TLD Assessment", "detail": "TLD .com is standard", "status": "ok"},
                    {"label": "Domain Name", "detail": "Domain name length is normal", "status": "ok"},
                ]
            }
        },
        "mitigation": [
            "Verify the site's legitimacy before entering any credentials.",
            "Check the SSL certificate details match the expected organization.",
            "Enable browser security warnings and use a reputable password manager.",
        ]
    }, indent=2)

    final_report_raw = _chat(client, [
        {"role": "system", "content": _INTEL_SYSTEM},
        {"role": "user", "content": (
            f"Synthesize a complete threat report for: {url}\n\n"
            f"--- STATIC ANALYSIS SUMMARY (Agent 1) ---\n{static_summary}\n\n"
            f"--- DYNAMIC ANALYSIS SUMMARY (Agent 2) ---\n{dynamic_summary}\n\n"
            f"--- DOMAIN REPUTATION CHECK ---\n{reputation_output}\n\n"
            "Instructions:\n"
            "1. Assign scores (0-100) for each phase based on the findings above\n"
            "2. Compute: riskScore = round(0.35 * static + 0.40 * dynamic + 0.25 * intel)\n"
            "3. Verdict: riskScore >= 70 → MALICIOUS | riskScore >= 40 → SUSPICIOUS | else → CLEAN\n"
            "4. Extract 3-5 specific findings per phase from the summaries above\n"
            "5. Write 3-5 prioritized, actionable mitigation steps\n\n"
            "STRICT RULES:\n"
            "- status values MUST be exactly: 'alert', 'warn', or 'ok' (lowercase only)\n"
            "- verdict MUST be exactly: 'MALICIOUS', 'SUSPICIOUS', or 'CLEAN'\n"
            "- targetType MUST be exactly: 'url'\n"
            "- All scores MUST be integers 0-100\n"
            "- Each phase MUST have at least 3 findings\n"
            "- Output ONLY the JSON object, nothing else\n\n"
            f"Required JSON structure (follow exactly):\n{schema_example}"
        )},
    ])
    print(f"[Agent 3] Done. Raw output length: {len(final_report_raw)} chars")

    # ── Parse output ─────────────────────────────────────────────────────────
    report = _extract_json(final_report_raw)
    if not report:
        raise ValueError(
            "Agent 3 failed to produce valid JSON. Raw output:\n" + final_report_raw[:500]
        )

    # Add/override backend-generated fields
    report['id'] = str(uuid.uuid4())
    report['timestamp'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    report['target'] = url
    report['targetType'] = 'url'

    return report


# ─── File analysis (static heuristic — no execution) ─────────────────────────

_EXT_RISK = {
    'exe': 45, 'bat': 40, 'ps1': 40, 'vbs': 40, 'msi': 40,
    'dll': 35, 'scr': 45, 'pif': 45, 'cmd': 38, 'hta': 38,
    'js':  25, 'jar': 30, 'py':  20, 'php': 20, 'sh': 20,
    'pdf': 12, 'docx': 10, 'doc': 10, 'xls': 10, 'xlsx': 10,
    'zip': 8,  'iso': 15, 'dmg': 15, 'bin': 20, 'so': 20,
}
_HIGH_RISK_EXTS = {'exe', 'bat', 'ps1', 'vbs', 'msi', 'scr', 'pif', 'hta', 'dll'}
_MED_RISK_EXTS  = {'js', 'jar', 'py', 'php', 'sh', 'cmd'}
_TEXT_EXTS      = {'js', 'py', 'php', 'sh', 'bat', 'ps1', 'vbs', 'hta', 'cmd'}

_SCRIPT_SUSPICIOUS = [
    (rb'eval\s*\(', 'eval() — runtime code execution/obfuscation'),
    (rb'base64_decode', 'base64_decode — encoded payload in script'),
    (rb'system\s*\(', 'system() — executes OS commands'),
    (rb'exec\s*\(', 'exec() — process execution'),
    (rb'WScript\.Shell', 'WScript.Shell — Windows shell execution'),
    (rb'powershell', 'PowerShell reference — used in dropper scripts'),
    (rb'wget\s+http', 'wget download — fetches remote payload'),
    (rb'curl\s+http', 'curl download — fetches remote payload'),
    (rb'/dev/tcp/', 'Reverse shell via /dev/tcp'),
    (rb'certutil', 'certutil — LOLBin for downloading/decoding payloads'),
]

_MALWARE_API_STRINGS = [
    b'CreateRemoteThread', b'VirtualAllocEx', b'WriteProcessMemory',
    b'ShellExecute', b'RegSetValue', b'WScript.Shell',
    b'InternetOpen', b'URLDownloadToFile',
]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def analyze_file(filename: str, content: bytes) -> dict:
    """Static heuristic analysis for uploaded files (no execution)."""
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else 'unknown'
    size_kb = len(content) / 1024
    sha256 = hashlib.sha256(content).hexdigest()

    static_findings, dynamic_findings, intel_findings = [], [], []
    s_risk = _EXT_RISK.get(ext, 5)

    # ── Static phase ─────────────────────────────────────────────────────────
    if ext in _HIGH_RISK_EXTS:
        static_findings.append({"label": "File Extension", "detail": f".{ext} is a high-risk executable — primary malware delivery format", "status": "alert"})
    elif ext in _MED_RISK_EXTS:
        static_findings.append({"label": "File Extension", "detail": f".{ext} is a potentially dangerous script/code format", "status": "warn"})
    else:
        static_findings.append({"label": "File Extension", "detail": f".{ext} is a common document/archive format with lower inherent risk", "status": "ok"})

    if size_kb < 5:
        static_findings.append({"label": "File Size", "detail": f"Very small file ({size_kb:.1f} KB) — may be a dropper stub", "status": "warn"})
        s_risk += 10
    else:
        static_findings.append({"label": "File Size", "detail": f"File size {size_kb:.1f} KB — within normal range", "status": "ok"})

    entropy_val = _entropy(content)
    if entropy_val > 7.2:
        static_findings.append({"label": "Byte Entropy", "detail": f"Very high entropy ({entropy_val:.2f}/8) — likely packed or encrypted", "status": "alert"})
        s_risk += 25
    elif entropy_val > 6.5:
        static_findings.append({"label": "Byte Entropy", "detail": f"Elevated entropy ({entropy_val:.2f}/8) — possible compression/obfuscation", "status": "warn"})
        s_risk += 10
    else:
        static_findings.append({"label": "Byte Entropy", "detail": f"Normal entropy ({entropy_val:.2f}/8) — not packed/encrypted", "status": "ok"})

    static_findings.append({"label": "SHA-256 Hash", "detail": sha256, "status": "ok"})

    # ── Dynamic phase ─────────────────────────────────────────────────────────
    d_risk = 0
    if ext in _TEXT_EXTS:
        hits = 0
        for pattern, desc in _SCRIPT_SUSPICIOUS:
            if re.search(pattern, content, re.IGNORECASE):
                dynamic_findings.append({"label": "Suspicious Pattern", "detail": desc, "status": "alert"})
                d_risk += 15
                hits += 1
        if hits == 0:
            dynamic_findings.append({"label": "Script Content", "detail": "No obviously malicious patterns in script source", "status": "ok"})
    else:
        dynamic_findings.append({"label": "Binary Format", "detail": f"Binary .{ext} — static indicators assessed; sandbox needed for full dynamic analysis", "status": "warn"})
        if ext in _HIGH_RISK_EXTS:
            d_risk = s_risk  # mirror static risk for high-risk binaries

    if not dynamic_findings:
        dynamic_findings.append({"label": "Behavior", "detail": "No dynamic analysis available for this format", "status": "ok"})

    # ── Intel phase ───────────────────────────────────────────────────────────
    i_risk = 0
    found_api = [s.decode() for s in _MALWARE_API_STRINGS if s in content]
    if found_api:
        intel_findings.append({"label": "Suspicious API Strings", "detail": f"Malware-associated Windows API strings: {', '.join(found_api[:5])}", "status": "alert"})
        i_risk += 30
    else:
        intel_findings.append({"label": "API String Scan", "detail": "No known malware API strings found in binary data", "status": "ok"})

    intel_findings.append({"label": "AV Engine", "detail": "Real-time AV scan requires sandbox integration (planned feature)", "status": "warn"})
    intel_findings.append({"label": "File Reputation", "detail": f"SHA-256 {sha256[:16]}… — VirusTotal lookup requires API key (planned)", "status": "ok"})

    # ── Score calculation ─────────────────────────────────────────────────────
    s_score = min(100, s_risk)
    d_score = min(100, d_risk)
    i_score = min(100, i_risk)
    risk_score = round(0.35 * s_score + 0.40 * d_score + 0.25 * i_score)

    verdict = "MALICIOUS" if risk_score >= 70 else "SUSPICIOUS" if risk_score >= 40 else "CLEAN"

    if verdict == "MALICIOUS":
        mitigation = [
            "Do NOT execute or open this file.",
            "Quarantine the file immediately and isolate the source system.",
            "Submit the SHA-256 hash to VirusTotal for community analysis.",
            "Scan all connected drives for similar files.",
            "Report the incident to your security team.",
        ]
    elif verdict == "SUSPICIOUS":
        mitigation = [
            "Do not execute until reviewed by a security analyst.",
            "Submit to a sandboxed environment (e.g., Any.run) for dynamic analysis.",
            "Verify the file source and sender authenticity.",
            "Cross-reference the SHA-256 hash with threat intelligence databases.",
        ]
    else:
        mitigation = [
            "File appears benign based on static analysis.",
            "Always scan files with an up-to-date antivirus before opening.",
            "Validate the file source to ensure it has not been tampered with.",
        ]

    return {
        "id": str(uuid.uuid4()),
        "verdict": verdict,
        "riskScore": risk_score,
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "target": filename,
        "targetType": "file",
        "engine": "heuristic",
        "scores": {"static": s_score, "dynamic": d_score, "intel": i_score},
        "phases": {
            "static":  {"name": "Static Analysis",     "score": s_score, "findings": static_findings},
            "dynamic": {"name": "Dynamic Analysis",    "score": d_score, "findings": dynamic_findings},
            "intel":   {"name": "Threat Intelligence", "score": i_score, "findings": intel_findings},
        },
        "mitigation": mitigation,
    }
