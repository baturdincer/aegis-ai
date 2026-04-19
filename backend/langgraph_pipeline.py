"""LangGraph implementation of the Aegis URL analysis pipeline."""

from __future__ import annotations

import json
import os
import re
from urllib.parse import urlparse
from typing import TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph

from analysis_report import finalize_report
from crew.tools.content_tools import analyze_page_content, check_domain_reputation, check_phishing_databases
from crew.tools.url_tools import analyze_url_patterns, inspect_http_headers


MODEL_NAME = "llama-3.3-70b-versatile"


class UrlAnalysisState(TypedDict, total=False):
    url: str
    static_tool_output: str
    header_tool_output: str
    dynamic_tool_output: str
    phishing_output: str
    reputation_output: str
    static_summary: str
    dynamic_summary: str
    intel_summary: str
    final_report_raw: str
    final_report: dict


def _client() -> ChatOpenAI:
    return ChatOpenAI(
        model=MODEL_NAME,
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
        temperature=0.05,
        max_tokens=4096,
    )


def _extract_json(text: str) -> dict | None:
    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except json.JSONDecodeError:
            pass

    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass

    return None


def _schema_example(url: str) -> str:
    return json.dumps({
        "verdict": "SUSPICIOUS",
        "riskScore": 62,
        "target": url,
        "targetType": "url",
        "engine": "langgraph",
        "scores": {"static": 55, "dynamic": 70, "intel": 50},
        "phases": {
            "static": {
                "name": "Static Analysis",
                "score": 55,
                "findings": [
                    {"label": "URL Length", "detail": "URL is 87 chars — moderately long", "status": "warn"},
                    {"label": "HTTPS", "detail": "Site uses HTTPS correctly", "status": "ok"},
                    {"label": "Security Headers", "detail": "Missing HSTS and CSP headers", "status": "alert"},
                ],
            },
            "dynamic": {
                "name": "Dynamic Analysis",
                "score": 70,
                "findings": [
                    {"label": "Password Form", "detail": "Login form found — verify legitimacy", "status": "warn"},
                    {"label": "Inline JavaScript", "detail": "No obfuscated JS patterns detected", "status": "ok"},
                    {"label": "External Scripts", "detail": "7 external scripts loaded", "status": "ok"},
                ],
            },
            "intel": {
                "name": "Threat Intelligence",
                "score": 50,
                "findings": [
                    {"label": "DNS Resolution", "detail": "Domain resolves to public IP", "status": "ok"},
                    {"label": "TLD Assessment", "detail": "TLD .com is standard", "status": "ok"},
                    {"label": "Domain Name", "detail": "Domain name length is normal", "status": "ok"},
                ],
            },
        },
        "mitigation": [
            "Verify the site's legitimacy before entering any credentials.",
            "Check the SSL certificate details match the expected organization.",
            "Enable browser security warnings and use a reputable password manager.",
        ],
    }, indent=2)


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


def _invoke(messages: list) -> str:
    response = _client().invoke(messages)
    return (response.content or "").strip()


def _tool_run(tool, url: str) -> str:
    """Execute a CrewAI Tool wrapper and return its string output."""
    return tool.run(url)


def _extract_estimated_score(text: str) -> int:
    """Extract '<... score: N/100>' from tool outputs."""
    match = re.search(r"Estimated\s+[a-zA-Z\s]*score:\s*(\d{1,3})/100", text)
    if not match:
        return 0
    value = int(match.group(1))
    return max(0, min(100, value))


def _contains_strong_alert(text: str) -> bool:
    """Return True if tool output contains strong alert indicators."""
    upper = (text or "").upper()
    if "ALERT:" not in upper:
        return False
    strong_tokens = (
        "PRESENT IN OPENPHISH",
        "MATCHES ENTRY IN OPENPHISH",
        "URL IS PRESENT",
        "PUNYCODE DOMAIN",
        "IP ADDRESS USED AS HOST",
        "CREDENTIAL HARVESTING",
        "EXTERNAL DOMAIN",
        "HOMOGLYPH",
    )
    return any(token in upper for token in strong_tokens)


def _is_low_signal_hidden_iframe_alert(item: dict) -> bool:
    label = (item.get("label") or "").lower()
    detail = (item.get("detail") or "").lower()
    return "hidden iframe" in label and ("1 hidden iframe" in detail or "single hidden iframe" in detail)


def _merge_minimum_phase_scores(report: dict, static_floor: int, dynamic_floor: int, intel_floor: int) -> dict:
    """Ensure phase scores cannot fall below deterministic tool-based floors."""
    report.setdefault("scores", {})
    report.setdefault("phases", {})

    def _safe(value) -> int:
        try:
            return max(0, min(100, int(value)))
        except (TypeError, ValueError):
            return 0

    current_static = _safe(report.get("scores", {}).get("static", report.get("phases", {}).get("static", {}).get("score", 0)))
    current_dynamic = _safe(report.get("scores", {}).get("dynamic", report.get("phases", {}).get("dynamic", {}).get("score", 0)))
    current_intel = _safe(report.get("scores", {}).get("intel", report.get("phases", {}).get("intel", {}).get("score", 0)))

    static_score = max(current_static, _safe(static_floor))
    dynamic_score = max(current_dynamic, _safe(dynamic_floor))
    intel_score = max(current_intel, _safe(intel_floor))

    report["scores"]["static"] = static_score
    report["scores"]["dynamic"] = dynamic_score
    report["scores"]["intel"] = intel_score

    if "static" in report["phases"]:
        report["phases"]["static"]["score"] = static_score
    if "dynamic" in report["phases"]:
        report["phases"]["dynamic"]["score"] = dynamic_score
    if "intel" in report["phases"]:
        report["phases"]["intel"]["score"] = intel_score

    return report


def _enforce_threat_floor(
    report: dict,
    static_tool_output: str,
    header_tool_output: str,
    dynamic_tool_output: str,
    phishing_output: str,
    reputation_output: str,
) -> dict:
    """Prevent CLEAR/CLEAN verdicts when deterministic tool signals indicate threat."""

    def _set_floor(min_risk: int, verdict: str | None = None) -> None:
        current = int(report.get("riskScore", 0))
        if current < min_risk:
            report["riskScore"] = min_risk
        if verdict is not None:
            report["verdict"] = verdict

    phishing_upper = (phishing_output or "").upper()
    if "ALERT: URL IS PRESENT IN OPENPHISH DATABASE" in phishing_upper or "ALERT: URL MATCHES ENTRY IN OPENPHISH DATABASE" in phishing_upper:
        _set_floor(90, "MALICIOUS")
        return report

    tool_outputs = [
        static_tool_output,
        header_tool_output,
        dynamic_tool_output,
        phishing_output,
        reputation_output,
    ]
    strong_hits = sum(1 for output in tool_outputs if _contains_strong_alert(output or ""))

    phases = report.get("phases", {})
    findings = []
    for phase_name in ("static", "dynamic", "intel"):
        findings.extend(phases.get(phase_name, {}).get("findings", []))
    alert_findings = [item for item in findings if (item.get("status") or "").lower() == "alert"]
    significant_alerts = [item for item in alert_findings if not _is_low_signal_hidden_iframe_alert(item)]

    if strong_hits >= 2:
        _set_floor(70, "MALICIOUS")
    elif strong_hits == 1:
        _set_floor(45, "SUSPICIOUS")

    if len(significant_alerts) >= 2:
        _set_floor(55, "SUSPICIOUS")
    elif len(significant_alerts) == 1:
        _set_floor(40, "SUSPICIOUS")

    return report


def _apply_low_risk_calibration(url: str, report: dict) -> dict:
    """Reduce false positives for legitimate domains when no alert findings exist."""
    phases = report.get("phases", {})
    findings = []
    for phase_name in ("static", "dynamic", "intel"):
        findings.extend(phases.get(phase_name, {}).get("findings", []))

    alerts = [f for f in findings if (f.get("status") or "").lower() == "alert"]

    has_alert = any(not _is_low_signal_hidden_iframe_alert(item) for item in alerts)
    domain = urlparse(url).netloc.lower()
    trusted_suffixes = (".com", ".com.tr", ".org.tr", ".gov.tr", ".edu.tr")
    domain_looks_normal = any(domain.endswith(sfx) for sfx in trusted_suffixes)

    if has_alert or not domain_looks_normal:
        return report

    score = int(report.get("riskScore", 0))
    if score < 40:
        return report

    # If all findings are OK/WARN and intel is clean, be conservative with suspicious verdict.
    intel_score = int(report.get("scores", {}).get("intel", 0))
    static_score = int(report.get("scores", {}).get("static", 0))
    dynamic_score = int(report.get("scores", {}).get("dynamic", 0))
    if intel_score <= 10 and static_score <= 25 and dynamic_score <= 35:
        report["riskScore"] = 35
        report["verdict"] = "CLEAN"
    return report


def _normalize_report_scores(report: dict) -> dict:
    """Recompute total risk and verdict from phase scores deterministically."""
    scores = report.get("scores", {}) or {}
    phases = report.get("phases", {}) or {}

    def _safe_score(value) -> int:
        try:
            return max(0, min(100, int(value)))
        except (TypeError, ValueError):
            return 0

    static_score = _safe_score(scores.get("static", phases.get("static", {}).get("score", 0)))
    dynamic_score = _safe_score(scores.get("dynamic", phases.get("dynamic", {}).get("score", 0)))
    intel_score = _safe_score(scores.get("intel", phases.get("intel", {}).get("score", 0)))

    report.setdefault("scores", {})
    report["scores"]["static"] = static_score
    report["scores"]["dynamic"] = dynamic_score
    report["scores"]["intel"] = intel_score

    if "static" in phases:
        phases["static"]["score"] = static_score
    if "dynamic" in phases:
        phases["dynamic"]["score"] = dynamic_score
    if "intel" in phases:
        phases["intel"]["score"] = intel_score

    risk_score = round(0.35 * static_score + 0.40 * dynamic_score + 0.25 * intel_score)
    report["riskScore"] = risk_score
    report["verdict"] = "MALICIOUS" if risk_score >= 70 else "SUSPICIOUS" if risk_score >= 40 else "CLEAN"

    return report


def _run_static(state: UrlAnalysisState) -> UrlAnalysisState:
    url = state["url"]
    static_tool_output = _tool_run(analyze_url_patterns, url)
    header_tool_output = _tool_run(inspect_http_headers, url)
    static_context = (
        f"=== URL PATTERN ANALYSIS ===\n{static_tool_output}\n\n"
        f"=== HTTP HEADER INSPECTION ===\n{header_tool_output}"
    )

    static_score = round((_extract_estimated_score(static_tool_output) + _extract_estimated_score(header_tool_output)) / 2)
    summary = (
        f"{static_context}\n\n"
        f"Deterministic static score from tools: {static_score}/100\n"
        "Rule: Preserve tool severities exactly; do not upgrade OK findings to WARN/ALERT."
    )

    return {
        "static_tool_output": static_tool_output,
        "header_tool_output": header_tool_output,
        "static_summary": summary,
    }


def _run_dynamic(state: UrlAnalysisState) -> UrlAnalysisState:
    url = state["url"]
    dynamic_tool_output = _tool_run(analyze_page_content, url)
    dynamic_score = _extract_estimated_score(dynamic_tool_output)
    summary = (
        f"=== PAGE CONTENT ANALYSIS ===\n{dynamic_tool_output}\n\n"
        f"Deterministic dynamic score from tools: {dynamic_score}/100\n"
        "Rule: If the tool marks a finding as OK, keep it as OK."
    )

    return {
        "dynamic_tool_output": dynamic_tool_output,
        "dynamic_summary": summary,
    }


def _run_intel(state: UrlAnalysisState) -> UrlAnalysisState:
    url = state["url"]
    reputation_output = _tool_run(check_domain_reputation, url)
    phishing_output = _tool_run(check_phishing_databases, url)

    raw = _invoke([
        SystemMessage(content=_INTEL_SYSTEM),
        HumanMessage(content=(
            f"Synthesize a complete threat report for: {url}\n\n"
            f"--- URL PATTERN TOOL OUTPUT ---\n{state['static_tool_output']}\n\n"
            f"--- HEADER TOOL OUTPUT ---\n{state['header_tool_output']}\n\n"
            f"--- PAGE CONTENT TOOL OUTPUT ---\n{state['dynamic_tool_output']}\n\n"
            f"--- PHISHING DATABASE CHECK ---\n{phishing_output}\n\n"
            f"--- DOMAIN REPUTATION CHECK ---\n{reputation_output}\n\n"
            "Instructions:\n"
            "1. Assign scores (0-100) for each phase based on the findings above\n"
            "2. Compute: riskScore = round(0.35 * static + 0.40 * dynamic + 0.25 * intel)\n"
            "3. Verdict: riskScore >= 70 -> MALICIOUS | riskScore >= 40 -> SUSPICIOUS | else -> CLEAN\n"
            "4. Extract 3-5 specific findings per phase from the summaries above\n"
            "5. Write 3-5 prioritized, actionable mitigation steps\n\n"
            "STRICT RULES:\n"
            "- status values MUST be exactly: 'alert', 'warn', or 'ok' (lowercase only)\n"
            "- verdict MUST be exactly: 'MALICIOUS', 'SUSPICIOUS', or 'CLEAN'\n"
            "- targetType MUST be exactly: 'url'\n"
            "- All scores MUST be integers 0-100\n"
            "- Each phase MUST have at least 3 findings\n"
            "- NEVER escalate an explicit OK tool finding to WARN or ALERT\n"
            "- Output ONLY the JSON object, nothing else\n\n"
            f"Required JSON structure (follow exactly):\n{_schema_example(url)}"
        )),
    ])

    report = _extract_json(raw)
    if not report:
        raise ValueError("LangGraph failed to produce valid JSON. Raw output:\n" + raw[:500])

    # Deterministic score floors from tool outputs to prevent under-reporting by LLM.
    static_floor = round((
        _extract_estimated_score(state["static_tool_output"]) +
        _extract_estimated_score(state["header_tool_output"])
    ) / 2)
    dynamic_floor = _extract_estimated_score(state["dynamic_tool_output"])
    intel_floor = max(
        _extract_estimated_score(phishing_output),
        _extract_estimated_score(reputation_output),
    )

    # Hard escalation when phishing DB confirms the URL.
    if "ALERT: URL IS PRESENT IN OPENPHISH DATABASE" in phishing_output.upper() or "ALERT: URL MATCHES ENTRY IN OPENPHISH DATABASE" in phishing_output.upper():
        intel_floor = max(intel_floor, 95)

    report = _merge_minimum_phase_scores(report, static_floor, dynamic_floor, intel_floor)
    report = _normalize_report_scores(report)
    report = _enforce_threat_floor(
        report,
        state.get("static_tool_output", ""),
        state.get("header_tool_output", ""),
        state.get("dynamic_tool_output", ""),
        phishing_output,
        reputation_output,
    )

    # Apply low-risk calibration only when there is no strong tool-level alert.
    strong_tool_alert = any([
        _contains_strong_alert(state.get("static_tool_output", "")),
        _contains_strong_alert(state.get("header_tool_output", "")),
        _contains_strong_alert(state.get("dynamic_tool_output", "")),
        _contains_strong_alert(phishing_output),
        _contains_strong_alert(reputation_output),
    ])
    if not strong_tool_alert:
        report = _apply_low_risk_calibration(url, report)

    return {
        "reputation_output": reputation_output,
        "phishing_output": phishing_output,
        "final_report_raw": raw,
        "final_report": report,
    }


def _build_graph():
    graph = StateGraph(UrlAnalysisState)
    graph.add_node("static", _run_static)
    graph.add_node("dynamic", _run_dynamic)
    graph.add_node("intel", _run_intel)
    graph.add_edge(START, "static")
    graph.add_edge("static", "dynamic")
    graph.add_edge("dynamic", "intel")
    graph.add_edge("intel", END)
    return graph.compile()


_GRAPH = _build_graph()


def analyze_url(url: str) -> dict:
    """Run the LangGraph pipeline against a URL and return the validated report."""
    result = _GRAPH.invoke({"url": url})
    report = result.get("final_report")
    if not report:
        raise ValueError("LangGraph pipeline did not return a final report.")
    return finalize_report(report, url, "url", "langgraph")
