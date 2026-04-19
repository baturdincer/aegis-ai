"""LangGraph implementation of the Aegis URL analysis pipeline."""

from __future__ import annotations

import json
import os
import re
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


def _run_static(state: UrlAnalysisState) -> UrlAnalysisState:
    url = state["url"]
    static_context = (
        f"=== URL PATTERN ANALYSIS ===\n{analyze_url_patterns(url)}\n\n"
        f"=== HTTP HEADER INSPECTION ===\n{inspect_http_headers(url)}"
    )

    summary = _invoke([
        SystemMessage(content=_STATIC_SYSTEM),
        HumanMessage(content=(
            f"The target URL is: {url}\n\n"
            f"Here are the automated tool results:\n\n{static_context}\n\n"
            "Summarize the static phase findings and provide a static risk score (0-100)."
        )),
    ])

    return {"static_summary": summary}


def _run_dynamic(state: UrlAnalysisState) -> UrlAnalysisState:
    url = state["url"]
    summary = _invoke([
        SystemMessage(content=_DYNAMIC_SYSTEM),
        HumanMessage(content=(
            f"The target URL is: {url}\n\n"
            f"STATIC ANALYSIS FINDINGS (from Agent 1):\n{state['static_summary']}\n\n"
            f"=== PAGE CONTENT ANALYSIS ===\n{analyze_page_content(url)}\n\n"
            "Summarize the dynamic phase findings and provide a dynamic risk score (0-100)."
        )),
    ])

    return {"dynamic_summary": summary}


def _run_intel(state: UrlAnalysisState) -> UrlAnalysisState:
    url = state["url"]
    reputation_output = check_domain_reputation(url)
    phishing_output = check_phishing_databases(url)

    raw = _invoke([
        SystemMessage(content=_INTEL_SYSTEM),
        HumanMessage(content=(
            f"Synthesize a complete threat report for: {url}\n\n"
            f"--- STATIC ANALYSIS SUMMARY (LangGraph node 1) ---\n{state['static_summary']}\n\n"
            f"--- DYNAMIC ANALYSIS SUMMARY (LangGraph node 2) ---\n{state['dynamic_summary']}\n\n"
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
            "- Output ONLY the JSON object, nothing else\n\n"
            f"Required JSON structure (follow exactly):\n{_schema_example(url)}"
        )),
    ])

    report = _extract_json(raw)
    if not report:
        raise ValueError("LangGraph failed to produce valid JSON. Raw output:\n" + raw[:500])

    return {"final_report_raw": raw, "final_report": report}


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
