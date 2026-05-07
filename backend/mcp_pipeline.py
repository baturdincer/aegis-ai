import os
import json
import re
import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from analysis_report import finalize_report

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

MODEL_NAME = "gpt-4o-mini"

def _client() -> ChatOpenAI:
    return ChatOpenAI(
        model=MODEL_NAME,
        api_key=os.getenv("OPENAI_API_KEY"),
        temperature=0.05,
        max_tokens=4096,
    )

def _extract_score(text: str, *, pattern: str) -> int:
    """
    Extract first integer score matched by `pattern`.
    Example pattern: r"Estimated static score: (\\d+)/100"
    """
    m = re.search(pattern, text or "")
    if not m:
        return 0
    try:
        return int(m.group(1))
    except Exception:
        return 0


def _parse_findings(text: str) -> list[dict]:
    """
    Parse MCP tool output lines like:
      - OK: ...
      - WARN: ...
      - ALERT: ...
    Returns list of Finding dicts compatible with pydantic models.
    """
    lines = (text or "").splitlines()
    start_idx = None
    for i, line in enumerate(lines):
        if line.strip() == "Findings:":
            start_idx = i + 1
            break

    if start_idx is None:
        return []

    findings: list[dict] = []
    for line in lines[start_idx:]:
        m = re.match(r"^\s*-\s*(OK|WARN|ALERT):\s*(.*)\s*$", line)
        if not m:
            continue
        label_raw = m.group(1)
        detail = (m.group(2) or "").strip()
        if label_raw == "ALERT":
            status = "alert"
        elif label_raw == "WARN":
            status = "warn"
        else:
            status = "ok"
        findings.append({"label": label_raw, "detail": detail, "status": status})
    return findings


def _heuristic_report_from_tools(
    *,
    url: str,
    static_pattern_text: str,
    header_text: str,
    dynamic_text: str,
    phish_text: str,
    rep_text: str,
) -> dict:
    # Scores (tool strings are deterministic in this repo).
    static_url_patterns = _extract_score(
        static_pattern_text,
        pattern=r"Estimated static score:\s*(\d+)/100",
    )
    static_headers = _extract_score(
        header_text,
        pattern=r"Estimated header score:\s*(\d+)/100",
    )
    dynamic_score = _extract_score(
        dynamic_text,
        pattern=r"Estimated dynamic score:\s*(\d+)/100",
    )
    phish_intel = _extract_score(
        phish_text,
        pattern=r"Estimated intel score:\s*(\d+)/100",
    )
    rep_intel = _extract_score(
        rep_text,
        pattern=r"Estimated intel score:\s*(\d+)/100",
    )

    static_score = min(100, static_url_patterns + static_headers)
    intel_score = min(100, phish_intel + rep_intel)
    dynamic_score = min(100, dynamic_score)

    risk_score = round(0.35 * static_score + 0.40 * dynamic_score + 0.25 * intel_score)
    risk_score = max(0, min(100, int(risk_score)))

    if risk_score >= 70:
        verdict = "MALICIOUS"
    elif risk_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    findings_static = _parse_findings(static_pattern_text) + _parse_findings(header_text)
    findings_dynamic = _parse_findings(dynamic_text)
    findings_intel = _parse_findings(phish_text) + _parse_findings(rep_text)

    if verdict == "MALICIOUS":
        mitigation = [
            "Block access to the URL across all organizational networks.",
            "Notify users about the phishing threat and educate on recognizing similar URLs.",
            "Implement web filtering solutions that can classify and block such malicious activities.",
        ]
    elif verdict == "SUSPICIOUS":
        mitigation = [
            "Quarantine or restrict access to the URL until further verification completes.",
            "Monitor for user reports and block the URL if additional indicators confirm abuse.",
            "Add URL/domain indicators to your security filters and review related traffic.",
        ]
    else:
        mitigation = [
            "Allow access with standard monitoring and logging.",
            "Keep an eye on domain reputation changes and security advisories.",
            "Re-run analysis periodically to catch updates to page behavior.",
        ]

    return {
        "verdict": verdict,
        "riskScore": risk_score,
        "scores": {
            "static": static_score,
            "dynamic": dynamic_score,
            "intel": intel_score,
        },
        "phases": {
            "static": {"name": "Static Analysis", "score": static_score, "findings": findings_static[:10]},
            "dynamic": {"name": "Dynamic Analysis", "score": dynamic_score, "findings": findings_dynamic[:10]},
            "intel": {"name": "Threat Intelligence", "score": intel_score, "findings": findings_intel[:10]},
        },
        "mitigation": mitigation,
    }


async def _run_mcp_analysis_async(url: str) -> dict:
    # 1. MCP Sunucusuna Bağlan

    current_dir = os.path.dirname(os.path.abspath(__file__))
    server_path = os.path.join(current_dir, "mcp_server.py")

    server_params = StdioServerParameters(
        command="uv",                # Komutumuz doğrudan uv
        args=["run", server_path]    # uv'ye "run" komutunu ve dosya yolunu veriyoruz
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 2. Araçları MCP üzerinden doğrudan çağır
            try:
                static_res = await session.call_tool("analyze_url_patterns", arguments={"url": url})
                header_res = await session.call_tool("inspect_http_headers", arguments={"url": url})
                dynamic_res = await session.call_tool("analyze_page_content", arguments={"url": url})
                phish_res = await session.call_tool("check_phishing_databases", arguments={"url": url})
                rep_res = await session.call_tool("check_domain_reputation", arguments={"url": url})
            except Exception as e:
                raise RuntimeError(f"MCP Sunucusu ile iletişim kurulamadı. Sunucunun ayakta olduğundan emin olun: {e}")

            # MCP sonuçlarından metinleri çıkar
            def extract_text(res):
                return res.content[0].text if res.content else ""

            static_pattern_text = extract_text(static_res)
            header_text = extract_text(header_res)
            dynamic_text = extract_text(dynamic_res)
            phish_text = extract_text(phish_res)
            rep_text = extract_text(rep_res)

            openai_key = os.getenv("OPENAI_API_KEY")
            heuristic_kwargs = dict(
                url=url,
                static_pattern_text=static_pattern_text,
                header_text=header_text,
                dynamic_text=dynamic_text,
                phish_text=phish_text,
                rep_text=rep_text,
            )

            # 3. LLM'e Bağımsız Olarak Gönder ve Sentezlet
            static_text = static_pattern_text + "\n" + header_text
            intel_text = phish_text + "\n" + rep_text
            system_msg = """You are a principal threat intelligence analyst.
            You synthesize tool findings into structured threat assessments.
            You ALWAYS respond with a single valid JSON object and NOTHING else."""
            
            human_msg = f"""Synthesize a complete threat report for: {url}
            
            --- STATIC PHASE OUTPUT ---
            {static_text}
            
            --- DYNAMIC PHASE OUTPUT ---
            {dynamic_text}
            
            --- THREAT INTEL PHASE OUTPUT ---
            {intel_text}
            
            Instructions:
            1. Assign scores (0-100) for static, dynamic, and intel phases.
            2. Compute riskScore = round(0.35 * static + 0.40 * dynamic + 0.25 * intel)
            3. Verdict: riskScore >= 70 -> MALICIOUS | riskScore >= 40 -> SUSPICIOUS | else -> CLEAN
            4. Extract 3-5 specific findings per phase and format as JSON matching the Aegis schema.
            5. Provide 3 prioritized mitigation steps.
            """
            
            # OpenAI key varsa dene; herhangi bir hata olursa deterministik fallback'e dön.
            if openai_key:
                try:
                    response = _client().invoke(
                        [
                            SystemMessage(content=system_msg),
                            HumanMessage(content=human_msg),
                        ]
                    )

                    raw_text = (response.content or "").strip()

                    # JSON'ı temizle ve parse et
                    if "```json" in raw_text:
                        raw_text = raw_text.split("```json")[1].split("```")[0].strip()
                    elif "```" in raw_text:
                        raw_text = raw_text.split("```")[1].split("```")[0].strip()

                    report_data = json.loads(raw_text)
                    # 4. Standart Aegis Formatına Dönüştür
                    return finalize_report(report_data, url, "url", "mcp")
                except Exception:
                    # AnyIO TaskGroup ile "unhandled errors" gibi yüzey hatalara düşmemek için:
                    # OpenAI/JSON parse/LLM hatalarında doğrudan deterministic fallback döndür.
                    return finalize_report(_heuristic_report_from_tools(**heuristic_kwargs), url, "url", "mcp")

            # 2. LLM sentezi atlandıysa deterministik fallback
            return finalize_report(_heuristic_report_from_tools(**heuristic_kwargs), url, "url", "mcp")


async def analyze_url(url: str) -> dict:
    return await _run_mcp_analysis_async(url)