import os
import json
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

from analysis_report import finalize_report

MODEL_NAME = "llama-3.3-70b-versatile"

def _client() -> ChatOpenAI:
    return ChatOpenAI(
        model=MODEL_NAME,
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1",
        temperature=0.05,
        max_tokens=4096,
    )

async def _run_mcp_analysis_async(url: str) -> dict:
    # 1. MCP Sunucusuna Bağlan
    server_params = StdioServerParameters(
        command="python",
        args=["mcp_server.py"] # Sunucu dosyasının yolu
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

            static_text = extract_text(static_res) + "\n" + extract_text(header_res)
            dynamic_text = extract_text(dynamic_res)
            intel_text = extract_text(phish_res) + "\n" + extract_text(rep_res)

            # 3. LLM'e Bağımsız Olarak Gönder ve Sentezlet
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

            response = _client().invoke([
                SystemMessage(content=system_msg), 
                HumanMessage(content=human_msg)
            ])
            
            raw_text = (response.content or "").strip()
            
            # JSON'ı temizle ve parse et
            if "```json" in raw_text:
                raw_text = raw_text.split("```json")[1].split("```")[0].strip()
            elif "```" in raw_text:
                raw_text = raw_text.split("```")[1].split("```")[0].strip()
                
            report_data = json.loads(raw_text)
            
            # 4. Standart Aegis Formatına Dönüştür
            return finalize_report(report_data, url, "url", "mcp")


async def analyze_url(url: str) -> dict:
    return await _run_mcp_analysis_async(url)