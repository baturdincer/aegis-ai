from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
import os

from analysis_report import finalize_report
from .tools.url_tools import analyze_url_patterns, inspect_http_headers
from .tools.content_tools import analyze_page_content, check_domain_reputation, check_phishing_databases

# ---- MCP İÇİN YENİ EKLENEN İMPORTLAR ----
from mcp import StdioServerParameters
from crewai_tools import MCPServerAdapter

@CrewBase
class AegisCrew():
    """Aegis UI threat analysis crew"""

    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    def __init__(self):
        # ---- MCP SUNUCUSU AYARLARI ----
        # Örnek 1: Yerel bir SQLite veritabanındaki tehdit verilerine erişmek için MCP sunucusu
        # Ed Donner kursunda genelde npx veya uvx komutlarıyla harici sunucular çalıştırılır
        sqlite_mcp_params = StdioServerParameters(
            command="uvx", 
            args=["mcp-server-sqlite", "--db", "threat_intel.db"],
            env=os.environ.copy()
        )
        
        # Adaptörü kullanarak MCP sunucusundaki fonksiyonları CrewAI tool'larına çeviriyoruz
        self.mcp_adapter = MCPServerAdapter(sqlite_mcp_params)
        self.sqlite_mcp_tools = MCPServerAdapter(sqlite_mcp_params).tools

    @agent
    def static_analyst(self) -> Agent:
        return Agent(
            config=self.agents_config['static_analyst'],
            tools=[analyze_url_patterns, inspect_http_headers],
            verbose=True,
            llm="groq/llama-3.3-70b-versatile"
        )

    @agent
    def dynamic_analyst(self) -> Agent:
        return Agent(
            config=self.agents_config['dynamic_analyst'],
            tools=[analyze_page_content],
            verbose=True,
            llm="groq/llama-3.3-70b-versatile"
        )

    @agent
    def intel_specialist(self) -> Agent:
        return Agent(
            config=self.agents_config['intel_specialist'],
            # ---- MCP ARAÇLARINI AJANA EKLEME ----
            # Hem kendi yazdığınız araçları hem de MCP'den gelen araçları birleştiriyoruz
            tools=[check_domain_reputation, check_phishing_databases] + self.sqlite_mcp_tools,
            verbose=True,
            llm="groq/llama-3.3-70b-versatile"
        )

    @task
    def static_analysis_task(self) -> Task:
        return Task(
            config=self.tasks_config['static_analysis_task'],
            agent=self.static_analyst()
        )

    @task
    def dynamic_analysis_task(self) -> Task:
        return Task(
            config=self.tasks_config['dynamic_analysis_task'],
            agent=self.dynamic_analyst()
        )

    @task
    def intel_synthesis_task(self) -> Task:
        from models import CrewReportOutput
        return Task(
            config=self.tasks_config['intel_synthesis_task'],
            agent=self.intel_specialist(),
            output_pydantic=CrewReportOutput
        )

    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=self.agents, 
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
            memory=False
        )

def analyze_url(url: str) -> dict:
    """Wrapper function to instantiate the crew, run it, and inject final metadata"""
    inputs = {
        'url': url
    }
    
    # Run the crew
    crew_instance = AegisCrew().crew()
    result = crew_instance.kickoff(inputs=inputs)
    
    report = None
    if hasattr(result, 'pydantic') and result.pydantic:
        report = result.pydantic.model_dump()
    elif hasattr(result, 'json_dict') and result.json_dict:
        report = result.json_dict

    if not report:
        raise ValueError("CrewAI output did not return the expected Pydantic model representation.")

    return finalize_report(report, url, 'url', 'crew')

# Keep the heuristic function for file analysis from the previous impl,
# since file analysis is static and not requested to be changed to crew right now.
from .aegis_crew import analyze_file
