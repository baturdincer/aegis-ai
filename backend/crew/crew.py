"""
Aegis Threat Analyzer Crew.
Implementation using the official CrewAI @CrewBase decorators and YAML config
as taught in Ed Donner's Complete Agentic AI Engineering Course.
"""

from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
import os
import uuid
from datetime import datetime, timezone

from .tools.url_tools import analyze_url_patterns, inspect_http_headers
from .tools.content_tools import analyze_page_content, check_domain_reputation, check_phishing_databases

# Need to set os.environ for Groq API via LiteLLM which crewai uses natively
# CrewAI allows specifying LLM simply by setting the environment variable or via llm param.
# For Ed Donner's format, setting the LLM string inside the Agent or relying on the model is typical.
# By default CrewAI will use OPENAI_API_KEY if we specify openai/. 
# We can just tell it to use the groq/model string.

@CrewBase
class AegisCrew():
    """Aegis UI threat analysis crew"""

    # Tell CrewBase where the config files are located relative to this file
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    def __init__(self):
        # Ensure CrewAI uses the Groq API key via LiteLLM
        # LiteLLM looks for GROQ_API_KEY when the model string is "groq/..."
        pass

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
            tools=[check_domain_reputation, check_phishing_databases],
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
        """Creates the Aegis Threat Analyzer crew"""
        return Crew(
            agents=self.agents, # Automatically accumulated by the @agent decorator
            tasks=self.tasks, # Automatically accumulated by the @task decorator
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

    # Add backend-generated fields that the frontend expects
    report['id'] = str(uuid.uuid4())
    report['timestamp'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    report['target'] = url
    report['targetType'] = 'url'
    
    return report

# Keep the heuristic function for file analysis from the previous impl,
# since file analysis is static and not requested to be changed to crew right now.
from .aegis_crew import analyze_file
