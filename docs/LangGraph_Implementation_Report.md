# Aegis AI - LangGraph Integration Report

## 1. Assignment Requirements
This report addresses the homework instructions:

- Include LangGraph in the project.
- Understand its purpose and implement it effectively.
- Keep LangGraph in the same project alongside CrewAI (both working).
- Define implementation steps clearly.
- LangSmith integration is helpful.
- Commit to Git and share Git account link.
- Submit a PDF report including screenshot(s) and implemented features.

## 2. What Was Implemented
LangGraph was integrated into the existing Aegis project without creating a new project.

### Added
- A LangGraph URL analysis pipeline with three nodes:
	- Static analysis
	- Dynamic analysis
	- Threat intelligence synthesis
- Engine switching in the existing API (`crew` or `langgraph`).
- Frontend engine selector for URL scans.
- Shared report schema so CrewAI and LangGraph output the same structure.
- Optional LangSmith support.

### Preserved
- Existing CrewAI URL pipeline remains active.
- Existing file-analysis flow remains active.

## 3. Why LangGraph
LangGraph provides explicit node-based orchestration and visible state transitions. This makes the analysis flow easier to reason about, debug, and discuss in class.

## 4. Architecture
- Frontend: React + Vite
- Backend: FastAPI
- URL orchestration engines:
	- CrewAI
	- LangGraph
- LLM backend: Groq OpenAI-compatible API
- Shared output validation: Pydantic report model

## 5. Step-by-Step Implementation

### Step 1 - Install backend dependencies
Added required packages in `backend/requirements.txt`:

```txt
langgraph>=0.2.0
langchain-openai>=0.2.0
langsmith>=0.1.0
```

### Step 2 - Create LangGraph pipeline
Created `backend/langgraph_pipeline.py` with:

- State definition (`UrlAnalysisState`)
- Graph nodes:
	- `_run_static`
	- `_run_dynamic`
	- `_run_intel`
- Graph topology:

```txt
START -> static -> dynamic -> intel -> END
```

### Step 3 - Reuse existing analysis tools
Reused tool layer from:

- `backend/crew/tools/url_tools.py`
- `backend/crew/tools/content_tools.py`

Important fix:
- CrewAI `@tool` wrappers are not directly callable as normal functions.
- Correct invocation used in LangGraph path: `tool.run(url)`.

### Step 4 - Keep one API endpoint and add engine routing
In existing `POST /api/scan/url` flow:

- `engine="crew"` routes to CrewAI pipeline
- `engine="langgraph"` routes to LangGraph pipeline

This keeps API surface simple and compatible.

### Step 5 - Keep one response schema
Both engines output same report structure, validated through shared report logic.

Result:
- Frontend report UI works identically regardless of selected engine.

### Step 6 - Add frontend engine selector
Dashboard URL scan mode now includes selector:

- CrewAI
- LangGraph

Selected engine is sent with scan request and displayed in report/history.

### Step 7 - Optional LangSmith support
LangSmith is available but treated as optional.

Recommended env setup when needed:

```env
ENABLE_LANGSMITH=true
LANGCHAIN_API_KEY=your_key
LANGCHAIN_PROJECT=aegis-ai
LANGCHAIN_TRACING_V2=true
```

## 6. Scoring and Verdict Rules
Risk score formula:

```txt
riskScore = round(0.35 * static + 0.40 * dynamic + 0.25 * intel)
```

Verdict:
- `MALICIOUS` if riskScore >= 70
- `SUSPICIOUS` if riskScore >= 40
- `CLEAN` otherwise

## 7. False Positive Optimization
After real tests, risk heuristics were tuned to reduce false positives on trusted domains.

Main improvements:
- Better registered-domain parsing for ccTLD cases (example: `.com.tr`).
- URL length scoring based on canonical URL separate from query length.
- Dynamic iframe risk tuned:
	- single external hidden iframe -> `warn`
	- multiple external hidden iframes -> `alert`
- Conservative low-risk calibration for trusted domains with weak evidence.

## 8. Verification Steps

### Run backend
```powershell
cd backend
..\.venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Run frontend
```powershell
cd ..
npm run dev
```

### Check health
```powershell
Invoke-WebRequest -UseBasicParsing http://localhost:8000/api/health | Select-Object -ExpandProperty Content
```

Expected:
```json
{"status":"ok","service":"Aegis Threat Analyzer","engines":["crew","langgraph"]}
```

## 9. Requirement Coverage Matrix
| Requirement | How it was satisfied |
|---|---|
| Include LangGraph | Added `backend/langgraph_pipeline.py` and wired it to API |
| Keep CrewAI working | Existing CrewAI flow preserved and selectable |
| Same project only | Integrated into current Aegis repository |
| Steps well defined | Section 5 documents step-by-step implementation |
| LangSmith helpful | Optional LangSmith support documented and supported |
| Git commit + account link | Work committed and links provided below |
| PDF with screenshot | Screenshot section and export instructions included |

## 10. Git Links
- GitHub account: <https://github.com/baturdincer>
- Repository: <https://github.com/baturdincer/aegis-ai>

## 11. Screenshot Section (Required for Submission)
Add at least one screenshot that shows:

- URL scan page with `CrewAI / LangGraph` selector
- Final LangGraph report output

Recommended filename:
- `docs/screenshot-langgraph-run.png`

Then include it in your PDF version of this report.

## 12. PDF Export
You can use either:

1. The LaTeX file prepared for this report:
	 - `docs/LangGraph_Implementation_Report.tex`
2. This markdown file exported to PDF from your editor.

If using LaTeX:

```powershell
pdflatex -interaction=nonstopmode -halt-on-error "docs/LangGraph_Implementation_Report.tex"
```

## 13. Presentation Preparation Notes
Be ready to explain in class:

- Why LangGraph was added although CrewAI already existed.
- Node/state flow design in LangGraph.
- Why shared schema reduces UI complexity.
- Tool invocation detail (`tool.run(url)`) and related runtime fix.
- How false positives were reduced and why those rules were chosen.
