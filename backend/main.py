"""
Aegis Threat Analyzer — FastAPI entry point.
"""
from dotenv import load_dotenv
load_dotenv()  # Must be first — loads GROQ_API_KEY before crewai imports

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from models import UrlScanRequest
from crew.aegis_crew import analyze_url, analyze_file

app = FastAPI(
    title="Aegis Threat Analyzer API",
    version="1.0.0",
    description="AI-powered website and file security analysis using CrewAI + Groq.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Aegis Threat Analyzer"}


@app.post("/api/scan/url")
async def scan_url(request: UrlScanRequest):
    """
    Analyze a URL using the 3-agent CrewAI pipeline:
    Static Analyst → Dynamic Analyst → Threat Intel Specialist.
    Returns a full threat report matching the frontend schema.
    """
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="URL cannot be empty.")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="URL must start with http:// or https://")

    try:
        result = analyze_url(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...)):
    """
    Heuristic static analysis for uploaded files.
    Checks extension risk, byte entropy, and suspicious string patterns.
    Returns a full threat report matching the frontend schema.
    """
    try:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=422, detail="Uploaded file is empty.")
        result = analyze_file(file.filename or "unknown", content)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
