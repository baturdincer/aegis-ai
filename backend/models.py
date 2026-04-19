from pydantic import BaseModel, Field
from typing import List, Literal
import uuid
from datetime import datetime


class UrlScanRequest(BaseModel):
    url: str
    engine: str = "crew"


class Finding(BaseModel):
    label: str
    detail: str
    status: Literal["alert", "warn", "ok"]


class PhaseResult(BaseModel):
    name: str
    score: int = Field(ge=0, le=100)
    findings: List[Finding]


class ScoreBreakdown(BaseModel):
    static: int = Field(ge=0, le=100)
    dynamic: int = Field(ge=0, le=100)
    intel: int = Field(ge=0, le=100)


class Phases(BaseModel):
    static: PhaseResult
    dynamic: PhaseResult
    intel: PhaseResult


class ThreatReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    verdict: Literal["MALICIOUS", "SUSPICIOUS", "CLEAN"]
    riskScore: int = Field(ge=0, le=100)
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    target: str
    targetType: Literal["url", "file"]
    engine: str = "crew"
    scores: ScoreBreakdown
    phases: Phases
    mitigation: List[str]


# Pydantic model used as CrewAI output_pydantic target (no id/timestamp — added by backend)
class CrewReportOutput(BaseModel):
    verdict: str
    riskScore: int
    target: str
    targetType: str
    engine: str = "crew"
    scores: ScoreBreakdown
    phases: Phases
    mitigation: List[str]
