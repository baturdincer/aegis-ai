"""Shared threat-report helpers for all backend analysis engines."""

from datetime import datetime, timezone
import uuid

from models import ThreatReport


def finalize_report(report: dict, target: str, target_type: str, engine: str) -> dict:
    """Attach common metadata and validate the final report shape."""
    payload = dict(report)
    payload["id"] = payload.get("id") or str(uuid.uuid4())
    payload["timestamp"] = payload.get("timestamp") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload["target"] = target
    payload["targetType"] = target_type
    payload["engine"] = engine

    validated = ThreatReport.model_validate(payload)
    return validated.model_dump()