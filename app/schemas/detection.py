from pydantic import BaseModel, Field
from typing import Optional, List, Dict


# ─── Request Schemas ─────────────────────────────────────────────

class ScanRequest(BaseModel):
    text: str = Field(..., max_length=50000, description="Text to scan for PII")
    session_id: Optional[str] = Field(None, description="Session ID for entity linking")
    ai_platform: Optional[str] = Field(
        None, description="AI platform: chatgpt, claude, other"
    )


# ─── Response Schemas ────────────────────────────────────────────

class DetectedEntity(BaseModel):
    type: str
    text: str
    start: int
    end: int
    confidence: float


class ScanResponse(BaseModel):
    safe: bool
    entities: List[DetectedEntity]
    redacted_text: str
    redaction_mapping: Dict[str, str]
    latency_ms: int
    log_id: int
