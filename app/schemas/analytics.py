from pydantic import BaseModel
from typing import Optional, List, Dict


# ─── Overview ────────────────────────────────────────────────────

class PeriodSchema(BaseModel):
    start: str
    end: str


class MetricsSchema(BaseModel):
    total_prompts: int
    prompts_with_pii: int
    pii_detection_rate: float
    total_entities_detected: int
    prompts_blocked: int
    prompts_overridden: int


class DailyActivityItem(BaseModel):
    date: str
    prompts: int
    pii_detected: int


class OverviewResponse(BaseModel):
    period: PeriodSchema
    metrics: MetricsSchema
    entity_breakdown: Dict[str, int]
    platform_breakdown: Dict[str, int]
    daily_activity: List[DailyActivityItem]


# ─── Activity Log ────────────────────────────────────────────────

class ActivityLogUser(BaseModel):
    id: int
    email: str
    full_name: Optional[str] = None


class ActivityLogItem(BaseModel):
    id: int
    user: ActivityLogUser
    original_prompt: str
    redacted_prompt: Optional[str] = None
    entities_detected: int
    entity_types: Optional[List[str]] = None
    ai_platform: Optional[str] = None
    was_blocked: bool
    was_overridden: bool
    created_at: str


class PaginationSchema(BaseModel):
    page: int
    limit: int
    total: int
    pages: int


class ActivityLogResponse(BaseModel):
    logs: List[ActivityLogItem]
    pagination: PaginationSchema
