import time
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import User, PromptLog, DetectionPattern
from app.schemas.detection import ScanRequest, ScanResponse, DetectedEntity
from app.services.detector import pii_detector
from app.services.session_manager import session_manager
from app.dependencies import get_current_user

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
async def scan_prompt(
    request: ScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Scan text for PII and return redacted version.

    Maintains entity consistency within sessions using pseudonymization.
    Logs all scans to prompt_logs for audit.
    """
    start_time = time.time()

    # Validate text length
    if len(request.text) > 50000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Text exceeds maximum length of 50,000 characters",
        )

    # Session management
    sid = request.session_id or str(uuid.uuid4())
    session = session_manager.get_or_create(sid)

    # Load organization-specific patterns if user has an org
    org_patterns = []
    if current_user.organization_id:
        db_patterns = (
            db.query(DetectionPattern)
            .filter(
                DetectionPattern.organization_id == current_user.organization_id,
                DetectionPattern.is_active == True,
            )
            .all()
        )
        org_patterns = [
            {
                "pattern_type": p.pattern_type,
                "pattern_value": p.pattern_value,
                "entity_type": p.entity_type,
            }
            for p in db_patterns
        ]

    # Detect PII
    entities = pii_detector.detect(
        text=request.text,
        language="en",
        org_patterns=org_patterns if org_patterns else None,
    )

    # Redact if entities found
    redacted_text = request.text
    mapping = {}
    if entities:
        redacted_text, mapping = pii_detector.redact(
            text=request.text,
            entities=entities,
            session=session,
        )

    # Calculate latency
    latency_ms = int((time.time() - start_time) * 1000)

    # Convert entities to response format
    entity_dicts = [
        {
            "type": e.type,
            "text": e.text,
            "start": e.start,
            "end": e.end,
            "confidence": e.confidence,
        }
        for e in entities
    ]

    # Extract entity type list for JSONB storage
    entity_types = list(set(e.type for e in entities)) if entities else []

    # Log to database
    prompt_log = PromptLog(
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        original_prompt=request.text,
        redacted_prompt=redacted_text if entities else None,
        ai_platform=request.ai_platform,
        entities_detected=len(entities),
        entity_types=entity_types,
        detection_details=entity_dicts,
        redaction_mapping=mapping if mapping else None,
        was_blocked=False,
        was_overridden=False,
        session_id=sid,
        latency_ms=latency_ms,
    )
    db.add(prompt_log)
    db.commit()
    db.refresh(prompt_log)

    return ScanResponse(
        safe=len(entities) == 0,
        entities=[
            DetectedEntity(**e) for e in entity_dicts
        ],
        redacted_text=redacted_text,
        redaction_mapping=mapping,
        latency_ms=latency_ms,
        log_id=prompt_log.id,
    )
