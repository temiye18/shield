import csv
import io
import math
from datetime import date, datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, case, cast, Date, text
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import User, PromptLog
from app.schemas.analytics import (
    OverviewResponse,
    PeriodSchema,
    MetricsSchema,
    DailyActivityItem,
    ActivityLogResponse,
    ActivityLogItem,
    ActivityLogUser,
    PaginationSchema,
)
from app.dependencies import get_current_user, get_admin_user

router = APIRouter()


@router.get("/overview", response_model=OverviewResponse)
async def get_overview(
    start_date: str = Query(..., description="Start date (ISO format: YYYY-MM-DD)"),
    end_date: str = Query(..., description="End date (ISO format: YYYY-MM-DD)"),
    user_id: int = Query(None, description="Filter by user (admin only)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get aggregate statistics for the dashboard overview."""
    try:
        start = date.fromisoformat(start_date)
        end = date.fromisoformat(end_date)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")

    # Base query filtered by org and date range
    base_query = db.query(PromptLog).filter(
        cast(PromptLog.created_at, Date) >= start,
        cast(PromptLog.created_at, Date) <= end,
    )

    # Scope by organization
    if current_user.organization_id:
        base_query = base_query.filter(
            PromptLog.organization_id == current_user.organization_id
        )
    else:
        base_query = base_query.filter(PromptLog.user_id == current_user.id)

    # Optional user filter (admin only)
    if user_id and current_user.role == "admin":
        base_query = base_query.filter(PromptLog.user_id == user_id)

    # Core metrics
    total_prompts = base_query.count()
    prompts_with_pii = base_query.filter(PromptLog.entities_detected > 0).count()
    detection_rate = (
        round((prompts_with_pii / total_prompts) * 100, 1) if total_prompts > 0 else 0.0
    )

    total_entities = (
        db.query(func.sum(PromptLog.entities_detected))
        .filter(
            cast(PromptLog.created_at, Date) >= start,
            cast(PromptLog.created_at, Date) <= end,
        )
    )
    if current_user.organization_id:
        total_entities = total_entities.filter(
            PromptLog.organization_id == current_user.organization_id
        )
    else:
        total_entities = total_entities.filter(PromptLog.user_id == current_user.id)
    total_entities_count = total_entities.scalar() or 0

    prompts_blocked = base_query.filter(PromptLog.was_blocked == True).count()
    prompts_overridden = base_query.filter(PromptLog.was_overridden == True).count()

    # Entity breakdown from JSONB
    all_logs = base_query.filter(PromptLog.entity_types.isnot(None)).all()
    entity_breakdown = {}
    for log in all_logs:
        if log.entity_types:
            for etype in log.entity_types:
                entity_breakdown[etype] = entity_breakdown.get(etype, 0) + 1

    # Platform breakdown
    platform_breakdown = {}
    platform_results = (
        base_query.with_entities(
            PromptLog.ai_platform, func.count(PromptLog.id)
        )
        .group_by(PromptLog.ai_platform)
        .all()
    )
    for platform, count in platform_results:
        if platform:
            platform_breakdown[platform] = count

    # Daily activity
    daily_results = (
        base_query.with_entities(
            cast(PromptLog.created_at, Date).label("day"),
            func.count(PromptLog.id).label("prompts"),
            func.sum(
                case((PromptLog.entities_detected > 0, 1), else_=0)
            ).label("pii_detected"),
        )
        .group_by(cast(PromptLog.created_at, Date))
        .order_by(cast(PromptLog.created_at, Date))
        .all()
    )
    daily_activity = [
        DailyActivityItem(
            date=str(row.day),
            prompts=row.prompts,
            pii_detected=int(row.pii_detected or 0),
        )
        for row in daily_results
    ]

    return OverviewResponse(
        period=PeriodSchema(start=start_date, end=end_date),
        metrics=MetricsSchema(
            total_prompts=total_prompts,
            prompts_with_pii=prompts_with_pii,
            pii_detection_rate=detection_rate,
            total_entities_detected=total_entities_count,
            prompts_blocked=prompts_blocked,
            prompts_overridden=prompts_overridden,
        ),
        entity_breakdown=entity_breakdown,
        platform_breakdown=platform_breakdown,
        daily_activity=daily_activity,
    )


@router.get("/activity-log", response_model=ActivityLogResponse)
async def get_activity_log(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    user_id: int = Query(None, description="Filter by user ID"),
    has_pii: bool = Query(None, description="Filter by PII detection status"),
    start_date: str = Query(None, description="Start date (YYYY-MM-DD)"),
    end_date: str = Query(None, description="End date (YYYY-MM-DD)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get paginated activity log of all prompts."""
    query = db.query(PromptLog)

    # Scope by organization or user
    if current_user.role == "admin" and current_user.organization_id:
        query = query.filter(
            PromptLog.organization_id == current_user.organization_id
        )
    else:
        query = query.filter(PromptLog.user_id == current_user.id)

    # Apply filters
    if user_id and current_user.role == "admin":
        query = query.filter(PromptLog.user_id == user_id)

    if has_pii is True:
        query = query.filter(PromptLog.entities_detected > 0)
    elif has_pii is False:
        query = query.filter(PromptLog.entities_detected == 0)

    if start_date:
        try:
            query = query.filter(
                cast(PromptLog.created_at, Date) >= date.fromisoformat(start_date)
            )
        except ValueError:
            pass

    if end_date:
        try:
            query = query.filter(
                cast(PromptLog.created_at, Date) <= date.fromisoformat(end_date)
            )
        except ValueError:
            pass

    # Total count for pagination
    total = query.count()
    total_pages = math.ceil(total / limit) if total > 0 else 1

    # Paginate
    offset = (page - 1) * limit
    logs = (
        query.order_by(PromptLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    # Build response items with user info
    items = []
    for log in logs:
        user = db.query(User).filter(User.id == log.user_id).first()
        items.append(
            ActivityLogItem(
                id=log.id,
                user=ActivityLogUser(
                    id=user.id if user else 0,
                    email=user.email if user else "",
                    full_name=user.full_name if user else None,
                ),
                original_prompt=log.original_prompt,
                redacted_prompt=log.redacted_prompt,
                entities_detected=log.entities_detected,
                entity_types=log.entity_types,
                ai_platform=log.ai_platform,
                was_blocked=log.was_blocked,
                was_overridden=log.was_overridden,
                created_at=log.created_at.isoformat() if log.created_at else "",
            )
        )

    return ActivityLogResponse(
        logs=items,
        pagination=PaginationSchema(
            page=page,
            limit=limit,
            total=total,
            pages=total_pages,
        ),
    )


@router.get("/export")
async def export_audit_logs(
    start_date: str = Query(..., description="Start date (YYYY-MM-DD)"),
    end_date: str = Query(..., description="End date (YYYY-MM-DD)"),
    format: str = Query("csv", description="Export format: csv or json"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user),
):
    """Export audit logs as CSV or JSON for compliance (admin only)."""
    try:
        start = date.fromisoformat(start_date)
        end = date.fromisoformat(end_date)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")

    query = (
        db.query(PromptLog, User)
        .join(User, PromptLog.user_id == User.id)
        .filter(
            cast(PromptLog.created_at, Date) >= start,
            cast(PromptLog.created_at, Date) <= end,
        )
    )

    if current_user.organization_id:
        query = query.filter(
            PromptLog.organization_id == current_user.organization_id
        )

    results = query.order_by(PromptLog.created_at.desc()).all()

    if format == "json":
        data = [
            {
                "id": log.id,
                "timestamp": log.created_at.isoformat() if log.created_at else "",
                "user_email": user.email,
                "user_name": user.full_name or "",
                "original_prompt": log.original_prompt,
                "entities_detected": log.entities_detected,
                "entity_types": ",".join(log.entity_types) if log.entity_types else "",
                "platform": log.ai_platform or "",
                "was_blocked": log.was_blocked,
            }
            for log, user in results
        ]
        from fastapi.responses import JSONResponse

        return JSONResponse(
            content=data,
            headers={
                "Content-Disposition": f'attachment; filename="audit-log-{start_date}-{end_date}.json"'
            },
        )

    # CSV format (default)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "timestamp", "user_email", "user_name",
        "original_prompt", "entities_detected", "entity_types",
        "platform", "was_blocked",
    ])

    for log, user in results:
        writer.writerow([
            log.id,
            log.created_at.isoformat() if log.created_at else "",
            user.email,
            user.full_name or "",
            log.original_prompt,
            log.entities_detected,
            ",".join(log.entity_types) if log.entity_types else "",
            log.ai_platform or "",
            log.was_blocked,
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="audit-log-{start_date}-{end_date}.csv"'
        },
    )
