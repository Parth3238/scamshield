"""Community scam reports, public campaigns and admin moderation."""

from __future__ import annotations

import datetime
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_optional, require_admin
from app.core.database import get_db
from app.core.rate_limit import build_limiter
from app.models.db_models import Campaign, Indicator, Report, User
from app.schemas.reports import (
    AdminReportOut,
    CampaignOut,
    ReportCreate,
    ReportCreatedOut,
    ReviewOut,
)
from app.services.api_throttle import (
    log_key_usage,
    rate_limit_headers,
    resolve_caller,
    touch_key_last_used,
)
from app.schemas.reports import (
    AdminReportOut,
    CampaignOut,
    ReportCreate,
    ReportCreatedOut,
    ReviewOut,
)
from app.services.redact import redact_pii
from app.services.reports import (
    InvalidTargetError,
    find_or_create_campaign,
    is_official_domain,
    normalize_report_target,
)
from app.services.upi_analyzer import mask_upi

router = APIRouter()

REPORT_THANKS_MSG = (
    "Thanks! Your report will be reviewed before it appears publicly."
)
OFFICIAL_TARGET_MSG = "This target cannot be reported"
DUPLICATE_MSG = "You have already reported this target recently."
REPORT_RATE_LIMIT_MSG = "Too many reports. Try again later."
ALREADY_REVIEWED_MSG = "This report has already been reviewed."

# Max 5 reports per hour per user (or per IP when anonymous).
# Redis-backed when REDIS_URL is set, in-memory otherwise.
report_limiter = build_limiter(5, 60 * 60, scope="report")

DUPLICATE_WINDOW = datetime.timedelta(hours=24)
TRENDING_WINDOW = datetime.timedelta(days=7)
SAMPLE_TARGET_LIMIT = 3


def _client_ip(request: Request) -> str:
    if request.client is not None:
        return request.client.host
    return "unknown"


def _reporter_key(user: User | None, ip: str) -> str:
    if user is not None:
        return f"user:{user.id}"
    digest = hashlib.sha256(ip.encode("utf-8")).hexdigest()
    return f"ip:{digest}"


def _rate_key(user: User | None, ip: str) -> str:
    if user is not None:
        return f"user:{user.id}"
    return f"ip:{ip}"


def _sample_targets(db: Session, campaign_id: str) -> list[str]:
    rows = (
        db.query(Indicator)
        .filter(Indicator.campaign_id == campaign_id)
        .order_by(Indicator.id)
        .limit(SAMPLE_TARGET_LIMIT)
        .all()
    )
    out: list[str] = []
    for row in rows:
        # UPI IDs are masked in public output; domains are shown as-is.
        out.append(mask_upi(row.value) if row.type == "upi" else row.value)
    return out


def _campaign_out(db: Session, campaign: Campaign) -> CampaignOut:
    return CampaignOut(
        title=campaign.title,
        scam_type=campaign.scam_type,
        report_count=campaign.report_count,
        last_seen=campaign.last_seen,
        sample_targets=_sample_targets(db, campaign.id),
    )


@router.post("/api/reports", response_model=ReportCreatedOut)
def submit_report(
    req: ReportCreate,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    # Optional X-API-Key auth with per-key limits, else anonymous IP limits.
    # Invalid keys give 401 here (never fall back to anonymous).
    caller, api_key_row, limit, remaining = resolve_caller(
        request, db, current_user, "POST /api/reports"
    )
    for k, v in rate_limit_headers(limit, remaining).items():
        response.headers[k] = v
    ip = _client_ip(request)
    rate_key = _rate_key(caller, ip)
    blocked, retry_after = report_limiter.is_blocked(rate_key)
    if blocked:
        raise HTTPException(
            status_code=429,
            detail=REPORT_RATE_LIMIT_MSG,
            headers={"Retry-After": str(retry_after)},
        )

    target_type: str | None = None
    target_value: str | None = None
    if req.target is not None and req.target.strip():
        try:
            target_type, target_value = normalize_report_target(req.target)
        except InvalidTargetError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if target_type == "domain" and is_official_domain(target_value):
            # Never let anyone poison the database against real banks/apps.
            raise HTTPException(status_code=422, detail=OFFICIAL_TARGET_MSG)

    reporter_key = _reporter_key(caller, ip)
    if target_value is not None:
        since = datetime.datetime.now(datetime.timezone.utc) - DUPLICATE_WINDOW
        dup = (
            db.query(Report)
            .filter(
                Report.reporter_key == reporter_key,
                Report.reported_value_type == target_type,
                Report.reported_value == target_value,
                Report.created_at >= since,
            )
            .first()
        )
        if dup is not None:
            raise HTTPException(status_code=409, detail=DUPLICATE_MSG)

    report = Report(
        user_id=caller.id if caller is not None else None,
        campaign_id=None,
        scam_type=req.scam_type,
        content=redact_pii(req.content),
        reported_value_type=target_type,
        reported_value=target_value,
        reporter_key=reporter_key,
        status="pending",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    report_limiter.record_hit(rate_key)
    if api_key_row is not None:
        log_key_usage(db, api_key_row.id, "POST /api/reports", 200)
        touch_key_last_used(db, api_key_row)
    return ReportCreatedOut(
        report_id=report.id, status="pending", message=REPORT_THANKS_MSG
    )


@router.get("/api/campaigns/trending", response_model=list[CampaignOut])
def trending_campaigns(db: Session = Depends(get_db)):
    cutoff = datetime.datetime.now(datetime.timezone.utc) - TRENDING_WINDOW
    rows = (
        db.query(Campaign)
        .filter(Campaign.report_count > 0, Campaign.last_seen >= cutoff)
        .order_by(Campaign.report_count.desc())
        .limit(20)
        .all()
    )
    return [_campaign_out(db, c) for c in rows]


@router.get("/api/campaigns/search", response_model=list[CampaignOut])
def search_campaigns(q: str = Query(min_length=3, max_length=100), db: Session = Depends(get_db)):
    needle = q.strip().lower()
    # Escape LIKE wildcards so "%" or "_" only match themselves, never everything.
    escaped = (
        needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
    pattern = f"%{escaped}%"
    title_hits = (
        db.query(Campaign)
        .filter(
            Campaign.report_count > 0,
            func.lower(Campaign.title).like(pattern, escape="\\"),
        )
        .all()
    )
    indicator_hits = (
        db.query(Indicator)
        .filter(
            Indicator.source == "community",
            func.lower(Indicator.value).like(pattern, escape="\\"),
        )
        .all()
    )
    ids = {c.id for c in title_hits}
    ids.update(i.campaign_id for i in indicator_hits if i.campaign_id)
    if not ids:
        return []
    rows = (
        db.query(Campaign)
        .filter(Campaign.id.in_(ids), Campaign.report_count > 0)
        .order_by(Campaign.report_count.desc())
        .limit(20)
        .all()
    )
    return [_campaign_out(db, c) for c in rows]


@router.get("/api/admin/reports", response_model=list[AdminReportOut])
def list_reports(
    status: str = Query("pending"),
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if status not in ("pending", "approved", "rejected"):
        raise HTTPException(status_code=422, detail="Unknown report status.")
    rows = (
        db.query(Report)
        .filter(Report.status == status)
        .order_by(Report.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        AdminReportOut(
            id=r.id,
            scam_type=r.scam_type,
            content=r.content,
            reported_value_type=r.reported_value_type,
            reported_value=r.reported_value,
            status=r.status,
            created_at=r.created_at,
        )
        for r in rows
    ]


def _get_pending_report(db: Session, report_id: str) -> Report:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "pending":
        raise HTTPException(status_code=409, detail=ALREADY_REVIEWED_MSG)
    return report


@router.post("/api/admin/reports/{report_id}/approve", response_model=ReviewOut)
def approve_report(
    report_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    now = datetime.datetime.now(datetime.timezone.utc)
    report = _get_pending_report(db, report_id)
    try:
        report.status = "approved"
        report.reviewed_by = admin.id
        report.reviewed_at = now
        campaign = find_or_create_campaign(
            db, report.scam_type, report.reported_value_type, report.reported_value
        )
        report.campaign_id = campaign.id
        if report.reported_value_type and report.reported_value:
            exists = (
                db.query(Indicator)
                .filter(
                    Indicator.type == report.reported_value_type,
                    Indicator.value == report.reported_value,
                )
                .first()
            )
            if exists is None:
                db.add(
                    Indicator(
                        type=report.reported_value_type,
                        value=report.reported_value,
                        confidence=60,
                        source="community",
                        campaign_id=campaign.id,
                    )
                )
            elif exists.campaign_id is None:
                exists.campaign_id = campaign.id
        campaign.report_count += 1
        campaign.last_seen = now
        db.commit()
    except Exception:
        db.rollback()
        raise
    return ReviewOut(report_id=report.id, status="approved")


@router.post("/api/admin/reports/{report_id}/reject", response_model=ReviewOut)
def reject_report(
    report_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    now = datetime.datetime.now(datetime.timezone.utc)
    report = _get_pending_report(db, report_id)
    report.status = "rejected"
    report.reviewed_by = admin.id
    report.reviewed_at = now
    db.commit()
    return ReviewOut(report_id=report.id, status="rejected")
