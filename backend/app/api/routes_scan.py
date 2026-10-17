import hashlib
import ipaddress
import uuid as uuid_module
from collections.abc import Callable
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_current_user_optional
from app.core.database import get_db
from app.models.db_models import Scan, ScanFinding, User
from app.models.finding import Finding
from app.schemas.scan import FindingOut, ScanHistoryOut, ScanRequest, ScanResponse
from app.services.api_throttle import (
    log_key_usage,
    rate_limit_headers,
    resolve_caller,
    touch_key_last_used,
)
from app.models.finding import Finding
from app.schemas.scan import FindingOut, ScanHistoryOut, ScanRequest, ScanResponse
from app.services.domain_age import get_domain_age_cached
from app.services.message_analyzer import analyze_message, extract_urls
from app.services.qr_decoder import (
    ImageTooLargeError,
    InvalidImageError,
    QRNotFoundError,
    decode_qr,
)
from app.services.redact import redact_pii
from app.services.reports import is_official_domain
from app.services.safe_fetch import FetchResult, safe_fetch
from app.services.scoring import calculate_score
from app.services.upi_analyzer import analyze_upi, extract_upi_ids, mask_upi, normalize_upi
from app.services.upi_qr_parser import analyze_upi_qr, parse_upi_uri
from app.services.url_analyzer import analyze_url, check_domain_age, get_registered_domain

router = APIRouter()

FETCH_NOTE = (
    "We could not safely open this link, so only the address itself was checked."
)

MESSAGE_LINKS_NOTE = "Links in the message were checked by address only."

UPI_NOTE = "A scan only checks signs of risk. It cannot prove that a UPI ID is safe."

QR_PAY_NOTE = (
    "A QR code is only for PAYING. If someone asks you to scan a QR code to "
    "RECEIVE money, it is a scam."
)

INVALID_IMAGE_MSG = "This file is not a valid image"
TOO_LARGE_IMAGE_MSG = "The image is too large (max 5 MB)"
NO_QR_MSG = "No QR code found in this image"

SAVE_ERROR_NOTE = "This result could not be saved."

AGE_UNKNOWN_NOTE = "We could not check how old this website is."

# At most this many RDAP lookups per scan, so one message cannot fan out.
MAX_AGE_LOOKUPS_PER_SCAN = 2


def get_fetch_function() -> Callable[[str], FetchResult]:
    """Provide the fetch callable so tests can override it with a fake."""
    return safe_fetch


def get_age_lookup(db: Session = Depends(get_db)) -> Callable[[str], int | None]:
    """Provide the cached RDAP age lookup so tests can override it with a fake."""
    def lookup(registered_domain: str) -> int | None:
        return get_domain_age_cached(db, registered_domain)

    return lookup


def _age_target(link: str) -> str | None:
    """Registered domain eligible for an age lookup, else None.

    Official brand domains and IP-address hosts are skipped: the former are
    never flagged by age, the latter have no RDAP domain record.
    """
    try:
        host = (urlparse(link or "").hostname or "").lower()
    except Exception:
        return None
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    registered = get_registered_domain(host)
    if not registered or is_official_domain(registered):
        return None
    return registered


def _input_hash(raw: str) -> str:
    return hashlib.sha256(raw.strip().lower().encode("utf-8")).hexdigest()


@router.post("/api/scan", response_model=ScanResponse)
async def scan(
    req: ScanRequest,
    request: Request,
    response: Response,
    fetcher: Callable[[str], FetchResult] = Depends(get_fetch_function),
    age_lookup: Callable[[str], int | None] = Depends(get_age_lookup),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    # Optional X-API-Key auth with per-key limits, else anonymous IP limits.
    caller, api_key_row, limit, remaining = resolve_caller(
        request, db, current_user, "POST /api/scan"
    )
    for k, v in rate_limit_headers(limit, remaining).items():
        response.headers[k] = v
    if req.type == "message":
        original = req.input or ""
        msg_findings: list[Finding] = analyze_message(original)
        urls = extract_urls(original)
        url_findings: list[Finding] = []
        age_lookups = 0
        for u in urls:
            link = (u or "").strip()
            if "://" not in link:
                link = "https://" + link
            age: int | None = None
            target = _age_target(link) if age_lookups < MAX_AGE_LOOKUPS_PER_SCAN else None
            if target is not None:
                age_lookups += 1
                try:
                    age = await run_in_threadpool(age_lookup, target)
                except Exception:
                    age = None
            url_findings.extend(analyze_url(link, db=db, age_days=age))
        upi_findings: list[Finding] = []
        for uid in extract_upi_ids(original)[:3]:
            upi_findings.extend(analyze_upi(uid, db))
        findings = list(msg_findings) + list(url_findings) + list(upi_findings)
        notes: list[str] = []
        redirect_chain: list[str] = []
        if urls:
            notes.append(MESSAGE_LINKS_NOTE)
        scored = calculate_score(findings)
        storage_text = redact_pii(original)
        hash_source = storage_text
    elif req.type == "upi":
        original = req.input or ""
        normalized = normalize_upi(original)
        findings = analyze_upi(normalized, db)
        notes = [UPI_NOTE]
        redirect_chain = []
        scored = calculate_score(findings)
        storage_text = mask_upi(normalized)
        hash_source = normalized
        # _input_hash lowercases/strips again, which keeps the hash
        # equal to sha256 of the normalized full ID.
    else:
        url = (req.input or "").strip()
        if "://" not in url:
            url = "https://" + url

        first_findings: list[Finding] = analyze_url(url, db=db)
        notes = []
        redirect_chain = [url]

        # Domain age (RDAP, cached). Runs even if the fetch below fails;
        # a failed lookup adds no finding, only a note.
        age_extra: list[Finding] = []
        age_note: str | None = None
        age_target = _age_target(url)
        if age_target is not None:
            try:
                age_value = await run_in_threadpool(age_lookup, age_target)
            except Exception:
                age_value = None
            if age_value is None:
                age_note = AGE_UNKNOWN_NOTE
            else:
                age_finding = check_domain_age(age_value)
                if age_finding is not None:
                    age_extra.append(age_finding)

        try:
            fetch_result = await run_in_threadpool(fetcher, url)
            findings = analyze_url(url, fetch_result, db=db) + age_extra
            if fetch_result.redirect_chain:
                redirect_chain = list(fetch_result.redirect_chain)
            else:
                redirect_chain = [url]
        except Exception:
            # Never leak raw exception text or internal details to the client.
            notes.append(FETCH_NOTE)
            findings = first_findings + age_extra
            redirect_chain = [url]
        if age_note is not None:
            notes.append(age_note)

        scored = calculate_score(findings)
        storage_text = req.input
        hash_source = req.input

    scan_id = str(uuid4())
    try:
        row = Scan(
            id=scan_id,
            user_id=caller.id if caller is not None else None,
            input_type=req.type,
            input_hash=_input_hash(hash_source),
            raw_input=storage_text,
            risk_score=scored.risk_score,
            verdict=scored.verdict,
            summary=scored.summary,
            redirect_chain=list(redirect_chain),
            notes=list(notes),
        )
        db.add(row)
        for f in scored.findings:
            db.add(
                ScanFinding(
                    scan_id=scan_id,
                    rule_code=f.rule_code,
                    severity=f.severity,
                    explanation=f.explanation,
                )
            )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:  # nosec B110 - rollback must never raise; scan continues with SAVE_ERROR_NOTE
            pass
        # Never expose database errors in the response.
        notes.append(SAVE_ERROR_NOTE)

    if api_key_row is not None:
        # Usage write and last-used update must never break the request.
        log_key_usage(db, api_key_row.id, "POST /api/scan", 200)
        touch_key_last_used(db, api_key_row)

    return ScanResponse(
        scan_id=scan_id,
        type=req.type,
        risk_score=scored.risk_score,
        verdict=scored.verdict,
        summary=scored.summary,
        findings=[
            FindingOut(
                rule_code=f.rule_code,
                severity=f.severity,
                explanation=f.explanation,
            )
            for f in scored.findings
        ],
        redirect_chain=redirect_chain,
        notes=notes,
    )


@router.post("/api/scan/qr", response_model=ScanResponse)
async def scan_qr(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    fetcher: Callable[[str], FetchResult] = Depends(get_fetch_function),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    caller, api_key_row, limit, remaining = resolve_caller(
        request, db, current_user, "POST /api/scan/qr"
    )
    for k, v in rate_limit_headers(limit, remaining).items():
        response.headers[k] = v

    def _fail(status: int, msg: str):
        # Log key usage with the real status, then raise. Never break on log.
        if api_key_row is not None:
            log_key_usage(db, api_key_row.id, "POST /api/scan/qr", status)
        raise HTTPException(status_code=status, detail=msg)

    try:
        content = await file.read()
    except Exception:
        _fail(400, INVALID_IMAGE_MSG)

    try:
        payload = await run_in_threadpool(decode_qr, bytes(content or b""))
    except ImageTooLargeError:
        _fail(413, TOO_LARGE_IMAGE_MSG)
    except InvalidImageError:
        _fail(400, INVALID_IMAGE_MSG)
    except QRNotFoundError:
        _fail(422, NO_QR_MSG)

    text = (payload or "").strip()
    low = text.lower()

    if low.startswith("upi://"):
        parsed = parse_upi_uri(text)
        findings: list[Finding] = analyze_upi_qr(text, db)
        notes: list[str] = [QR_PAY_NOTE]
        redirect_chain: list[str] = []
        pa = parsed.get("pa")
        if pa:
            storage_text = redact_pii(text.replace(pa, mask_upi(pa), 1))
        else:
            storage_text = redact_pii(text)
        hash_source = storage_text
    elif low.startswith("http://") or low.startswith("https://"):
        url = text
        first_findings: list[Finding] = analyze_url(url, db=db)
        notes = []
        redirect_chain = [url]
        try:
            fetch_result = await run_in_threadpool(fetcher, url)
            findings = analyze_url(url, fetch_result, db=db)
            if fetch_result.redirect_chain:
                redirect_chain = list(fetch_result.redirect_chain)
            else:
                redirect_chain = [url]
        except Exception:
            notes.append(FETCH_NOTE)
            findings = first_findings
            redirect_chain = [url]
        storage_text = text
        hash_source = text
    else:
        findings = analyze_message(text)
        notes = []
        redirect_chain = []
        storage_text = redact_pii(text)
        hash_source = storage_text

    scored = calculate_score(findings)

    scan_id = str(uuid4())
    try:
        row = Scan(
            id=scan_id,
            user_id=caller.id if caller is not None else None,
            input_type="qr",
            input_hash=_input_hash(hash_source),
            raw_input=storage_text,
            risk_score=scored.risk_score,
            verdict=scored.verdict,
            summary=scored.summary,
            redirect_chain=list(redirect_chain),
            notes=list(notes),
        )
        db.add(row)
        for f in scored.findings:
            db.add(
                ScanFinding(
                    scan_id=scan_id,
                    rule_code=f.rule_code,
                    severity=f.severity,
                    explanation=f.explanation,
                )
            )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:  # nosec B110 - rollback must never raise; scan continues with SAVE_ERROR_NOTE
            pass
        notes.append(SAVE_ERROR_NOTE)

    if api_key_row is not None:
        log_key_usage(db, api_key_row.id, "POST /api/scan/qr", 200)
        touch_key_last_used(db, api_key_row)

    return ScanResponse(
        scan_id=scan_id,
        type="qr",
        risk_score=scored.risk_score,
        verdict=scored.verdict,
        summary=scored.summary,
        findings=[
            FindingOut(
                rule_code=f.rule_code,
                severity=f.severity,
                explanation=f.explanation,
            )
            for f in scored.findings
        ],
        redirect_chain=redirect_chain,
        notes=notes,
    )


@router.get("/api/scans", response_model=list[ScanHistoryOut])
def list_scans(
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rows = (
        db.query(Scan)
        .filter(Scan.user_id == user.id)
        .order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        ScanHistoryOut(
            id=r.id,
            type=r.input_type,
            risk_score=r.risk_score,
            verdict=r.verdict,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.get("/api/scan/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    try:
        uuid_module.UUID(scan_id)
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id is not None:
        # Private scan: only its owner (or an admin) may read it. Everyone
        # else gets the same generic 404, so ids cannot be probed.
        allowed = (
            current_user is not None
            and (
                current_user.id == scan.user_id or current_user.role == "admin"
            )
        )
        if not allowed:
            raise HTTPException(status_code=404, detail="Scan not found")
    ordered = sorted(scan.findings, key=lambda f: f.id or 0)
    return ScanResponse(
        scan_id=scan.id,
        type=scan.input_type,
        risk_score=scan.risk_score,
        verdict=scan.verdict,
        summary=scan.summary,
        findings=[
            FindingOut(
                rule_code=f.rule_code,
                severity=f.severity,
                explanation=f.explanation,
            )
            for f in ordered
        ],
        redirect_chain=list(scan.redirect_chain or []),
        notes=list(scan.notes or []),
    )
