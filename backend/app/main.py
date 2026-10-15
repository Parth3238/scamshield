import logging
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import inspect

from app.api.routes_auth import router as auth_router
from app.api.routes_keys import router as keys_router
from app.api.routes_reports import router as reports_router
from app.api.routes_scan import router as scan_router
from app.core.database import engine
from app.core.middleware import (
    REQUEST_ID_SCOPE_KEY,
    BodyLimitMiddleware,
    CorsMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
)

# Import models so Base.metadata knows about the tables.
import app.models.db_models  # noqa: F401

# Load detection-rule data once at startup. If any YAML file is invalid
# the loader raises RuntimeError naming the file, line and problem, so the
# app refuses to start instead of scanning with broken rules.
from app.rules.loader import load_rules as _load_detection_rules

_load_detection_rules()

error_logger = logging.getLogger("scamshield.error")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Tables are created by Alembic migrations, not here. Fail fast with a
    # clear hint instead of running against an empty database.
    if "users" not in inspect(engine).get_table_names():
        raise RuntimeError(
            "Database tables are missing. Run: alembic upgrade head"
        )
    yield


def create_app(environment: str | None = None) -> FastAPI:
    """Build the app. ENVIRONMENT=production disables the interactive docs."""
    env = (environment or os.getenv("ENVIRONMENT", "development")).strip().lower()
    is_prod = env == "production"
    docs_kwargs = (
        {"docs_url": None, "redoc_url": None, "openapi_url": None}
        if is_prod
        else {}
    )

    application = FastAPI(title="ScamShield API", lifespan=lifespan, **docs_kwargs)
    application.include_router(auth_router)
    application.include_router(keys_router)
    application.include_router(reports_router)
    application.include_router(scan_router)

    @application.exception_handler(RequestValidationError)
    async def validation_no_input_echo(request: Request, exc: RequestValidationError):
        # Same 422 shape as FastAPI but without echoing the user's raw input.
        clean = [
            {"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")}
            for e in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": clean})

    @application.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        # Last resort for truly unexpected errors (HTTPException and
        # validation errors keep their own handlers: Starlette looks those up
        # first). The user gets a generic message; the full detail goes only
        # to the server log under a random id. No stack traces leave the app.
        error_id = uuid.uuid4().hex[:12]
        request_id = request.scope.get(REQUEST_ID_SCOPE_KEY, "-")
        error_logger.exception(
            "unhandled error id=%s request_id=%s %s %s: %r",
            error_id,
            request_id,
            request.method,
            request.url.path,
            exc,
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Something went wrong"},
            headers={"X-Error-ID": error_id},
        )

    @application.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # First added = outermost.
    application.add_middleware(RequestIDMiddleware)
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(CorsMiddleware)
    application.add_middleware(BodyLimitMiddleware)
    return application


app = create_app()
