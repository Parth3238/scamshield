# syntax=docker/dockerfile:1
# ScamShield backend image. Runtime only, non-root, no secrets baked in.

# ---------- Builder: compile/download wheels only ----------
FROM python:3.12-slim AS builder
WORKDIR /app

# build-essential lives ONLY here so the final image stays small
# and has fewer tools an attacker could use.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Build wheels for runtime deps + their transitive deps.
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


# ---------- Runtime: minimal image that actually runs ----------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENVIRONMENT=production \
    DATABASE_URL=sqlite:////data/scamshield.db

WORKDIR /app

# Minimum system libs for opencv-python-headless + Pillow on slim:
# - libglib2.0-0: needed by OpenCV (fails to import without it).
# - libgomp1: OpenMP runtime needed by OpenCV/numpy math routines.
# Pillow and psycopg[binary] ship their own bundled libs in wheels,
# so nothing else is required. No curl: HEALTHCHECK uses plain python.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libglib2.0-0 libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --user-group appuser \
    && mkdir -p /app /data \
    && chown appuser:appuser /app /data

# Install runtime deps from builder wheels (no compiler, no pip cache here).
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels

# Copy ONLY what the app needs to run. Tests, .venv, *.db, .env are
# excluded by backend/.dockerignore AND by simply not copying them here.
COPY --chown=appuser:appuser app ./app
COPY --chown=appuser:appuser alembic ./alembic
COPY --chown=appuser:appuser alembic.ini ./alembic.ini
COPY --chown=appuser:appuser scripts ./scripts
COPY --chown=appuser:appuser docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x ./docker-entrypoint.sh \
    && sed -i 's/\r$//' ./docker-entrypoint.sh

# NOTE: SECRET_KEY is intentionally NOT set here. The app reads it from
# the environment at runtime and refuses to start without it.

USER appuser
EXPOSE 8000

# No curl in slim: use the Python standard library only.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5).status == 200 else 1)"

ENTRYPOINT ["./docker-entrypoint.sh"]
# No --reload in containers.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
