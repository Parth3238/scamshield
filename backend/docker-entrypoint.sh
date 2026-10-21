#!/bin/sh
# Docker entrypoint for the ScamShield backend.
# - Runs "alembic upgrade head" only when RUN_MIGRATIONS=true.
# - Then starts whatever CMD was given (default: uvicorn).
# SECRET_KEY must come from the environment at runtime; it is never baked in.
set -e

if [ "${RUN_MIGRATIONS:-false}" = "true" ]; then
  echo "RUN_MIGRATIONS=true, running: alembic upgrade head"
  alembic upgrade head
else
  echo "Skipping migrations (set RUN_MIGRATIONS=true to run them)."
fi

exec "$@"


