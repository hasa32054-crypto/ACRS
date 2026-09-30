#!/bin/sh
set -e
if [ "${ACRS_STORE:-sql}" = "sql" ]; then
  echo "acrs: applying migrations"
  alembic upgrade head
  python -m app.seed
fi
echo "acrs: SIMULATION ONLY - no real network operations"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1 --proxy-headers
