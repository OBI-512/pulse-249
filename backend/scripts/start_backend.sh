#!/bin/sh
set -eu

echo "[FTTW] Validating runtime safety..."
python scripts/validate_runtime_safety.py

echo "[FTTW] Waiting for database and applying migrations..."
alembic upgrade head
echo "[FTTW] Database migrations complete."

if [ "${SEED_DEMO_DATA:-false}" = "true" ]; then
  echo "[FTTW] Seeding deterministic demo data..."
  python scripts/seed_initial_data.py
  echo "[FTTW] Demo data ready."
fi

echo "[FTTW] Starting API..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
