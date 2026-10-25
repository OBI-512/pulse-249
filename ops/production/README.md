# FTTW Production Container Baseline

This file documents the Phase B3 production container baseline. The existing `docker-compose.yml` remains the development/default stack. Production uses `docker-compose.prod.yml` explicitly.

## Production topology

Only the frontend is published to the host by default.

- Host -> `frontend:8080` (Nginx, unprivileged)
- Nginx `/api/*` -> `backend:8000` on the Compose application network
- Backend -> PostgreSQL/Redis on the Compose data network
- PostgreSQL: no host port
- Redis: no host port
- Backend: no host port

## Start production

1. Copy `.env.production.example` to `.env.production`.
2. Replace the database password and `DATABASE_URL` placeholder with a strong production value.
3. Set `CORS_ORIGINS` and `FRONTEND_PROD_PORT` for the intended deployment.
4. Start:

```powershell
docker compose --env-file .env.production -f docker-compose.prod.yml up -d --build
```

Stop without deleting persistent volumes:

```powershell
docker compose --env-file .env.production -f docker-compose.prod.yml down --remove-orphans
```

Do not use `down -v` in normal operation.

## Development

Development remains unchanged:

```powershell
docker compose up -d
```

The development frontend continues to use Vite on port 3000. Production never uses the Vite development server.

## Non-root identities

The production backend image creates and runs as UID/GID `10001:10001`. Backend, worker, scheduler and restore-control inherit that identity. The frontend runtime uses the upstream `nginx-unprivileged` image, which runs as UID 101.

PostgreSQL and Redis retain their upstream image runtime behavior.

## Persistence

Production uses named volumes:

- `postgres_data` — PostgreSQL database
- `redis_data` — Redis persistence
- `app_data` — shared FTTW application/restore data

The same `app_data` volume is mounted by backend, worker, scheduler and restore-control.

## Health and restart conventions

Every production service uses `restart: unless-stopped` and Docker local log rotation (`10m`, 5 files). PostgreSQL, Redis, backend, frontend, worker, scheduler and restore-control have service-appropriate health checks.

## Resource guidance

These are starting guidelines, not hard limits. Measure actual production load before enforcing them.

| Service | Suggested CPU | Suggested memory |
|---|---:|---:|
| frontend | 0.25 | 128-256 MB |
| backend | 1-2 | 512 MB-1 GB |
| worker | 1-2 | 1-2 GB |
| scheduler | 0.25 | 256 MB |
| restore-control | 0.5-1 | 512 MB-1 GB |
| PostgreSQL | 1-2 | 1-2 GB minimum |
| Redis | 0.5 | 256-512 MB |

Resource enforcement should be introduced only after representative load measurements.

## B3 boundaries

This baseline intentionally does not add SAST, secret scanning, vulnerability scanning, image scanning, SBOM generation, or license analysis. Those belong to B4.
