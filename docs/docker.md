# ScamShield — Docker Compose guide (Windows PowerShell)

Full stack: `postgres` + `redis` + `backend` + `frontend`. Only the
frontend (port 3000) is reachable from your computer. Secrets live
only in the root `.env` file, which is never committed.

## 1. First-time setup

```powershell
path\to\scamshield
Copy-Item .env.example .env
```

Fill in `.env`:

- `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` — pick any values.
- `SECRET_KEY` — at least 32 characters. Generate one with:

```powershell
-join ((48..57+65..90+97..122) | Get-Random -Count 48 | ForEach-Object {[char]$_})
```
- `REDIS_PASSWORD` — alphanumeric only (it sits inside `REDIS_URL`).
  Generate one with:

```powershell
-join ((48..57+65..90+97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
```

Rate limits (login 5/15 min, anonymous 10/min + 100/day, per-key
minute/daily, reports 5/hour) are counted in Redis, so they are shared
by every backend replica. If Redis is down, the backend falls back to
per-process in-memory counting and logs a warning — requests keep
working. Redis holds no persistent data (no volume): a restart only
resets counters.

## 2. Start

```powershell
docker compose up -d --build
docker compose ps   # all four should say "healthy"
```

## 3. View logs

```powershell
docker compose logs backend    # includes "alembic upgrade head"
docker compose logs frontend
docker compose logs postgres
docker compose logs redis
# live follow (Ctrl+C stops watching, containers keep running):
docker compose logs -f backend
```

## 4. Rebuild after code changes

```powershell
docker compose up -d --build
```

## 5. Create an admin

Needs a real terminal (the password prompt is hidden):

```powershell
docker compose exec backend python scripts/create_admin.py admin@example.com
```

## 6. Open psql

```powershell
docker compose exec postgres psql -U <POSTGRES_USER> -d <POSTGRES_DB> -c "\dt"
```

(Replace `<POSTGRES_USER>` / `<POSTGRES_DB>` with your `.env` values.)

## 7. Back up the database (pg_dump)

```powershell
docker compose exec postgres pg_dump -U <POSTGRES_USER> -d <POSTGRES_DB> > scamshield-backup.sql
```

## 8. Stop (keeps data)

```powershell
docker compose stop     # containers stop, volumes kept
docker compose up -d    # start again, data still there
```

## 9. Reset everything (DELETES ALL DATA)

Warning: this permanently deletes the database volume.

```powershell
docker compose down -v
```

## 10. Run the test suite against PostgreSQL (optional)

Uses a throwaway database, never the app database:

```powershell
# Start a temporary postgres just for tests (own port + volume):
$pgpass = (Select-String -Path .\.env -Pattern "^POSTGRES_PASSWORD=(.*)" | ForEach-Object {$_.Matches.Groups[1].Value})
docker run -d --name scamshield-testpg -e POSTGRES_USER=scamshield -e POSTGRES_PASSWORD="$pgpass" -e POSTGRES_DB=scamshield_test -p 5433:5432 postgres:16-alpine

# From the backend folder, point the suite at it:
cd backend
$env:TEST_DATABASE_URL = "postgresql+psycopg://scamshield:$pgpass@localhost:5433/scamshield_test"
.\.venv\Scripts\python.exe -m pytest tests -q

# Clean up the throwaway database:
docker rm -f scamshield-testpg
```
