# ScamShield backend — Docker (Windows PowerShell)

Backend only. No compose, no frontend. Secrets always come from
environment variables at runtime, never baked into the image.

## 1. Build the image

```powershell
cd C:\Users\parth\scamshield
docker build -t scamshield-backend ./backend
```

Check size:

```powershell
docker image ls scamshield-backend
```

## 2. Create a named volume for the SQLite database

Do this once. The database file lives at `/data/scamshield.db`
inside the container, so it survives container restarts.

```powershell
docker volume create scamshield-data
```

## 3. Make a random SECRET_KEY (test only, 48 characters)

Never put a real secret in a file or image. Generate one in memory:

```powershell
$secret = -join ((48..57+65..90+97..122) | Get-Random -Count 48 | ForEach-Object {[char]$_})
$secret.Length  # must print 48
```

## 4. Run the container

```powershell
docker run -d --name scamshield-test `
  -p 8000:8000 `
  -e SECRET_KEY="$secret" `
  -e RUN_MIGRATIONS=true `
  -e ENVIRONMENT=production `
  -e DATABASE_URL="sqlite:////data/scamshield.db" `
  -v scamshield-data:/data `
  scamshield-backend
```

What each flag means:

- `-d` runs in the background.
- `-p 8000:8000` publishes container port 8000 on the host.
- `RUN_MIGRATIONS=true` runs `alembic upgrade head` once at startup.
- `ENVIRONMENT=production` disables `/docs`, `/redoc`, `/openapi.json`.
- `DATABASE_URL=sqlite:////data/scamshield.db` keeps the DB in the volume.
- `-v scamshield-data:/data` mounts the named volume at `/data`.

## 5. Check it works

```powershell
# Health (expect {"status":"ok"})
Invoke-RestMethod -Uri http://127.0.0.1:8000/health | ConvertTo-Json

# Docs must be 404 in production (expect a 404 error, that is correct)
try { Invoke-WebRequest -Uri http://127.0.0.1:8000/docs -UseBasicParsing } catch { $_.Exception.Message }

# Test scan (expect risk_score, verdict, summary back)
$body = @{ type = "url"; input = "https://example.com" } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/scan -Method Post -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 6

# Prove we are NOT root (expect "appuser")
docker exec scamshield-test whoami
```

## 6. View logs

```powershell
docker logs scamshield-test
# live follow with Ctrl+C to stop watching (container keeps running):
docker logs -f scamshield-test
```

## 7. Stop and remove

```powershell
docker stop scamshield-test
docker rm scamshield-test
# Volume is kept on purpose so the database survives.
# Delete it only if you really want to erase all data:
# docker volume rm scamshield-data
```

## 8. Prove it refuses to start without SECRET_KEY

```powershell
docker run --name scamshield-no-secret `
  -e RUN_MIGRATIONS=true `
  -e ENVIRONMENT=production `
  -e DATABASE_URL="sqlite:////data/scamshield.db" `
  -v scamshield-data:/data `
  -p 8001:8000 `
  scamshield-backend
# Expect: RuntimeError: SECRET_KEY is not set. Set a random string of at
# least 32 characters in the SECRET_KEY environment variable before
# starting the app.
docker rm scamshield-no-secret
```
