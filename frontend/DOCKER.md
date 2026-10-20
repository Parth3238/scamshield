# ScamShield frontend — Docker (Windows PowerShell)

Frontend only. No compose. No secrets in the image.
`BACKEND_URL` is a BUILD-time value (the `/api` rewrite is baked
into the build). Rebuild to change it.

## 1. Build the image

For local test (backend runs on Windows, reachable from the container):

```powershell
cd C:\Users\parth\scamshield
docker build -t scamshield-frontend --build-arg BACKEND_URL=http://host.docker.internal:8000 ./frontend
```

Default (no `--build-arg`) bakes in `http://backend:8000`,
the future compose service name:

```powershell
docker build -t scamshield-frontend ./frontend
```

Check size:

```powershell
docker image ls scamshield-frontend
```

## 2. Run the container

```powershell
docker run -d --name scamshield-front-test -p 3000:3000 scamshield-frontend
```

## 3. Check it works

```powershell
# Home page (expect StatusCode 200)
(Invoke-WebRequest -Uri http://127.0.0.1:3000/ -UseBasicParsing).StatusCode

# Security headers (all four must be present)
$r = Invoke-WebRequest -Uri http://127.0.0.1:3000/ -UseBasicParsing
$r.Headers["Content-Security-Policy"]
$r.Headers["X-Content-Type-Options"]   # expect: nosniff
$r.Headers["Referrer-Policy"]          # expect: no-referrer
$r.Headers["X-Frame-Options"]          # expect: DENY

# Prove it is NOT root (expect: appuser)
docker exec scamshield-front-test whoami
```

## 4. View logs

```powershell
docker logs scamshield-front-test
# live follow with Ctrl+C to stop watching (container keeps running):
docker logs -f scamshield-front-test
```

## 5. Stop and remove

```powershell
docker stop scamshield-front-test
docker rm scamshield-front-test
```
