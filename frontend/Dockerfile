# syntax=docker/dockerfile:1
# ScamShield frontend. Multi-stage: deps -> build -> minimal runtime.
# No secrets here. BACKEND_URL is a BUILD-time value for the /api rewrite.

# ---------- Stage 1: dependencies ----------
FROM node:25-alpine AS deps
WORKDIR /app
# Cache-friendly: install first, so rebuilds skip this layer
# unless package.json / package-lock.json changed.
COPY package.json package-lock.json ./
RUN npm ci
# Telemetry off for all later stages too.
ENV NEXT_TELEMETRY_DISABLED=1

# ---------- Stage 2: build ----------
FROM node:25-alpine AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# BACKEND_URL is read in next.config.ts at BUILD time (rewrites are
# baked into the build output). Default is the future compose service
# name; override with --build-arg BACKEND_URL=... when building.
ARG BACKEND_URL=http://backend:8000
ENV BACKEND_URL=$BACKEND_URL
RUN npm run build

# ---------- Stage 3: runtime (minimal, non-root) ----------
FROM node:25-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000

# Non-root user. Alpine uses addgroup/adduser (no useradd).
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Only what standalone mode needs to run: the traced server,
# static assets, and public files. No source, no devDependencies.
COPY --from=builder /app/public ./public
COPY --from=builder --chown=appuser:appgroup /app/.next/standalone ./
COPY --from=builder --chown=appuser:appgroup /app/.next/static ./.next/static

USER appuser
EXPOSE 3000

# No curl in the image: use node (global fetch exists in Node 22).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>{process.exit(r.ok?0:1)}).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
