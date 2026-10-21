# Architecture

## System diagram

```mermaid
flowchart LR
    Browser["Browser"] --> Next["Next.js App Router<br/>/api/* rewrite to backend"]
    Next --> API["FastAPI<br/>middleware: request-id, security headers,<br/>CORS allow-list, body limits"]
    API --> Auth["Auth: cookie JWT / X-API-Key / anonymous IP"]
    Auth --> Analyzers["String analyzers<br/>url / message / upi / upi_qr<br/>(pure, offline)"]
    Auth --> RL[("Redis<br/>sliding-window counters<br/>ss:rl:*")]
    RL --> Auth
    Analyzers --> Fetch["safe_fetch<br/>resolve-once, IP pinning,<br/>Host+SNI, re-validated redirects"]
    Fetch --> Age["Domain age<br/>RDAP rdap.org, cached 7d/1h,<br/>max 2 lookups per scan"]
    Age --> Score["calculate_score<br/>dedup + combos, cap 100"]
    Score --> DB[("SQLite<br/>SQLAlchemy + Alembic")]
    DB --> API
    API --> Next
    Reports["Community reports<br/>pending until approved"] --> DB
    Admin["Admin moderation<br/>approve/reject"] --> Reports
```

## POST /api/scan sequence

```mermaid
sequenceDiagram
    participant B as Browser
    participant N as Next.js proxy
    participant F as FastAPI
    participant T as api_throttle
    participant A as analyzers
    participant S as safe_fetch
    participant R as RDAP (rdap.org)
    participant D as SQLite

    B->>N: POST /api/scan {type, input}
    N->>F: proxy + httpOnly cookie
    F->>T: resolve_caller(cookie / X-API-Key / IP)
    T-->>F: caller + limits (401/429 on failure)
    F->>A: analyze_url / analyze_message / analyze_upi
    F->>S: fetch URL (url scans)
    S->>S: resolve once, block private IPs
    S->>S: connect to validated IP, Host+SNI
    S->>S: follow <=5 redirects, re-validate each
    F->>R: domain age (<=2 lookups, cached)
    R-->>F: age days or None
    F->>F: calculate_score(findings + combos)
    F->>D: save scan (PII redacted)
    F-->>B: verdict + findings + notes + rate-limit headers
```

## Database (ER)

```mermaid
erDiagram
    users ||--o{ scans : "owns"
    users ||--o{ reports : "files"
    users ||--o{ api_keys : "owns"
    scans ||--o{ scan_findings : "has"
    campaigns ||--o{ reports : "groups"
    campaigns ||--o{ indicators : "groups"
    api_keys ||--o{ api_usage : "logs"
    reports }o--|| campaigns : "approved-into"
    indicators }o--|| campaigns : "belongs-to"

    users {
        string id PK
        string email UK
        string password_hash
        string role
        bool is_active
        datetime created_at
    }
    scans {
        string id PK
        string user_id FK
        string input_type
        string input_hash
        string raw_input
        int risk_score
        string verdict
        string summary
        json redirect_chain
        json notes
        datetime created_at
    }
    scan_findings {
        int id PK
        string scan_id FK
        string rule_code
        int severity
        string explanation
    }
    indicators {
        int id PK
        string type
        string value UK
        int confidence
        string source
        string campaign_id FK
        datetime created_at
    }
    campaigns {
        string id PK
        string title
        string scam_type
        int report_count
        datetime first_seen
        datetime last_seen
    }
    reports {
        string id PK
        string user_id FK
        string campaign_id FK
        string scam_type
        string content
        string reported_value_type
        string reported_value
        string reporter_key
        string status
        datetime created_at
        string reviewed_by
        datetime reviewed_at
    }
    api_keys {
        string id PK
        string user_id FK
        string name
        string key_prefix
        string key_hash UK
        int daily_limit
        int per_minute_limit
        bool revoked
        datetime created_at
        datetime last_used_at
    }
    api_usage {
        int id PK
        string api_key_id FK
        string endpoint
        int status_code
        datetime created_at
    }
    domain_age_cache {
        int id PK
        string domain UK
        datetime created_on
        datetime checked_at
    }
```

## Design decisions (why)

- **Rule-based scoring, no LLM in the loop** (`app/services/scoring.py`): every point maps to a named, testable rule, so verdicts are explainable and deterministic.
- **Analyzers are pure string functions** (`url_analyzer.py`, `message_analyzer.py`, `upi_analyzer.py`): offline, fast, and unit-testable; network/DB effects enter only through explicit parameters (`fetch_result`, `db`, `age_days`).
- **Fetch to pinned IPs, not hostnames** (`safe_fetch.py`): closes the DNS-rebinding time-of-check gap; `Host`/SNI keep virtual-hosting and certificate checks correct.
- **Alembic for schema changes** (not `create_all`): migrations replay/roll back on any copy of the DB, and `test_migration_sync.py` fails CI-style if models drift from migrations.
- **SQLite now, PostgreSQL planned**: one-file zero-setup DB for local dev; `psycopg[binary]` is pinned and migrations avoid SQLite-only DDL so the move is a URL change plus Docker compose (planned).
- **Redis sliding-window limits** (`rate_limit.py`, `api_throttle.py`): one sorted set per caller key (prune-old, count/add, expire in a single MULTI/EXEC pipeline, so replicas can't interleave); keys are `ss:rl:<scope>:<sha256>` so emails/IPs/key ids never reach Redis; `Retry-After` comes from the oldest hit; 1 s Redis timeout with in-memory fallback so a Redis outage weakens limits to per-process instead of breaking requests (logins included).
- **httpOnly SameSite=Lax cookie + same-origin proxy** (`deps.py`, `next.config.ts`): tokens never touch JavaScript; default-empty CORS allow-list because cross-origin is never needed.
- **Hash-only API keys** (`routes_keys.py`, `api_throttle.py`): `ss_live_` keys shown once; only SHA-256 goes to the DB, lookups by hash.
- **Fail-closed auxiliaries**: usage/cache/best-effort lookups may never break a scan (each guarded, each `# nosec`-annotated for bandit).
