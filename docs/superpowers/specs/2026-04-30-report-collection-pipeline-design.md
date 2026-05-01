# Design Spec: Report Collection Pipeline (PROMPT 01)

**Date:** 2026-04-30  
**Status:** Approved  
**Pipeline position:** Stage 1 of 7 — feeds into PROMPT 02 (LLM Pattern Extraction)

---

## 1. Context & Goals

This is the first stage of a 7-prompt self-improving bug bounty research system:

```
01 Collect → 02 Extract Patterns → 03 Generate Skills → 04 Research Agent
          → 05 Update Skills → 06 Generate Reports → 07 Orchestrator
```

The pipeline scrapes publicly disclosed, legitimately paid bug bounty reports from five sources, deduplicates them, stores them in SQLite, and exports a JSONL file consumed by PROMPT 02.

**Success criteria:**
- Collects 200–500+ new reports per run across all sources
- Zero crashes from single-source failures
- Dedup rate tracked and reported
- JSONL output is schema-stable and sufficient for LLM pattern extraction

---

## 2. Environment

- **Platform:** WSL2 (Ubuntu 22.04 LTS) on Windows 11
- **Python:** 3.11+ in a virtualenv at `~/projects/bug-bounty/venv/`
- **Project root:** `~/projects/bug-bounty/` (inside WSL filesystem, not `/mnt/c/`)
- **Setup:** `setup_env.sh` bootstraps the full environment on first run

---

## 3. Project Structure

```
bug-bounty/
├── setup_env.sh                     # One-shot WSL2 + BB tools bootstrapper
├── .env.example                     # GITHUB_TOKEN template
├── .env                             # gitignored
├── requirements.txt
├── collector/
│   ├── main.py                      # Click CLI entrypoint
│   ├── config.py                    # Paths, rate limits, source toggles
│   ├── models.py                    # Pydantic v2 RawReport
│   ├── storage.py                   # aiosqlite storage layer
│   ├── dedup.py                     # SHA256 content hash
│   ├── sources/
│   │   ├── __init__.py
│   │   ├── base.py                  # AsyncCollector ABC
│   │   ├── hackerone.py             # GraphQL XHR interception
│   │   ├── bugcrowd.py              # Crowdstream XHR interception
│   │   ├── pentesterland.py         # RSS via feedparser
│   │   ├── github_writeups.py       # GitHub REST API (PAT optional)
│   │   └── medium_rss.py            # Medium tag RSS × 3 tags
│   └── run_collection.sh            # Activates venv, runs collect
└── data/
    ├── raw/                         # reports.jsonl
    ├── logs/                        # collection_{ts}.log, errors.log
    └── reports.db                   # SQLite dedup store
```

---

## 4. Architecture

### 4.1 Data Flow

```
asyncio.gather()
  ├── HackerOne  → Playwright → intercepts /graphql XHR → httpx paginates
  ├── Bugcrowd   → Playwright → intercepts crowdstream XHR → httpx paginates
  ├── PentesterLand → feedparser (no browser)
  ├── GitHub        → httpx (PAT if present, else unauth)
  └── Medium        → feedparser × 3 tags concurrently
        │
        ▼  async generator: each source yields RawReport as discovered
   dedup.py — SHA256(url) checked against SQLite PRIMARY KEY
        │
        ├── new → INSERT OR IGNORE into SQLite
        └── dup → skip, increment counter
        │
        ▼
   Rich Live table (per-source count + status)
        │
        ▼
   storage.export_to_jsonl() — streams all new records to reports.jsonl
        │
        ▼
   Final summary + structured log file
```

### 4.2 Concurrency Model

- All 5 sources run via `asyncio.gather(return_exceptions=True)`
- Playwright sources share a single `asyncio.Semaphore(2)` — max 2 browser contexts simultaneously
- `return_exceptions=True` ensures one failed source doesn't cancel the rest
- Storage writes are serialised through a single `aiosqlite` connection held for the session lifetime

---

## 5. Data Model

### 5.1 RawReport (models.py)

```python
from pydantic import BaseModel, field_validator
from typing import Optional, Literal, Any
from datetime import datetime

class RawReport(BaseModel):
    source: Literal["hackerone", "bugcrowd", "pentesterland", "github", "medium"]
    title: str
    url: str
    severity: Optional[Literal["critical", "high", "medium", "low", "unknown"]] = None
    program: Optional[str] = None
    bounty_usd: Optional[float] = None
    disclosed_at: Optional[datetime] = None
    vuln_type_tags: list[str] = []
    raw_content_preview: Optional[str] = None   # ≤2000 chars, sentence-boundary truncated
    content_hash: str                            # SHA256(url)
    collected_at: datetime
    source_metadata: dict[str, Any] = {}         # stars, author, point_value, etc.
```

**`source_metadata` examples by source:**
- HackerOne: `{"reporter": "...", "cve": "CVE-2024-XXXX"}`
- Bugcrowd: `{"point_value": 150, "submission_count": 3}`
- GitHub: `{"stars": 42, "topics": ["xss", "bugbounty"]}`
- Medium: `{"author": "...", "reading_time": 5}`

### 5.2 Severity Normalisation

```python
SEVERITY_MAP = {
    # HackerOne labels
    "critical": "critical", "high": "high", "medium": "medium", "low": "low",
    # Bugcrowd priority labels
    "p1": "critical", "p2": "high", "p3": "medium", "p4": "low", "p5": "low",
    # Fallback
    "informational": "low", "none": "low",
}
# Anything not in map → "unknown"
```

### 5.3 Content Preview Truncation

Truncate at the last sentence boundary (`.`, `!`, `?`) within 2000 chars. If no sentence boundary found within 2000 chars, truncate at last whitespace. Never hard-cut mid-word.

---

## 6. Storage

### 6.1 SQLite Schema

```sql
CREATE TABLE IF NOT EXISTS raw_reports (
    content_hash        TEXT PRIMARY KEY,
    source              TEXT NOT NULL,
    title               TEXT NOT NULL,
    url                 TEXT NOT NULL,
    severity            TEXT,
    program             TEXT,
    bounty_usd          REAL,
    disclosed_at        TEXT,           -- ISO8601
    vuln_type_tags      TEXT,           -- JSON array
    raw_content_preview TEXT,
    collected_at        TEXT NOT NULL,  -- ISO8601
    source_metadata     TEXT            -- JSON object
);

CREATE INDEX IF NOT EXISTS idx_source    ON raw_reports(source);
CREATE INDEX IF NOT EXISTS idx_severity  ON raw_reports(severity);
CREATE INDEX IF NOT EXISTS idx_disclosed ON raw_reports(disclosed_at);
```

`INSERT OR IGNORE` on `content_hash` PRIMARY KEY handles dedup atomically.

### 6.2 Storage API

```python
class Storage:
    async def __aenter__(self) / __aexit__()     # context manager, holds one connection
    async def save_report(report: RawReport) -> bool       # True=new, False=dup
    async def get_stats() -> dict[str, int]                # per-source + total counts
    async def get_reports_by_severity(sev: str) -> list[RawReport]
    async def export_to_jsonl(path: str) -> int            # rows written, streams in 500-row batches
    async def get_uncollected_count() -> int
```

---

## 7. Source Collectors

### 7.1 Abstract Base (base.py)

```python
class AsyncCollector(ABC):
    source_name: str
    rate_limit_seconds: float = 2.0

    @abstractmethod
    async def collect(self, limit: int) -> AsyncGenerator[RawReport, None]: ...

    async def _sleep(self): await asyncio.sleep(self.rate_limit_seconds)

    async def _retry(self, coro_fn, retries=3):
        # exponential backoff: 1s, 2s, 4s; raises on final failure
        for attempt in range(retries):
            try:
                return await coro_fn()
            except Exception as e:
                if attempt == retries - 1: raise
                await asyncio.sleep(2 ** attempt)
```

### 7.2 HackerOne (hackerone.py)

**Strategy:** XHR interception of `/graphql` endpoint.

1. Playwright navigates to `https://hackerone.com/hacktivity?querystring=disclosed`
2. `page.on("response")` captures first response matching `**/graphql`
3. Extracts response JSON + request headers (for httpx replay)
4. `httpx.AsyncClient` paginates using the same GraphQL query with `cursor` variable
5. 2s delay between httpx pages
6. Stop conditions: empty results page OR `limit` reached

**GraphQL fields extracted:**
```
id, title, severity_rating, awarded_amount, currency,
disclosed_at, team.name, weakness.name, url
```

**Bounty normalisation:** convert non-USD amounts using `currency` field — if non-USD and no conversion available, set `bounty_usd=None`, store original in `source_metadata`.

### 7.3 Bugcrowd (bugcrowd.py)

**Strategy:** XHR interception of internal JSON endpoint.

1. Playwright navigates to `https://bugcrowd.com/crowdstream`
2. Intercepts the first JSON XHR whose URL matches the `/crowdstream` pattern (exact path discovered at runtime via `page.on("response")`)
3. Captures JSON response + headers for httpx replay
4. Paginates with `?page=N`, 2s delay
5. Extracts: `title`, `priority` → severity, `target.name` → program, `point_value`, `submitted_at`, `url`

### 7.4 PentesterLand (pentesterland.py)

**Strategy:** Pure feedparser, no browser.

- Feed URL: `https://pentester.land/writeups.rss`
- Iterate `feed.entries`, yield one `RawReport` per entry
- `entry.tags` → `vuln_type_tags`
- No pagination needed — RSS returns latest N entries
- Rate limit: 5s between feed fetches (single fetch, so effectively no limit)

### 7.5 GitHub (github_writeups.py)

**Strategy:** GitHub REST Search API.

- Endpoint: `GET https://api.github.com/search/repositories`
- Query: `"bug bounty" writeup disclosed in:readme,description`
- Auth: `Authorization: Bearer {GITHUB_TOKEN}` if env var present, else unauthenticated
- Rate limiting: `asyncio.Semaphore` + token bucket
  - Authenticated: 30 req/min
  - Unauthenticated: 10 req/min (logs warning on startup)
- Paginates with `?page=N&per_page=100`
- `source_metadata`: `{"stars": N, "topics": [...], "language": "..."}`

### 7.6 Medium RSS (medium_rss.py)

**Strategy:** feedparser × 3 tag feeds, concurrent.

```
https://medium.com/feed/tag/bug-bounty
https://medium.com/feed/tag/bugbounty
https://medium.com/feed/tag/bugbountytips
```

All three parsed concurrently with `asyncio.gather()`. Cross-tag duplicates caught by dedup layer (SHA256 of URL). Author from `entry.author` stored in `source_metadata`.

---

## 8. CLI

### 8.1 Commands

```bash
# Collect from all sources, limit 500 total
python main.py collect --sources all --limit 500

# Collect from specific sources
python main.py collect --sources hackerone bugcrowd --limit 200

# Export stored reports to JSONL
python main.py export --format jsonl --output data/raw/reports.jsonl

# Show stats
python main.py stats
```

### 8.2 Rich Output

During collection, a live Rich table shows:

```
┌─────────────────┬──────────┬───────┬────────┐
│ Source          │ Status   │ New   │ Dups   │
├─────────────────┼──────────┼───────┼────────┤
│ HackerOne       │ running  │  142  │   18   │
│ Bugcrowd        │ done     │   87  │    5   │
│ PentesterLand   │ done     │   34  │    2   │
│ GitHub          │ running  │   61  │    0   │
│ Medium          │ error    │    0  │    0   │
└─────────────────┴──────────┴───────┴────────┘
Total new: 324  |  Dups skipped: 25  |  Elapsed: 00:02:14
```

---

## 9. Error Handling

| Scenario | Behaviour |
|---|---|
| Single source raises exception | Logged to `errors.log`, other sources continue |
| httpx request fails | Retry 3× with 1s/2s/4s backoff, then log + skip page |
| Playwright `TimeoutError` | Retry once with fresh page, then mark source as error |
| HTTP 429 | Back off 30s, retry once |
| Malformed report data | Pydantic `ValidationError` caught, logged, report skipped |
| DB write fails | Logged as critical, pipeline continues (in-memory buffer attempted) |

All errors logged as structured JSON:
```json
{"ts": "2026-04-30T17:30:00Z", "level": "error", "source": "medium", "msg": "...", "url": "..."}
```

---

## 10. Setup Script (setup_env.sh)

Single idempotent script. Safe to re-run.

**Steps:**
1. `apt update && apt upgrade -y`
2. Install apt packages: `python3.11 python3.11-venv python3-pip git curl wget jq tmux nmap masscan sqlmap`
3. Install Go 1.22 to `/usr/local/go`
4. Install Go-based tools to `~/go/bin`:
   - `nuclei`, `subfinder`, `httpx` (toolkit), `dnsx`, `katana` — projectdiscovery suite
   - `ffuf`, `gobuster` — fuzzing
   - `waybackurls`, `gau`, `anew`, `gf`, `qsreplace`, `assetfinder` — recon utilities
   - `dalfox` — XSS scanner
5. Clone `https://github.com/danielmiessler/SecLists` → `~/tools/SecLists` (shallow clone)
6. Add `~/go/bin` to PATH in `~/.bashrc`
7. Create Python venv at `~/projects/bug-bounty/venv`
8. `pip install -r requirements.txt`
9. `playwright install chromium`
10. Copy `.env.example` → `.env` if not already present

---

## 11. Configuration (.env.example)

```bash
# GitHub Personal Access Token (optional — increases rate limit from 60/hr to 5000/hr)
GITHUB_TOKEN=

# Output paths (defaults shown, override if needed)
DATA_DIR=data
DB_PATH=data/reports.db
JSONL_OUTPUT=data/raw/reports.jsonl
LOG_DIR=data/logs
```

---

## 12. JSONL Output Schema

Each line is a valid JSON object matching `RawReport`. Example:

```json
{
  "source": "hackerone",
  "title": "SSRF in webhook endpoint allows internal network scanning",
  "url": "https://hackerone.com/reports/1234567",
  "severity": "high",
  "program": "Acme Corp",
  "bounty_usd": 2500.0,
  "disclosed_at": "2024-11-15T00:00:00Z",
  "vuln_type_tags": ["ssrf", "server-side-request-forgery"],
  "raw_content_preview": "The webhook feature at /api/webhooks allows users to specify a callback URL...",
  "content_hash": "a3f2c1...",
  "collected_at": "2026-04-30T17:00:00Z",
  "source_metadata": {"reporter": "hunter123"}
}
```

---

## 13. Downstream Interface Contract (for PROMPT 02)

PROMPT 02 (LLM Pattern Extraction) can rely on:
- Every record has `source`, `title`, `url`, `content_hash`, `collected_at` — never null
- `raw_content_preview` is ≤2000 chars and contains the most signal-dense text available
- `severity` is always one of the 5 literal values or `null` — never a raw string
- `vuln_type_tags` is always a list (may be empty)
- `source_metadata` is always a dict (may be empty)
- JSONL is append-safe — same `content_hash` will never appear twice

---

## 14. Dependencies (requirements.txt)

```
playwright>=1.44
httpx>=0.27
feedparser>=6.0
pydantic>=2.7
rich>=13.7
aiofiles>=23.2
aiosqlite>=0.20
click>=8.1
python-dotenv>=1.0
```
