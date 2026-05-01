# Report Collection Pipeline — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a fully async bug bounty report collection pipeline that scrapes 5 public sources, deduplicates via SQLite, and exports JSONL for downstream LLM pattern extraction.

**Architecture:** Five async source collectors run concurrently via `asyncio.gather()`; browser-based sources (HackerOne, Bugcrowd) use Playwright to intercept XHR/GraphQL responses then replay pagination via httpx; lightweight sources (PentesterLand, Medium, GitHub) use feedparser/httpx directly. All results stream into SQLite in real time then export to JSONL at the end of each run.

**Tech Stack:** Python 3.11, Playwright (async), httpx, feedparser, pydantic v2, rich, aiofiles, aiosqlite, click, python-dotenv, pytest + pytest-asyncio

---

## File Map

```
bug-bounty/
├── setup_env.sh
├── .env.example
├── .gitignore
├── requirements.txt
├── pyproject.toml                        ← pytest config
├── collector/
│   ├── __init__.py
│   ├── config.py
│   ├── dedup.py                          ← url_hash() only
│   ├── models.py                         ← RawReport + helpers
│   ├── storage.py                        ← Storage async context manager
│   ├── main.py                           ← Click CLI
│   ├── run_collection.sh
│   └── sources/
│       ├── __init__.py
│       ├── base.py
│       ├── pentesterland.py
│       ├── medium_rss.py
│       ├── github_writeups.py
│       ├── hackerone.py
│       └── bugcrowd.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_models.py
│   ├── test_dedup.py
│   ├── test_storage.py
│   ├── test_cli.py
│   └── sources/
│       ├── __init__.py
│       ├── test_pentesterland.py
│       ├── test_medium_rss.py
│       ├── test_github_writeups.py
│       ├── test_hackerone.py
│       └── test_bugcrowd.py
└── data/
    ├── raw/
    ├── logs/
    └── .gitkeep
```

---

## Task 1: Project Scaffolding

**Files:**
- Create: `requirements.txt`
- Create: `pyproject.toml`
- Create: `.env.example`
- Create: `.gitignore`
- Create: `collector/__init__.py`
- Create: `collector/sources/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/sources/__init__.py`
- Create: `data/.gitkeep`

- [ ] **Step 1: Create directory tree**

```bash
mkdir -p collector/sources tests/sources data/raw data/logs
touch collector/__init__.py collector/sources/__init__.py
touch tests/__init__.py tests/sources/__init__.py
touch data/.gitkeep
```

- [ ] **Step 2: Write requirements.txt**

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
pytest>=8.2
pytest-asyncio>=0.23
```

- [ ] **Step 3: Write pyproject.toml**

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

- [ ] **Step 4: Write .env.example**

```bash
# GitHub Personal Access Token (optional — 5000 req/hr vs 60 req/hr unauthenticated)
GITHUB_TOKEN=

# Output paths — defaults are relative to project root
DATA_DIR=data
DB_PATH=data/reports.db
JSONL_OUTPUT=data/raw/reports.jsonl
LOG_DIR=data/logs
```

- [ ] **Step 5: Write .gitignore**

```
.env
data/raw/
data/logs/
data/reports.db
venv/
__pycache__/
*.pyc
.pytest_cache/
*.egg-info/
```

- [ ] **Step 6: Verify structure**

```bash
find . -type f | sort
```

Expected: all scaffold files listed, no `data/raw/` or `data/logs/` content

- [ ] **Step 7: Commit**

```bash
git init
git add requirements.txt pyproject.toml .env.example .gitignore collector/__init__.py \
        collector/sources/__init__.py tests/__init__.py tests/sources/__init__.py data/.gitkeep
git commit -m "chore: project scaffolding"
```

---

## Task 2: setup_env.sh

**Files:**
- Create: `setup_env.sh`

- [ ] **Step 1: Write setup_env.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$HOME/tools"
GO_VERSION="1.22.3"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Updating apt packages"
sudo apt-get update -y && sudo apt-get upgrade -y

echo "==> Installing apt dependencies"
sudo apt-get install -y \
    python3.11 python3.11-venv python3-pip \
    git curl wget jq tmux \
    nmap masscan sqlmap \
    build-essential libssl-dev

echo "==> Installing Go ${GO_VERSION}"
if ! go version 2>/dev/null | grep -q "${GO_VERSION}"; then
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
fi

export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

if ! grep -q '/usr/local/go/bin' "$HOME/.bashrc"; then
    echo 'export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"' >> "$HOME/.bashrc"
fi

echo "==> Installing Go-based security tools"
GO_TOOLS=(
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/OJ/gobuster/v3@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/assetfinder@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    name=$(basename "${tool%%@*}")
    if ! command -v "$name" &>/dev/null; then
        echo "  Installing $name..."
        go install "$tool"
    else
        echo "  $name already installed, skipping"
    fi
done

echo "==> Cloning SecLists (shallow)"
mkdir -p "$TOOLS_DIR"
if [ ! -d "$TOOLS_DIR/SecLists" ]; then
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$TOOLS_DIR/SecLists"
else
    echo "  SecLists already present, skipping"
fi

echo "==> Setting up Python virtual environment"
if [ ! -d "$PROJECT_DIR/venv" ]; then
    python3.11 -m venv "$PROJECT_DIR/venv"
fi

source "$PROJECT_DIR/venv/bin/activate"
pip install --upgrade pip
pip install -r "$PROJECT_DIR/requirements.txt"

echo "==> Installing Playwright browsers"
playwright install chromium

echo "==> Copying .env.example → .env (if not present)"
if [ ! -f "$PROJECT_DIR/.env" ]; then
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    echo "  Created .env — add your GITHUB_TOKEN if desired"
fi

echo ""
echo "Setup complete. Run: source venv/bin/activate"
```

- [ ] **Step 2: Make executable and verify syntax**

```bash
chmod +x setup_env.sh
bash -n setup_env.sh
```

Expected: no output (syntax OK)

- [ ] **Step 3: Commit**

```bash
git add setup_env.sh
git commit -m "chore: add WSL2 + bug bounty tools setup script"
```

---

## Task 3: dedup.py + models.py + tests

**Files:**
- Create: `collector/dedup.py`
- Create: `collector/models.py`
- Create: `tests/test_dedup.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write failing tests for dedup**

`tests/test_dedup.py`:
```python
from collector.dedup import url_hash


def test_url_hash_is_64_chars():
    assert len(url_hash("https://example.com/report/1")) == 64


def test_url_hash_is_deterministic():
    url = "https://hackerone.com/reports/123"
    assert url_hash(url) == url_hash(url)


def test_url_hash_differs_for_different_urls():
    assert url_hash("https://example.com/1") != url_hash("https://example.com/2")


def test_url_hash_hex_string():
    result = url_hash("https://example.com")
    assert all(c in "0123456789abcdef" for c in result)
```

- [ ] **Step 2: Run — expect FAIL**

```bash
pytest tests/test_dedup.py -v
```

Expected: `ModuleNotFoundError: No module named 'collector.dedup'`

- [ ] **Step 3: Write collector/dedup.py**

```python
import hashlib


def url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()
```

- [ ] **Step 4: Run — expect PASS**

```bash
pytest tests/test_dedup.py -v
```

Expected: 4 passed

- [ ] **Step 5: Write failing tests for models**

`tests/test_models.py`:
```python
import pytest
from datetime import datetime, timezone
from collector.models import (
    RawReport,
    truncate_to_sentence,
    normalize_severity,
)
from collector.dedup import url_hash


# --- truncate_to_sentence ---

def test_truncate_short_text_unchanged():
    text = "Hello world."
    assert truncate_to_sentence(text, 2000) == text


def test_truncate_at_sentence_boundary():
    short = "First sentence."
    text = short + " " + "x" * 2000
    result = truncate_to_sentence(text, 2000)
    assert result == short


def test_truncate_at_whitespace_when_no_boundary():
    text = "a" * 1990 + " " + "b" * 100
    result = truncate_to_sentence(text, 2000)
    assert len(result) <= 2000
    assert not result.endswith("b")


def test_truncate_hard_cut_when_no_whitespace():
    text = "x" * 2100
    result = truncate_to_sentence(text, 2000)
    assert len(result) == 2000


def test_truncate_exclamation_and_question():
    assert truncate_to_sentence("Found it! " + "x" * 2000, 2000) == "Found it!"
    assert truncate_to_sentence("Really? " + "x" * 2000, 2000) == "Really?"


# --- normalize_severity ---

def test_normalize_hackerone_labels():
    assert normalize_severity("critical") == "critical"
    assert normalize_severity("high") == "high"
    assert normalize_severity("medium") == "medium"
    assert normalize_severity("low") == "low"


def test_normalize_bugcrowd_priorities():
    assert normalize_severity("p1") == "critical"
    assert normalize_severity("p2") == "high"
    assert normalize_severity("p3") == "medium"
    assert normalize_severity("p4") == "low"
    assert normalize_severity("p5") == "low"


def test_normalize_unknown_returns_unknown():
    assert normalize_severity("bogus") == "unknown"


def test_normalize_none_returns_none():
    assert normalize_severity(None) is None


def test_normalize_case_insensitive():
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("P1") == "critical"


# --- RawReport ---

def test_raw_report_minimal_valid():
    url = "https://hackerone.com/reports/1"
    report = RawReport(
        source="hackerone",
        title="XSS in search",
        url=url,
        content_hash=url_hash(url),
        collected_at=datetime.now(timezone.utc),
    )
    assert report.source == "hackerone"
    assert report.severity is None
    assert report.vuln_type_tags == []
    assert report.source_metadata == {}


def test_raw_report_invalid_source():
    with pytest.raises(Exception):
        RawReport(
            source="unknown_source",
            title="test",
            url="https://example.com",
            content_hash=url_hash("https://example.com"),
            collected_at=datetime.now(timezone.utc),
        )


def test_raw_report_content_hash_matches_url():
    url = "https://hackerone.com/reports/999"
    report = RawReport(
        source="hackerone",
        title="Test",
        url=url,
        content_hash=url_hash(url),
        collected_at=datetime.now(timezone.utc),
    )
    assert report.content_hash == url_hash(url)
```

- [ ] **Step 6: Run — expect FAIL**

```bash
pytest tests/test_models.py -v
```

Expected: `ModuleNotFoundError: No module named 'collector.models'`

- [ ] **Step 7: Write collector/models.py**

```python
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel

from .dedup import url_hash

SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "p1": "critical",
    "p2": "high",
    "p3": "medium",
    "p4": "low",
    "p5": "low",
    "informational": "low",
    "none": "low",
}


def truncate_to_sentence(text: str, max_chars: int = 2000) -> str:
    if len(text) <= max_chars:
        return text
    chunk = text[:max_chars]
    for boundary in (".", "!", "?"):
        idx = chunk.rfind(boundary)
        if idx > max_chars // 2:
            return chunk[: idx + 1]
    idx = chunk.rfind(" ")
    if idx > 0:
        return chunk[:idx]
    return chunk


def normalize_severity(
    raw: Optional[str],
) -> Optional[Literal["critical", "high", "medium", "low", "unknown"]]:
    if raw is None:
        return None
    return SEVERITY_MAP.get(raw.lower().strip(), "unknown")  # type: ignore[return-value]


class RawReport(BaseModel):
    source: Literal["hackerone", "bugcrowd", "pentesterland", "github", "medium"]
    title: str
    url: str
    severity: Optional[Literal["critical", "high", "medium", "low", "unknown"]] = None
    program: Optional[str] = None
    bounty_usd: Optional[float] = None
    disclosed_at: Optional[datetime] = None
    vuln_type_tags: list[str] = []
    raw_content_preview: Optional[str] = None
    content_hash: str
    collected_at: datetime
    source_metadata: dict[str, Any] = {}
```

- [ ] **Step 8: Run — expect PASS**

```bash
pytest tests/test_dedup.py tests/test_models.py -v
```

Expected: all tests pass

- [ ] **Step 9: Commit**

```bash
git add collector/dedup.py collector/models.py tests/test_dedup.py tests/test_models.py
git commit -m "feat: add dedup utility and RawReport model"
```

---

## Task 4: storage.py + tests

**Files:**
- Create: `collector/storage.py`
- Create: `tests/conftest.py`
- Create: `tests/test_storage.py`

- [ ] **Step 1: Write conftest.py**

`tests/conftest.py`:
```python
import pytest


@pytest.fixture
def tmp_db(tmp_path) -> str:
    return str(tmp_path / "test.db")
```

- [ ] **Step 2: Write failing tests**

`tests/test_storage.py`:
```python
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from collector.dedup import url_hash
from collector.models import RawReport
from collector.storage import Storage


def make_report(url: str, source: str = "hackerone", severity: str | None = None) -> RawReport:
    return RawReport(
        source=source,
        title=f"Report {url}",
        url=url,
        severity=severity,
        content_hash=url_hash(url),
        collected_at=datetime.now(timezone.utc),
    )


async def test_save_new_report_returns_true(tmp_db):
    async with Storage(tmp_db) as s:
        assert await s.save_report(make_report("https://hackerone.com/reports/1")) is True


async def test_save_duplicate_returns_false(tmp_db):
    async with Storage(tmp_db) as s:
        r = make_report("https://hackerone.com/reports/1")
        await s.save_report(r)
        assert await s.save_report(r) is False


async def test_get_stats_per_source(tmp_db):
    async with Storage(tmp_db) as s:
        await s.save_report(make_report("https://hackerone.com/reports/1", "hackerone"))
        await s.save_report(make_report("https://hackerone.com/reports/2", "hackerone"))
        await s.save_report(make_report("https://bugcrowd.com/reports/1", "bugcrowd"))
        stats = await s.get_stats()
    assert stats["hackerone"] == 2
    assert stats["bugcrowd"] == 1
    assert stats["total"] == 3


async def test_get_reports_by_severity(tmp_db):
    async with Storage(tmp_db) as s:
        await s.save_report(make_report("https://h1.com/1", severity="high"))
        await s.save_report(make_report("https://h1.com/2", severity="low"))
        results = await s.get_reports_by_severity("high")
    assert len(results) == 1
    assert results[0].severity == "high"


async def test_export_to_jsonl(tmp_db, tmp_path):
    out = str(tmp_path / "out.jsonl")
    async with Storage(tmp_db) as s:
        await s.save_report(make_report("https://h1.com/1"))
        await s.save_report(make_report("https://h1.com/2"))
        count = await s.export_to_jsonl(out)
    assert count == 2
    lines = Path(out).read_text().strip().splitlines()
    assert len(lines) == 2
    parsed = json.loads(lines[0])
    assert parsed["source"] == "hackerone"


async def test_get_uncollected_count(tmp_db):
    async with Storage(tmp_db) as s:
        await s.save_report(make_report("https://h1.com/1"))
        await s.save_report(make_report("https://h1.com/2"))
        count = await s.get_uncollected_count()
    assert count == 2
```

- [ ] **Step 3: Run — expect FAIL**

```bash
pytest tests/test_storage.py -v
```

Expected: `ModuleNotFoundError: No module named 'collector.storage'`

- [ ] **Step 4: Write collector/storage.py**

```python
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiofiles
import aiosqlite

from .models import RawReport

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS raw_reports (
    content_hash        TEXT PRIMARY KEY,
    source              TEXT NOT NULL,
    title               TEXT NOT NULL,
    url                 TEXT NOT NULL,
    severity            TEXT,
    program             TEXT,
    bounty_usd          REAL,
    disclosed_at        TEXT,
    vuln_type_tags      TEXT,
    raw_content_preview TEXT,
    collected_at        TEXT NOT NULL,
    source_metadata     TEXT
);
CREATE INDEX IF NOT EXISTS idx_source    ON raw_reports(source);
CREATE INDEX IF NOT EXISTS idx_severity  ON raw_reports(severity);
CREATE INDEX IF NOT EXISTS idx_disclosed ON raw_reports(disclosed_at);
"""


class Storage:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def __aenter__(self) -> "Storage":
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(_CREATE_TABLE)
        await self._conn.commit()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._conn:
            await self._conn.close()

    async def save_report(self, report: RawReport) -> bool:
        cursor = await self._conn.execute(
            """INSERT OR IGNORE INTO raw_reports
               (content_hash,source,title,url,severity,program,bounty_usd,
                disclosed_at,vuln_type_tags,raw_content_preview,collected_at,source_metadata)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                report.content_hash,
                report.source,
                report.title,
                report.url,
                report.severity,
                report.program,
                report.bounty_usd,
                report.disclosed_at.isoformat() if report.disclosed_at else None,
                json.dumps(report.vuln_type_tags),
                report.raw_content_preview,
                report.collected_at.isoformat(),
                json.dumps(report.source_metadata),
            ),
        )
        await self._conn.commit()
        return cursor.rowcount == 1

    async def get_stats(self) -> dict[str, int]:
        cursor = await self._conn.execute(
            "SELECT source, COUNT(*) as cnt FROM raw_reports GROUP BY source"
        )
        rows = await cursor.fetchall()
        stats: dict[str, int] = {row["source"]: row["cnt"] for row in rows}
        stats["total"] = sum(stats.values())
        return stats

    async def get_reports_by_severity(self, severity: str) -> list[RawReport]:
        cursor = await self._conn.execute(
            "SELECT * FROM raw_reports WHERE severity = ?", (severity,)
        )
        rows = await cursor.fetchall()
        return [_row_to_report(row) for row in rows]

    async def export_to_jsonl(self, output_path: str) -> int:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        count = 0
        cursor = await self._conn.execute(
            "SELECT * FROM raw_reports ORDER BY collected_at"
        )
        async with aiofiles.open(output_path, "w") as fh:
            while True:
                rows = await cursor.fetchmany(500)
                if not rows:
                    break
                for row in rows:
                    await fh.write(_row_to_report(row).model_dump_json() + "\n")
                    count += 1
        return count

    async def get_uncollected_count(self) -> int:
        cursor = await self._conn.execute("SELECT COUNT(*) as cnt FROM raw_reports")
        row = await cursor.fetchone()
        return row["cnt"]


def _row_to_report(row: aiosqlite.Row) -> RawReport:
    return RawReport(
        content_hash=row["content_hash"],
        source=row["source"],
        title=row["title"],
        url=row["url"],
        severity=row["severity"],
        program=row["program"],
        bounty_usd=row["bounty_usd"],
        disclosed_at=(
            datetime.fromisoformat(row["disclosed_at"]) if row["disclosed_at"] else None
        ),
        vuln_type_tags=json.loads(row["vuln_type_tags"]) if row["vuln_type_tags"] else [],
        raw_content_preview=row["raw_content_preview"],
        collected_at=datetime.fromisoformat(row["collected_at"]),
        source_metadata=json.loads(row["source_metadata"]) if row["source_metadata"] else {},
    )
```

- [ ] **Step 5: Run — expect PASS**

```bash
pytest tests/test_storage.py -v
```

Expected: 6 passed

- [ ] **Step 6: Commit**

```bash
git add collector/storage.py tests/conftest.py tests/test_storage.py
git commit -m "feat: add Storage layer with SQLite dedup"
```

---

## Task 5: sources/base.py

**Files:**
- Create: `collector/sources/base.py`

- [ ] **Step 1: Write collector/sources/base.py**

```python
from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import AsyncGenerator

from ..models import RawReport

logger = logging.getLogger(__name__)


class AsyncCollector(ABC):
    source_name: str
    rate_limit_seconds: float = 2.0

    @abstractmethod
    async def collect(self, limit: int) -> AsyncGenerator[RawReport, None]:
        ...

    async def _sleep(self) -> None:
        await asyncio.sleep(self.rate_limit_seconds)

    async def _retry(self, coro_fn, retries: int = 3):
        for attempt in range(retries):
            try:
                return await coro_fn()
            except Exception as exc:
                if attempt == retries - 1:
                    raise
                wait = 2 ** attempt
                logger.warning(
                    "%s retry %d/%d in %ds: %s",
                    self.source_name, attempt + 1, retries, wait, exc,
                )
                await asyncio.sleep(wait)
```

- [ ] **Step 2: Verify import**

```bash
python -c "from collector.sources.base import AsyncCollector; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add collector/sources/base.py
git commit -m "feat: add AsyncCollector abstract base"
```

---

## Task 6: PentesterLand collector + tests

**Files:**
- Create: `collector/sources/pentesterland.py`
- Create: `tests/sources/test_pentesterland.py`

- [ ] **Step 1: Write failing tests**

`tests/sources/test_pentesterland.py`:
```python
from unittest.mock import patch, MagicMock
from datetime import timezone

from collector.sources.pentesterland import PentesterLandCollector


class FeedEntry:
    def __init__(self, title, link, summary="", tags=None, published_parsed=None):
        self._d = {
            "title": title,
            "link": link,
            "summary": summary,
        }
        self.tags = [MagicMock(term=t) for t in (tags or [])]
        self.published_parsed = published_parsed or (2024, 6, 15, 0, 0, 0, 0, 0, 0)

    def get(self, key, default=""):
        return self._d.get(key, default)


def make_mock_feed(entries):
    feed = MagicMock()
    feed.entries = entries
    return feed


async def test_collects_basic_report():
    entry = FeedEntry(
        title="XSS in Acme Corp",
        link="https://pentester.land/writeups/xss-acme",
        summary="Found an XSS in the search field. The input was reflected without encoding.",
        tags=["xss", "bugbounty"],
    )
    feed = make_mock_feed([entry])

    with patch("collector.sources.pentesterland.feedparser.parse", return_value=feed):
        collector = PentesterLandCollector()
        reports = [r async for r in collector.collect(10)]

    assert len(reports) == 1
    r = reports[0]
    assert r.source == "pentesterland"
    assert r.title == "XSS in Acme Corp"
    assert r.url == "https://pentester.land/writeups/xss-acme"
    assert "xss" in r.vuln_type_tags
    assert r.disclosed_at is not None
    assert r.disclosed_at.tzinfo == timezone.utc


async def test_respects_limit():
    entries = [
        FeedEntry(title=f"Report {i}", link=f"https://pentester.land/{i}")
        for i in range(20)
    ]
    feed = make_mock_feed(entries)

    with patch("collector.sources.pentesterland.feedparser.parse", return_value=feed):
        collector = PentesterLandCollector()
        reports = [r async for r in collector.collect(5)]

    assert len(reports) == 5


async def test_skips_entries_without_link():
    entries = [
        FeedEntry(title="No link", link=""),
        FeedEntry(title="Has link", link="https://pentester.land/1"),
    ]
    feed = make_mock_feed(entries)

    with patch("collector.sources.pentesterland.feedparser.parse", return_value=feed):
        reports = [r async for r in PentesterLandCollector().collect(10)]

    assert len(reports) == 1
    assert reports[0].title == "Has link"


async def test_content_hash_is_sha256_of_url():
    from collector.dedup import url_hash
    entry = FeedEntry(title="T", link="https://pentester.land/abc")
    feed = make_mock_feed([entry])

    with patch("collector.sources.pentesterland.feedparser.parse", return_value=feed):
        reports = [r async for r in PentesterLandCollector().collect(10)]

    assert reports[0].content_hash == url_hash("https://pentester.land/abc")
```

- [ ] **Step 2: Run — expect FAIL**

```bash
pytest tests/sources/test_pentesterland.py -v
```

Expected: `ModuleNotFoundError: No module named 'collector.sources.pentesterland'`

- [ ] **Step 3: Write collector/sources/pentesterland.py**

```python
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import AsyncGenerator

import feedparser

from ..dedup import url_hash
from ..models import RawReport, truncate_to_sentence
from .base import AsyncCollector

logger = logging.getLogger(__name__)

FEED_URL = "https://pentester.land/writeups.rss"


class PentesterLandCollector(AsyncCollector):
    source_name = "pentesterland"
    rate_limit_seconds = 5.0

    async def collect(self, limit: int) -> AsyncGenerator[RawReport, None]:
        loop = asyncio.get_event_loop()
        feed = await loop.run_in_executor(None, feedparser.parse, FEED_URL)

        collected = 0
        for entry in feed.entries:
            if collected >= limit:
                break

            link = entry.get("link", "")
            if not link:
                continue

            title = entry.get("title", "").strip()

            disclosed_at = None
            if getattr(entry, "published_parsed", None):
                disclosed_at = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)

            tags = [
                t.term.lower()
                for t in getattr(entry, "tags", [])
                if getattr(t, "term", None)
            ]

            summary = entry.get("summary", "") or ""
            preview = truncate_to_sentence(summary, 2000) if summary else None

            yield RawReport(
                source="pentesterland",
                title=title,
                url=link,
                severity=None,
                program=None,
                bounty_usd=None,
                disclosed_at=disclosed_at,
                vuln_type_tags=tags,
                raw_content_preview=preview,
                content_hash=url_hash(link),
                collected_at=datetime.now(timezone.utc),
                source_metadata={},
            )
            collected += 1
```

- [ ] **Step 4: Run — expect PASS**

```bash
pytest tests/sources/test_pentesterland.py -v
```

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add collector/sources/pentesterland.py tests/sources/test_pentesterland.py
git commit -m "feat: add PentesterLand RSS collector"
```

---

## Task 7: Medium RSS collector + tests

**Files:**
- Create: `collector/sources/medium_rss.py`
- Create: `tests/sources/test_medium_rss.py`

- [ ] **Step 1: Write failing tests**

`tests/sources/test_medium_rss.py`:
```python
from unittest.mock import patch, MagicMock

from collector.sources.medium_rss import MediumRSSCollector


class FeedEntry:
    def __init__(self, title, link, author="", tags=None, published_parsed=None):
        self._d = {"title": title, "link": link, "summary": ""}
        self.author = author
        self.tags = [MagicMock(term=t) for t in (tags or [])]
        self.published_parsed = published_parsed or (2024, 3, 1, 0, 0, 0, 0, 0, 0)

    def get(self, key, default=""):
        return self._d.get(key, default)


def make_feed(entries):
    f = MagicMock()
    f.entries = entries
    return f


async def test_collects_from_all_three_feeds():
    feeds = [
        make_feed([FeedEntry("A", "https://medium.com/a")]),
        make_feed([FeedEntry("B", "https://medium.com/b")]),
        make_feed([FeedEntry("C", "https://medium.com/c")]),
    ]

    with patch("collector.sources.medium_rss.feedparser.parse", side_effect=feeds):
        reports = [r async for r in MediumRSSCollector().collect(10)]

    assert len(reports) == 3
    urls = {r.url for r in reports}
    assert urls == {"https://medium.com/a", "https://medium.com/b", "https://medium.com/c"}


async def test_deduplicates_cross_feed_urls():
    same_url = "https://medium.com/shared"
    feeds = [
        make_feed([FeedEntry("Same A", same_url)]),
        make_feed([FeedEntry("Same B", same_url)]),
        make_feed([FeedEntry("Different", "https://medium.com/other")]),
    ]

    with patch("collector.sources.medium_rss.feedparser.parse", side_effect=feeds):
        reports = [r async for r in MediumRSSCollector().collect(10)]

    urls = [r.url for r in reports]
    assert urls.count(same_url) == 1


async def test_respects_limit():
    feeds = [
        make_feed([FeedEntry(f"A{i}", f"https://medium.com/a{i}") for i in range(10)]),
        make_feed([FeedEntry(f"B{i}", f"https://medium.com/b{i}") for i in range(10)]),
        make_feed([FeedEntry(f"C{i}", f"https://medium.com/c{i}") for i in range(10)]),
    ]

    with patch("collector.sources.medium_rss.feedparser.parse", side_effect=feeds):
        reports = [r async for r in MediumRSSCollector().collect(5)]

    assert len(reports) == 5


async def test_author_stored_in_source_metadata():
    feeds = [
        make_feed([FeedEntry("T", "https://medium.com/t", author="alice")]),
        make_feed([]),
        make_feed([]),
    ]

    with patch("collector.sources.medium_rss.feedparser.parse", side_effect=feeds):
        reports = [r async for r in MediumRSSCollector().collect(10)]

    assert reports[0].source_metadata["author"] == "alice"


async def test_tolerates_feed_exception():
    from unittest.mock import MagicMock
    good_feed = make_feed([FeedEntry("OK", "https://medium.com/ok")])

    with patch(
        "collector.sources.medium_rss.feedparser.parse",
        side_effect=[Exception("network error"), good_feed, good_feed],
    ):
        reports = [r async for r in MediumRSSCollector().collect(10)]

    assert any(r.url == "https://medium.com/ok" for r in reports)
```

- [ ] **Step 2: Run — expect FAIL**

```bash
pytest tests/sources/test_medium_rss.py -v
```

Expected: `ModuleNotFoundError: No module named 'collector.sources.medium_rss'`

- [ ] **Step 3: Write collector/sources/medium_rss.py**

```python
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import AsyncGenerator

import feedparser

from ..dedup import url_hash
from ..models import RawReport, truncate_to_sentence
from .base import AsyncCollector

logger = logging.getLogger(__name__)

FEEDS = [
    "https://medium.com/feed/tag/bug-bounty",
    "https://medium.com/feed/tag/bugbounty",
    "https://medium.com/feed/tag/bugbountytips",
]


class MediumRSSCollector(AsyncCollector):
    source_name = "medium"
    rate_limit_seconds = 2.0

    async def collect(self, limit: int) -> AsyncGenerator[RawReport, None]:
        loop = asyncio.get_event_loop()
        results = await asyncio.gather(
            *[loop.run_in_executor(None, feedparser.parse, url) for url in FEEDS],
            return_exceptions=True,
        )

        seen: set[str] = set()
        collected = 0

        for result in results:
            if isinstance(result, Exception):
                logger.warning("Medium feed error: %s", result)
                continue
            for entry in result.entries:
                if collected >= limit:
                    return

                link = entry.get("link", "")
                if not link or link in seen:
                    continue
                seen.add(link)

                title = entry.get("title", "").strip()
                summary = entry.get("summary", "") or ""
                preview = truncate_to_sentence(summary, 2000) if summary else None

                disclosed_at = None
                if getattr(entry, "published_parsed", None):
                    disclosed_at = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)

                tags = [
                    t.term.lower()
                    for t in getattr(entry, "tags", [])
                    if getattr(t, "term", None)
                ]

                yield RawReport(
                    source="medium",
                    title=title,
                    url=link,
                    severity=None,
                    program=None,
                    bounty_usd=None,
                    disclosed_at=disclosed_at,
                    vuln_type_tags=tags,
                    raw_content_preview=preview,
                    content_hash=url_hash(link),
                    collected_at=datetime.now(timezone.utc),
                    source_metadata={"author": getattr(entry, "author", "")},
                )
                collected += 1
```

- [ ] **Step 4: Run — expect PASS**

```bash
pytest tests/sources/test_medium_rss.py -v
```

Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add collector/sources/medium_rss.py tests/sources/test_medium_rss.py
git commit -m "feat: add Medium RSS collector"
```

---

## Task 8: GitHub collector + tests

**Files:**
- Create: `collector/sources/github_writeups.py`
- Create: `tests/sources/test_github_writeups.py`

- [ ] **Step 1: Write failing tests**

`tests/sources/test_github_writeups.py`:
```python
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from collector.sources.github_writeups import GitHubWriteupsCollector

SAMPLE_RESPONSE = {
    "items": [
        {
            "full_name": "hunter/ssrf-writeup",
            "html_url": "https://github.com/hunter/ssrf-writeup",
            "description": "SSRF vulnerability in Acme Corp disclosed",
            "stargazers_count": 42,
            "topics": ["ssrf", "bugbounty"],
            "language": "Python",
            "updated_at": "2024-11-01T10:00:00Z",
        },
        {
            "full_name": "researcher/xss-chain",
            "html_url": "https://github.com/researcher/xss-chain",
            "description": "XSS to account takeover chain",
            "stargazers_count": 15,
            "topics": ["xss"],
            "language": None,
            "updated_at": "2024-10-15T08:00:00Z",
        },
    ]
}

EMPTY_RESPONSE = {"items": []}


def make_mock_response(data, status=200):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


async def test_collects_repos():
    responses = [make_mock_response(SAMPLE_RESPONSE), make_mock_response(EMPTY_RESPONSE)]

    with patch.dict("os.environ", {}, clear=True):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=responses)
            mock_client_cls.return_value = mock_client

            collector = GitHubWriteupsCollector()
            collector.rate_limit_seconds = 0
            reports = [r async for r in collector.collect(10)]

    assert len(reports) == 2
    assert reports[0].source == "github"
    assert reports[0].url == "https://github.com/hunter/ssrf-writeup"
    assert reports[0].source_metadata["stars"] == 42
    assert "ssrf" in reports[0].vuln_type_tags


async def test_uses_token_when_env_set():
    with patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test123"}):
        collector = GitHubWriteupsCollector()
    assert "Authorization" in collector._headers
    assert collector._headers["Authorization"] == "Bearer ghp_test123"
    assert collector.rate_limit_seconds == 2.0


async def test_no_token_warns_and_slower():
    with patch.dict("os.environ", {}, clear=True):
        collector = GitHubWriteupsCollector()
    assert "Authorization" not in collector._headers
    assert collector.rate_limit_seconds == 6.0


async def test_respects_limit():
    big = {"items": [
        {
            "full_name": f"u/r{i}",
            "html_url": f"https://github.com/u/r{i}",
            "description": "desc",
            "stargazers_count": 0,
            "topics": [],
            "language": None,
            "updated_at": "2024-01-01T00:00:00Z",
        }
        for i in range(20)
    ]}

    with patch.dict("os.environ", {}, clear=True):
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=make_mock_response(big))
            mock_client_cls.return_value = mock_client

            collector = GitHubWriteupsCollector()
            collector.rate_limit_seconds = 0
            reports = [r async for r in collector.collect(3)]

    assert len(reports) == 3
```

- [ ] **Step 2: Run — expect FAIL**

```bash
pytest tests/sources/test_github_writeups.py -v
```

Expected: `ModuleNotFoundError: No module named 'collector.sources.github_writeups'`

- [ ] **Step 3: Write collector/sources/github_writeups.py**

```python
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import AsyncGenerator

import httpx

from ..dedup import url_hash
from ..models import RawReport
from .base import AsyncCollector

logger = logging.getLogger(__name__)

_API = "https://api.github.com/search/repositories"
_QUERY = '"bug bounty" writeup disclosed in:readme,description'
_UA = "SecurityResearch/1.0 BugBountyStudy"


class GitHubWriteupsCollector(AsyncCollector):
    source_name = "github"
    rate_limit_seconds = 6.0

    def __init__(self) -> None:
        token = os.getenv("GITHUB_TOKEN")
        self._headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "User-Agent": _UA,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"
            self.rate_limit_seconds = 2.0
            logger.info("GitHub: authenticated (5000 req/hr)")
        else:
            logger.warning(
                "GitHub: unauthenticated (60 req/hr) — set GITHUB_TOKEN for higher limits"
            )

    async def collect(self, limit: int) -> AsyncGenerator[RawReport, None]:
        collected = 0
        page = 1

        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            while collected < limit:
                params = {
                    "q": _QUERY,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": min(100, limit - collected),
                    "page": page,
                }

                async def fetch(p=params):
                    r = await client.get(_API, params=p)
                    if r.status_code == 429:
                        await asyncio.sleep(30)
                        r = await client.get(_API, params=p)
                    r.raise_for_status()
                    return r.json()

                try:
                    data = await self._retry(fetch)
                except Exception as exc:
                    logger.error("GitHub page %d error: %s", page, exc)
                    break

                items = data.get("items", [])
                if not items:
                    break

                for item in items:
                    if collected >= limit:
                        return
                    html_url = item["html_url"]
                    updated = item.get("updated_at", "")
                    disclosed_at = None
                    if updated:
                        disclosed_at = datetime.fromisoformat(
                            updated.replace("Z", "+00:00")
                        )
                    yield RawReport(
                        source="github",
                        title=item.get("full_name", ""),
                        url=html_url,
                        severity=None,
                        program=None,
                        bounty_usd=None,
                        disclosed_at=disclosed_at,
                        vuln_type_tags=item.get("topics", []),
                        raw_content_preview=item.get("description") or None,
                        content_hash=url_hash(html_url),
                        collected_at=datetime.now(timezone.utc),
                        source_metadata={
                            "stars": item.get("stargazers_count", 0),
                            "topics": item.get("topics", []),
                            "language": item.get("language"),
                        },
                    )
                    collected += 1

                page += 1
                await self._sleep()
```

- [ ] **Step 4: Run — expect PASS**

```bash
pytest tests/sources/test_github_writeups.py -v
```

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add collector/sources/github_writeups.py tests/sources/test_github_writeups.py
git commit -m "feat: add GitHub REST API collector with optional PAT"
```

---

## Task 9: HackerOne collector + tests

**Files:**
- Create: `collector/sources/hackerone.py`
- Create: `tests/sources/test_hackerone.py`

- [ ] **Step 1: Write failing tests**

`tests/sources/test_hackerone.py`:
```python
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from collector.sources.hackerone import HackerOneCollector, _parse_edges
from collector.dedup import url_hash

SAMPLE_EDGES = [
    {
        "node": {
            "id": "1234567",
            "title": "SSRF via webhook callback",
            "severity_rating": "high",
            "total_awarded_amount": "2500",
            "currency": "USD",
            "disclosed_at": "2024-11-01T00:00:00Z",
            "report": {"id": "1234567", "url": "https://hackerone.com/reports/1234567"},
            "team": {"name": "Acme Corp"},
            "weakness": {"name": "Server-Side Request Forgery (SSRF)"},
        },
        "cursor": "abc123",
    },
    {
        "node": {
            "id": "9999999",
            "title": "XSS in search results",
            "severity_rating": "medium",
            "total_awarded_amount": None,
            "currency": "USD",
            "disclosed_at": "2024-10-15T00:00:00Z",
            "report": {"id": "9999999", "url": "https://hackerone.com/reports/9999999"},
            "team": {"name": "Beta Inc"},
            "weakness": {"name": "Cross-Site Scripting (XSS)"},
        },
        "cursor": "def456",
    },
]

SAMPLE_GQL_RESPONSE = {
    "data": {
        "hacktivity_items": {
            "edges": SAMPLE_EDGES,
            "pageInfo": {"hasNextPage": False, "endCursor": "def456"},
        }
    }
}


def test_parse_edges_extracts_fields():
    reports = list(_parse_edges(SAMPLE_EDGES))
    assert len(reports) == 2

    r = reports[0]
    assert r.source == "hackerone"
    assert r.title == "SSRF via webhook callback"
    assert r.url == "https://hackerone.com/reports/1234567"
    assert r.severity == "high"
    assert r.program == "Acme Corp"
    assert r.bounty_usd == 2500.0
    assert "server-side request forgery (ssrf)" in r.vuln_type_tags
    assert r.content_hash == url_hash("https://hackerone.com/reports/1234567")


def test_parse_edges_null_bounty():
    reports = list(_parse_edges(SAMPLE_EDGES))
    assert reports[1].bounty_usd is None


def test_parse_edges_non_usd_bounty():
    edges = [
        {
            "node": {
                "id": "111",
                "title": "RCE",
                "severity_rating": "critical",
                "total_awarded_amount": "5000",
                "currency": "EUR",
                "disclosed_at": "2024-01-01T00:00:00Z",
                "report": {"url": "https://hackerone.com/reports/111"},
                "team": {"name": "EuroApp"},
                "weakness": None,
            }
        }
    ]
    reports = list(_parse_edges(edges))
    assert reports[0].bounty_usd is None
    assert reports[0].source_metadata["bounty_currency"] == "EUR"
    assert reports[0].source_metadata["bounty_original"] == 5000.0


def test_parse_edges_builds_url_from_id_when_no_report():
    edges = [
        {
            "node": {
                "id": "777",
                "title": "Bug",
                "severity_rating": "low",
                "total_awarded_amount": None,
                "currency": "USD",
                "disclosed_at": "2024-01-01T00:00:00Z",
                "report": None,
                "team": {"name": "Corp"},
                "weakness": None,
            }
        }
    ]
    reports = list(_parse_edges(edges))
    assert reports[0].url == "https://hackerone.com/reports/777"
```

- [ ] **Step 2: Run — expect FAIL**

```bash
pytest tests/sources/test_hackerone.py -v
```

Expected: `ModuleNotFoundError: No module named 'collector.sources.hackerone'`

- [ ] **Step 3: Write collector/sources/hackerone.py**

```python
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import AsyncGenerator, Generator

import httpx
from playwright.async_api import async_playwright

from ..dedup import url_hash
from ..models import RawReport, normalize_severity
from .base import AsyncCollector

logger = logging.getLogger(__name__)

_HACKTIVITY_URL = "https://hackerone.com/hacktivity?querystring=disclosed"
_GRAPHQL_URL = "https://hackerone.com/graphql"
_UA = "SecurityResearch/1.0 BugBountyStudy"


def _parse_edges(edges: list[dict]) -> Generator[RawReport, None, None]:
    now = datetime.now(timezone.utc)
    for edge in edges:
        node = edge.get("node") or {}
        if not node:
            continue

        report = node.get("report") or {}
        url = report.get("url") or f"https://hackerone.com/reports/{node.get('id', '')}"

        raw_amount = node.get("total_awarded_amount")
        bounty = float(raw_amount) if raw_amount else None
        currency = (node.get("currency") or "USD").upper()
        meta: dict = {}
        if currency != "USD" and bounty is not None:
            meta["bounty_original"] = bounty
            meta["bounty_currency"] = currency
            bounty = None

        weakness = node.get("weakness") or {}
        tags = [weakness["name"].lower()] if weakness.get("name") else []

        disclosed_at = None
        raw_date = node.get("disclosed_at")
        if raw_date:
            disclosed_at = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))

        team = node.get("team") or {}

        yield RawReport(
            source="hackerone",
            title=(node.get("title") or "").strip(),
            url=url,
            severity=normalize_severity(node.get("severity_rating")),
            program=team.get("name"),
            bounty_usd=bounty,
            disclosed_at=disclosed_at,
            vuln_type_tags=tags,
            raw_content_preview=None,
            content_hash=url_hash(url),
            collected_at=now,
            source_metadata=meta,
        )


class HackerOneCollector(AsyncCollector):
    source_name = "hackerone"
    rate_limit_seconds = 2.0

    async def collect(self, limit: int) -> AsyncGenerator[RawReport, None]:
        captured: dict | None = None

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page(
                user_agent=_UA,
                extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
            )

            future: asyncio.Future = asyncio.get_event_loop().create_future()

            async def on_response(resp):
                if "/graphql" in resp.url and not future.done():
                    try:
                        body = await resp.json()
                        req_body = resp.request.post_data
                        future.set_result(
                            {
                                "response": body,
                                "req_headers": dict(resp.request.headers),
                                "req_body": __import__("json").loads(req_body)
                                if req_body
                                else {},
                            }
                        )
                    except Exception as exc:
                        logger.debug("HackerOne capture error: %s", exc)

            page.on("response", on_response)
            try:
                await page.goto(_HACKTIVITY_URL, wait_until="networkidle", timeout=30000)
                captured = await asyncio.wait_for(asyncio.shield(future), timeout=15.0)
            except asyncio.TimeoutError:
                logger.error("HackerOne: GraphQL XHR not captured within timeout")
            except Exception as exc:
                logger.error("HackerOne Playwright error: %s", exc)
            finally:
                await browser.close()

        if captured is None:
            return

        collected = 0
        first = True
        cursor = None
        req_headers = {**captured["req_headers"], "User-Agent": _UA}
        base_req_body: dict = captured["req_body"]

        async with httpx.AsyncClient(headers=req_headers, timeout=30) as client:
            while collected < limit:
                if first:
                    data = captured["response"]
                    first = False
                else:
                    body = {
                        **base_req_body,
                        "variables": {
                            **base_req_body.get("variables", {}),
                            "cursor": cursor,
                        },
                    }

                    async def fetch(b=body):
                        r = await client.post(_GRAPHQL_URL, json=b)
                        if r.status_code == 429:
                            await asyncio.sleep(30)
                            r = await client.post(_GRAPHQL_URL, json=b)
                        r.raise_for_status()
                        return r.json()

                    try:
                        data = await self._retry(fetch)
                    except Exception as exc:
                        logger.error("HackerOne pagination error: %s", exc)
                        break
                    await self._sleep()

                try:
                    items_data = data["data"]["hacktivity_items"]
                    edges = items_data["edges"]
                    page_info = items_data["pageInfo"]
                except (KeyError, TypeError):
                    logger.error("HackerOne: unexpected response shape")
                    break

                if not edges:
                    break

                for report in _parse_edges(edges):
                    if collected >= limit:
                        return
                    yield report
                    collected += 1

                cursor = page_info.get("endCursor")
                if not page_info.get("hasNextPage") or not cursor:
                    break
```

- [ ] **Step 4: Run — expect PASS**

```bash
pytest tests/sources/test_hackerone.py -v
```

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add collector/sources/hackerone.py tests/sources/test_hackerone.py
git commit -m "feat: add HackerOne GraphQL XHR interception collector"
```

---

## Task 10: Bugcrowd collector + tests

**Files:**
- Create: `collector/sources/bugcrowd.py`
- Create: `tests/sources/test_bugcrowd.py`

- [ ] **Step 1: Write failing tests**

`tests/sources/test_bugcrowd.py`:
```python
from datetime import timezone

from collector.sources.bugcrowd import BugcrowdCollector, _parse_activities
from collector.dedup import url_hash

SAMPLE_ACTIVITIES = [
    {
        "title": "SQL Injection in login endpoint",
        "priority": "p1",
        "url": "/submissions/abc123",
        "target": {"name": "Acme Corp"},
        "submitted_at": "2024-11-01T12:00:00Z",
        "point_value": 500,
    },
    {
        "title": "Reflected XSS",
        "priority": "p3",
        "url": "https://bugcrowd.com/submissions/def456",
        "target": {"name": "Beta Co"},
        "submitted_at": "2024-10-20T09:00:00Z",
        "point_value": 150,
    },
]


def test_parse_activities_extracts_fields():
    reports = list(_parse_activities(SAMPLE_ACTIVITIES))
    assert len(reports) == 2

    r = reports[0]
    assert r.source == "bugcrowd"
    assert r.title == "SQL Injection in login endpoint"
    assert r.url == "https://bugcrowd.com/submissions/abc123"
    assert r.severity == "critical"
    assert r.program == "Acme Corp"
    assert r.source_metadata["point_value"] == 500
    assert r.content_hash == url_hash("https://bugcrowd.com/submissions/abc123")


def test_parse_activities_full_url_unchanged():
    reports = list(_parse_activities(SAMPLE_ACTIVITIES))
    assert reports[1].url == "https://bugcrowd.com/submissions/def456"


def test_parse_activities_severity_mapping():
    activities = [
        {"title": "T", "priority": p, "url": f"/s/{p}",
         "target": {"name": "C"}, "submitted_at": "2024-01-01T00:00:00Z", "point_value": 0}
        for p in ["p1", "p2", "p3", "p4", "p5"]
    ]
    reports = list(_parse_activities(activities))
    severities = [r.severity for r in reports]
    assert severities == ["critical", "high", "medium", "low", "low"]


def test_parse_activities_skips_no_url():
    activities = [
        {"title": "No URL", "priority": "p2", "url": "",
         "target": {"name": "C"}, "submitted_at": "2024-01-01T00:00:00Z", "point_value": 0},
        {"title": "Has URL", "priority": "p2", "url": "/s/valid",
         "target": {"name": "C"}, "submitted_at": "2024-01-01T00:00:00Z", "point_value": 0},
    ]
    reports = list(_parse_activities(activities))
    assert len(reports) == 1
    assert reports[0].title == "Has URL"


def test_parse_activities_disclosed_at_timezone():
    reports = list(_parse_activities(SAMPLE_ACTIVITIES))
    assert reports[0].disclosed_at.tzinfo == timezone.utc
```

- [ ] **Step 2: Run — expect FAIL**

```bash
pytest tests/sources/test_bugcrowd.py -v
```

Expected: `ModuleNotFoundError: No module named 'collector.sources.bugcrowd'`

- [ ] **Step 3: Write collector/sources/bugcrowd.py**

```python
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import AsyncGenerator, Generator

import httpx
from playwright.async_api import async_playwright

from ..dedup import url_hash
from ..models import RawReport, normalize_severity
from .base import AsyncCollector

logger = logging.getLogger(__name__)

_CROWDSTREAM_URL = "https://bugcrowd.com/crowdstream"
_UA = "SecurityResearch/1.0 BugBountyStudy"


def _parse_activities(activities: list[dict]) -> Generator[RawReport, None, None]:
    now = datetime.now(timezone.utc)
    for item in activities:
        raw_url = item.get("url") or item.get("report_url", "")
        if not raw_url:
            continue

        url = raw_url if raw_url.startswith("http") else f"https://bugcrowd.com{raw_url}"

        submitted = item.get("submitted_at") or item.get("created_at", "")
        disclosed_at = None
        if submitted:
            try:
                disclosed_at = datetime.fromisoformat(submitted.replace("Z", "+00:00"))
            except ValueError:
                pass

        target = item.get("target") or {}
        program = (
            target.get("name")
            or item.get("program_name")
            or item.get("engagement_name")
        )

        yield RawReport(
            source="bugcrowd",
            title=(item.get("title") or item.get("description", "")).strip(),
            url=url,
            severity=normalize_severity(item.get("priority") or item.get("severity")),
            program=program,
            bounty_usd=None,
            disclosed_at=disclosed_at,
            vuln_type_tags=[],
            raw_content_preview=None,
            content_hash=url_hash(url),
            collected_at=now,
            source_metadata={"point_value": item.get("point_value") or item.get("points", 0)},
        )


class BugcrowdCollector(AsyncCollector):
    source_name = "bugcrowd"
    rate_limit_seconds = 2.0

    async def collect(self, limit: int) -> AsyncGenerator[RawReport, None]:
        captured: dict | None = None

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page(user_agent=_UA)

            future: asyncio.Future = asyncio.get_event_loop().create_future()

            async def on_response(resp):
                if "crowdstream" in resp.url.lower() and not future.done():
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct:
                        try:
                            body = await resp.json()
                            future.set_result(
                                {
                                    "base_url": resp.url.split("?")[0],
                                    "headers": dict(resp.request.headers),
                                    "body": body,
                                }
                            )
                        except Exception as exc:
                            logger.debug("Bugcrowd capture error: %s", exc)

            page.on("response", on_response)
            try:
                await page.goto(_CROWDSTREAM_URL, wait_until="networkidle", timeout=30000)
                captured = await asyncio.wait_for(asyncio.shield(future), timeout=15.0)
            except asyncio.TimeoutError:
                logger.error("Bugcrowd: crowdstream XHR not captured within timeout")
            except Exception as exc:
                logger.error("Bugcrowd Playwright error: %s", exc)
            finally:
                await browser.close()

        if captured is None:
            return

        collected = 0
        page_num = 1
        first = True
        headers = {**captured["headers"], "User-Agent": _UA}
        base_url = captured["base_url"]

        async with httpx.AsyncClient(headers=headers, timeout=30) as client:
            while collected < limit:
                if first:
                    data = captured["body"]
                    first = False
                else:
                    async def fetch(pn=page_num):
                        r = await client.get(base_url, params={"page": pn})
                        if r.status_code == 429:
                            await asyncio.sleep(30)
                            r = await client.get(base_url, params={"page": pn})
                        r.raise_for_status()
                        return r.json()

                    try:
                        data = await self._retry(fetch)
                    except Exception as exc:
                        logger.error("Bugcrowd page %d error: %s", page_num, exc)
                        break
                    await self._sleep()

                activities = (
                    data.get("activities")
                    or data.get("submissions")
                    or data.get("data")
                    or []
                )

                if not activities:
                    break

                for report in _parse_activities(activities):
                    if collected >= limit:
                        return
                    yield report
                    collected += 1

                page_num += 1
```

- [ ] **Step 4: Run — expect PASS**

```bash
pytest tests/sources/test_bugcrowd.py -v
```

Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add collector/sources/bugcrowd.py tests/sources/test_bugcrowd.py
git commit -m "feat: add Bugcrowd crowdstream XHR interception collector"
```

---

## Task 11: config.py

**Files:**
- Create: `collector/config.py`

- [ ] **Step 1: Write collector/config.py**

```python
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_BASE = Path(__file__).parent.parent

DATA_DIR = Path(os.getenv("DATA_DIR", _BASE / "data"))
DB_PATH = Path(os.getenv("DB_PATH", DATA_DIR / "reports.db"))
JSONL_OUTPUT = Path(os.getenv("JSONL_OUTPUT", DATA_DIR / "raw" / "reports.jsonl"))
LOG_DIR = Path(os.getenv("LOG_DIR", DATA_DIR / "logs"))

ALL_SOURCES = ["hackerone", "bugcrowd", "pentesterland", "github", "medium"]
```

- [ ] **Step 2: Verify import**

```bash
python -c "from collector.config import ALL_SOURCES, DB_PATH; print(ALL_SOURCES)"
```

Expected: `['hackerone', 'bugcrowd', 'pentesterland', 'github', 'medium']`

- [ ] **Step 3: Commit**

```bash
git add collector/config.py
git commit -m "feat: add config module with env-backed paths"
```

---

## Task 12: main.py (CLI) + tests

**Files:**
- Create: `collector/main.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

`tests/test_cli.py`:
```python
from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner

from collector.main import cli


def make_mock_storage():
    storage = AsyncMock()
    storage.__aenter__ = AsyncMock(return_value=storage)
    storage.__aexit__ = AsyncMock(return_value=False)
    storage.save_report = AsyncMock(return_value=True)
    storage.get_stats = AsyncMock(return_value={"hackerone": 5, "total": 5})
    storage.export_to_jsonl = AsyncMock(return_value=5)
    return storage


def test_stats_command():
    mock_storage = make_mock_storage()
    with patch("collector.main.Storage", return_value=mock_storage):
        runner = CliRunner()
        result = runner.invoke(cli, ["stats"])
    assert result.exit_code == 0
    assert "hackerone" in result.output


def test_export_command(tmp_path):
    out = str(tmp_path / "out.jsonl")
    mock_storage = make_mock_storage()
    with patch("collector.main.Storage", return_value=mock_storage):
        runner = CliRunner()
        result = runner.invoke(cli, ["export", "--output", out])
    assert result.exit_code == 0
    assert "5" in result.output


def test_collect_all_sources():
    async def empty_collect(limit):
        return
        yield  # make it an async generator

    mock_collector = MagicMock()
    mock_collector.collect = empty_collect
    mock_storage = make_mock_storage()

    with patch("collector.main.Storage", return_value=mock_storage):
        with patch("collector.main.get_collector", return_value=mock_collector):
            runner = CliRunner()
            result = runner.invoke(cli, ["collect", "--sources", "pentesterland", "--limit", "10"])
    assert result.exit_code == 0


def test_collect_invalid_source():
    runner = CliRunner()
    result = runner.invoke(cli, ["collect", "--sources", "notasource", "--limit", "5"])
    assert result.exit_code != 0 or "error" in result.output.lower()
```

- [ ] **Step 2: Run — expect FAIL**

```bash
pytest tests/test_cli.py -v
```

Expected: `ModuleNotFoundError: No module named 'collector.main'`

- [ ] **Step 3: Write collector/main.py**

```python
from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime, timezone
from typing import Optional

import click
from rich.console import Console
from rich.live import Live
from rich.table import Table

from .config import ALL_SOURCES, DB_PATH, JSONL_OUTPUT, LOG_DIR
from .sources.bugcrowd import BugcrowdCollector
from .sources.github_writeups import GitHubWriteupsCollector
from .sources.hackerone import HackerOneCollector
from .sources.medium_rss import MediumRSSCollector
from .sources.pentesterland import PentesterLandCollector
from .storage import Storage

console = Console()

_COLLECTORS = {
    "hackerone": HackerOneCollector,
    "bugcrowd": BugcrowdCollector,
    "pentesterland": PentesterLandCollector,
    "github": GitHubWriteupsCollector,
    "medium": MediumRSSCollector,
}


def get_collector(name: str):
    if name not in _COLLECTORS:
        raise click.BadParameter(f"Unknown source '{name}'. Choose from: {', '.join(ALL_SOURCES)}")
    return _COLLECTORS[name]()


def _setup_logging(ts: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = '{"ts":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}'
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(LOG_DIR / f"collection_{ts}.log"),
            logging.FileHandler(LOG_DIR / "collection_errors.log"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def _progress_table(stats: dict[str, dict]) -> Table:
    table = Table(title="Collection Progress", show_lines=False)
    table.add_column("Source", style="cyan", width=18)
    table.add_column("Status", width=10)
    table.add_column("New", justify="right", style="green", width=6)
    table.add_column("Dups", justify="right", style="yellow", width=6)

    total_new = total_dups = 0
    status_styles = {
        "running": "[blue]running[/]",
        "done": "[green]done[/]",
        "error": "[red]error[/]",
        "pending": "[dim]pending[/]",
    }
    for src, s in stats.items():
        table.add_row(src, status_styles.get(s["status"], s["status"]), str(s["new"]), str(s["dups"]))
        total_new += s["new"]
        total_dups += s["dups"]

    table.caption = f"Total new: {total_new}  |  Dups skipped: {total_dups}"
    return table


@click.group()
def cli() -> None:
    pass


@cli.command()
@click.option("--sources", "-s", multiple=True, default=("all",),
              help="Source names (repeat flag) or 'all'. E.g. --sources hackerone --sources bugcrowd")
@click.option("--limit", "-l", default=500, show_default=True, help="Max reports per source")
@click.option("--output", "-o", default=None, help="JSONL output path")
def collect(sources: tuple[str, ...], limit: int, output: Optional[str]) -> None:
    """Collect bug bounty reports from public sources."""
    source_names = ALL_SOURCES if "all" in sources else list(sources)
    for name in source_names:
        if name not in _COLLECTORS:
            raise click.BadParameter(f"Unknown source: '{name}'")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    _setup_logging(ts)
    out = output or str(JSONL_OUTPUT)
    asyncio.run(_collect(source_names, limit, out))


async def _collect(names: list[str], limit: int, out: str) -> None:
    stats = {n: {"status": "pending", "new": 0, "dups": 0} for n in names}

    async with Storage(str(DB_PATH)) as storage:
        with Live(_progress_table(stats), refresh_per_second=4, console=console) as live:

            async def run_one(name: str) -> None:
                stats[name]["status"] = "running"
                live.update(_progress_table(stats))
                try:
                    async for report in get_collector(name).collect(limit):
                        is_new = await storage.save_report(report)
                        key = "new" if is_new else "dups"
                        stats[name][key] += 1
                        live.update(_progress_table(stats))
                    stats[name]["status"] = "done"
                except Exception as exc:
                    logging.getLogger(__name__).error("Source %s failed: %s", name, exc, exc_info=True)
                    stats[name]["status"] = "error"
                live.update(_progress_table(stats))

            await asyncio.gather(*[run_one(n) for n in names], return_exceptions=True)

        count = await storage.export_to_jsonl(out)
        console.print(f"\n[green]Exported {count} reports → {out}[/green]")


@cli.command()
@click.option("--format", "fmt", default="jsonl", type=click.Choice(["jsonl"]), show_default=True)
@click.option("--output", "-o", default=None, help="Output path")
def export(fmt: str, output: Optional[str]) -> None:
    """Export stored reports to JSONL."""
    out = output or str(JSONL_OUTPUT)
    asyncio.run(_export(out))


async def _export(out: str) -> None:
    async with Storage(str(DB_PATH)) as storage:
        count = await storage.export_to_jsonl(out)
    console.print(f"Exported {count} reports → {out}")


@cli.command()
def stats() -> None:
    """Show collection statistics."""
    asyncio.run(_stats())


async def _stats() -> None:
    async with Storage(str(DB_PATH)) as storage:
        s = await storage.get_stats()
    table = Table(title="Collection Stats")
    table.add_column("Source")
    table.add_column("Count", justify="right")
    for k, v in s.items():
        table.add_row(k, str(v))
    console.print(table)


if __name__ == "__main__":
    cli()
```

- [ ] **Step 4: Run — expect PASS**

```bash
pytest tests/test_cli.py -v
```

Expected: 4 passed

- [ ] **Step 5: Run full test suite**

```bash
pytest -v
```

Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add collector/main.py tests/test_cli.py
git commit -m "feat: add Click CLI with Rich live progress table"
```

---

## Task 13: run_collection.sh + final wiring

**Files:**
- Create: `collector/run_collection.sh`

- [ ] **Step 1: Write collector/run_collection.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV="$PROJECT_DIR/venv"

if [ ! -d "$VENV" ]; then
    echo "ERROR: venv not found at $VENV. Run setup_env.sh first."
    exit 1
fi

source "$VENV/bin/activate"

LIMIT="${LIMIT:-500}"
SOURCES="${SOURCES:-all}"

cd "$PROJECT_DIR"

if [ "$SOURCES" = "all" ]; then
    python -m collector.main collect --limit "$LIMIT"
else
    # Split space-separated sources into --sources flags
    ARGS=()
    for src in $SOURCES; do
        ARGS+=("--sources" "$src")
    done
    python -m collector.main collect "${ARGS[@]}" --limit "$LIMIT"
fi
```

- [ ] **Step 2: Make executable**

```bash
chmod +x collector/run_collection.sh
bash -n collector/run_collection.sh
```

Expected: no output (syntax OK)

- [ ] **Step 3: Verify CLI entry point**

```bash
python -m collector.main --help
```

Expected: help text showing `collect`, `export`, `stats` commands

- [ ] **Step 4: Run full test suite one final time**

```bash
pytest -v --tb=short
```

Expected: all tests pass, 0 errors

- [ ] **Step 5: Final commit**

```bash
git add collector/run_collection.sh
git commit -m "feat: add run_collection.sh shell runner — pipeline complete"
```

---

## Self-Review Checklist

**Spec coverage:**

| Spec requirement | Task |
|---|---|
| HackerOne Playwright + GraphQL XHR interception | Task 9 |
| Bugcrowd Playwright + crowdstream XHR interception | Task 10 |
| PentesterLand RSS feedparser | Task 6 |
| GitHub REST API + optional PAT | Task 8 |
| Medium RSS × 3 tags | Task 7 |
| RawReport pydantic v2 model | Task 3 |
| 2000-char sentence-boundary truncation | Task 3 |
| Severity normalisation (HackerOne + Bugcrowd labels) | Task 3 |
| SHA256 URL dedup | Task 3 |
| SQLite storage + INSERT OR IGNORE | Task 4 |
| `save_report` / `get_stats` / `export_to_jsonl` | Task 4 |
| `asyncio.gather` concurrent execution | Task 12 |
| Rich live progress table | Task 12 |
| Click CLI (`collect`, `export`, `stats`) | Task 12 |
| Retry with exponential backoff (1s/2s/4s) | Task 5 |
| HTTP 429 back-off (30s) | Tasks 8, 9, 10 |
| Single source failure isolation | Task 12 |
| JSONL export streamed in 500-row batches | Task 4 |
| setup_env.sh WSL2 + all BB tools | Task 2 |
| `.env` / `GITHUB_TOKEN` support | Tasks 8, 11 |
| User-Agent header | Tasks 8, 9, 10 |
| `run_collection.sh` | Task 13 |

All spec requirements covered. No TBDs or placeholders.
