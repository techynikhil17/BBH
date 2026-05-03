"""Targeted HackerOne report loader from local TOP*.md files.

Source: pre-ranked lists from the hackerone-reports-master corpus
(`tops_by_bug_type/TOP<CATEGORY>.md`). Each file contains lines of the form

    1. [title](https://hackerone.com/reports/12345) to PROGRAM - 137 upvotes, $5000

This loader is offline-only — it reads files from disk, never makes network
requests — so it doesn't fit the AsyncCollector pattern (no rate limiting,
no retries). Kept as a plain function returning a list of RawReport.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from ..dedup import url_hash
from ..models import RawReport

logger = logging.getLogger(__name__)

LINE_PATTERN = re.compile(
    r"^\s*\d+\.\s+"
    r"\[(?P<title>.+?)\]"
    r"\((?P<url>https?://hackerone\.com/reports/\d+)\)"
    r"(?:\s+to\s+(?P<program>.+?))?"
    r"\s+-\s+(?P<upvotes>\d+)\s+upvotes,\s+\$(?P<bounty>[\d,]+)",
)


def category_from_filename(path: Path) -> str:
    """`TOPSSRF.md` → `ssrf`. Falls back to the lowercased stem if the file
    doesn't follow the TOP<CAT> convention."""
    stem = path.stem
    if stem.upper().startswith("TOP"):
        stem = stem[3:]
    return stem.lower()


def _parse_bounty(raw: str) -> float | None:
    """`5,000` → 5000.0; `0` → None (zero-bounty reports often mean
    'unspecified' rather than a literal $0 award)."""
    value = float(raw.replace(",", ""))
    return value if value > 0 else None


def load_top_file(
    path: Path,
    *,
    top_n: int | None = None,
    collected_at: datetime | None = None,
) -> list[RawReport]:
    """Parse a single TOP*.md file into RawReport objects.

    - Only lines whose URL matches `hackerone.com/reports/<id>` are included
      (the regex enforces this).
    - `vuln_type_tags` is set from the filename category.
    - `top_n` caps the number of returned reports (in file order).
    """
    if not path.exists():
        logger.warning("TOP file not found: %s", path)
        return []

    tag = category_from_filename(path)
    now = collected_at or datetime.now(timezone.utc)

    out: list[RawReport] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        m = LINE_PATTERN.match(line)
        if not m:
            continue

        url = m.group("url")
        title = m.group("title").strip()
        program = (m.group("program") or "").strip() or None
        bounty = _parse_bounty(m.group("bounty"))

        out.append(
            RawReport(
                source="hackerone",
                title=title,
                url=url,
                severity=None,
                program=program,
                bounty_usd=bounty,
                disclosed_at=None,
                vuln_type_tags=[tag],
                raw_content_preview=None,
                content_hash=url_hash(url),
                collected_at=now,
                source_metadata={
                    "ranked_source_file": path.name,
                    "rank_in_file": len(out) + 1,
                    "upvotes": int(m.group("upvotes")),
                },
            )
        )
        if top_n is not None and len(out) >= top_n:
            break

    return out


def load_categories(
    source_dir: Path,
    categories: list[str],
    *,
    top_n: int | None = None,
) -> dict[str, list[RawReport]]:
    """Load multiple categories. Returns {category: [RawReport, ...]}.

    Each `category` is matched against `TOP<CATEGORY>.md` (case-insensitive).
    Missing files are logged and produce an empty list for that category.
    """
    results: dict[str, list[RawReport]] = {}
    now = datetime.now(timezone.utc)
    for cat in categories:
        filename = f"TOP{cat.upper()}.md"
        path = source_dir / filename
        results[cat.lower()] = load_top_file(path, top_n=top_n, collected_at=now)
    return results
