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
