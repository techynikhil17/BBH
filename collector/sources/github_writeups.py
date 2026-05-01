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
