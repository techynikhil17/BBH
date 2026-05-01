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
