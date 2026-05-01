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
