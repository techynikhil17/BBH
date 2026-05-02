"""HackerOne hacktivity collector — Playwright captures the live
HacktivitySearchQuery, then httpx replays it page-by-page.

Updated 2026-05 — HackerOne replaced the legacy ``hacktivity_items`` GraphQL
shape with ``HacktivitySearchQuery``. The new response is
``data.search.nodes`` with paragraph-level ``hacktivity_summary`` per node.
Pagination is offset-based (``from`` variable) instead of cursor-based.
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
from datetime import datetime, timezone
from typing import AsyncGenerator, Generator

import httpx
from playwright.async_api import async_playwright

from ..dedup import url_hash
from ..models import RawReport, normalize_severity, truncate_to_sentence
from .base import AsyncCollector

logger = logging.getLogger(__name__)

_HACKTIVITY_URL = "https://hackerone.com/hacktivity?querystring=disclosed"
_GRAPHQL_URL = "https://hackerone.com/graphql"
_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
_TARGET_OPERATION = "HacktivitySearchQuery"


def _parse_edges(nodes: list[dict]) -> Generator[RawReport, None, None]:
    """Map a list of HacktivityDocument nodes to RawReport objects.

    Kept named ``_parse_edges`` for backward compatibility with the test
    suite, but the input is the modern ``data.search.nodes`` array.
    """
    now = datetime.now(timezone.utc)
    for node in nodes:
        if not isinstance(node, dict) or not node:
            continue

        report = node.get("report") or {}
        url = (
            report.get("url")
            or f"https://hackerone.com/reports/{report.get('databaseId') or node.get('_id') or node.get('id', '')}"
        )

        title = (report.get("title") or "").strip()
        # The hacktivity feed mixes fully-disclosed reports (with public titles
        # + summaries) with bounty announcements for content-private reports.
        # Without a title there's nothing for the extractor to learn from, so
        # we skip those entries — saves downstream wasted Claude Code spend.
        if not title:
            continue

        # Bounty + currency. The new schema sometimes has currency under
        # team.currency rather than node.currency.
        raw_amount = node.get("total_awarded_amount")
        bounty = None
        if raw_amount is not None:
            try:
                bounty = float(raw_amount)
            except (TypeError, ValueError):
                bounty = None
        team = node.get("team") or {}
        currency = (
            (node.get("currency") or team.get("currency") or "USD").upper()
        )
        meta: dict = {}
        if currency != "USD" and bounty is not None:
            meta["bounty_original"] = bounty
            meta["bounty_currency"] = currency
            bounty = None

        # Tags: prefer the legacy ``weakness.name``, fall back to the flat
        # ``cwe`` string the new schema returns.
        weakness = node.get("weakness") or {}
        if weakness.get("name"):
            tags = [weakness["name"].lower()]
        elif node.get("cwe"):
            tags = [str(node["cwe"]).lower()]
        else:
            tags = []
        if isinstance(node.get("cve_ids"), list):
            tags.extend(str(c).lower() for c in node["cve_ids"] if c)

        disclosed_at = None
        raw_date = report.get("disclosed_at") or node.get("disclosed_at")
        if raw_date:
            try:
                disclosed_at = datetime.fromisoformat(str(raw_date).replace("Z", "+00:00"))
            except ValueError:
                disclosed_at = None

        # The summary is what makes this collector valuable for the extractor.
        preview = None
        rgc = report.get("report_generated_content") or {}
        summary = rgc.get("hacktivity_summary")
        if summary:
            preview = truncate_to_sentence(str(summary), 2000)

        yield RawReport(
            source="hackerone",
            title=title,
            url=url,
            severity=normalize_severity(node.get("severity_rating")),
            program=team.get("name"),
            bounty_usd=bounty,
            disclosed_at=disclosed_at,
            vuln_type_tags=tags,
            raw_content_preview=preview,
            content_hash=url_hash(url),
            collected_at=now,
            source_metadata=meta,
        )


def _is_hacktivity_request(post_data: str | None) -> bool:
    if not post_data:
        return False
    return _TARGET_OPERATION in post_data


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
                if future.done() or "/graphql" not in resp.url:
                    return
                # Filter for the HacktivitySearchQuery operation specifically —
                # the page also fires AppQuery, CurrentUser, GetTeamsQuery, etc.
                if not _is_hacktivity_request(resp.request.post_data):
                    return
                try:
                    body = await resp.json()
                    req_body = resp.request.post_data
                    future.set_result(
                        {
                            "response": body,
                            "req_headers": dict(resp.request.headers),
                            "req_body": _json.loads(req_body) if req_body else {},
                        }
                    )
                except Exception as exc:
                    logger.debug("HackerOne capture error: %s", exc)

            page.on("response", on_response)
            try:
                # ``domcontentloaded`` lets us catch the search XHR which
                # fires after first paint; ``networkidle`` often times out
                # because of long-poll telemetry.
                await page.goto(_HACKTIVITY_URL, wait_until="domcontentloaded", timeout=30000)
                captured = await asyncio.wait_for(asyncio.shield(future), timeout=20.0)
            except asyncio.TimeoutError:
                logger.error("HackerOne: HacktivitySearchQuery not captured within timeout")
            except Exception as exc:
                logger.error("HackerOne Playwright error: %s", exc)
            finally:
                await browser.close()

        if captured is None:
            return

        collected = 0
        first = True
        offset = 0
        page_size = int(captured["req_body"].get("variables", {}).get("size", 25)) or 25
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
                            "from": offset,
                            "size": page_size,
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
                    search = data["data"]["search"]
                    nodes = search["nodes"]
                except (KeyError, TypeError):
                    logger.error("HackerOne: unexpected response shape")
                    break

                if not nodes:
                    break

                for report in _parse_edges(nodes):
                    if collected >= limit:
                        return
                    yield report
                    collected += 1

                # Offset-based pagination — advance by the number of nodes
                # we just received (server may return fewer than page_size).
                offset += len(nodes)
                if len(nodes) < page_size:
                    # Server returned partial page: end of feed for this query.
                    break
                total = search.get("total_count")
                if isinstance(total, int) and offset >= total:
                    break
