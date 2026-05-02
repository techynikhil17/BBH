"""Probe Bugcrowd for any endpoint that returns disclosed-report CONTENT
(title + description / writeup body), not just acceptance metadata."""

import asyncio
import json
from pathlib import Path

from playwright.async_api import async_playwright

OUT = Path("/tmp/bc_probe")
OUT.mkdir(parents=True, exist_ok=True)

CANDIDATE_PAGES = [
    "https://bugcrowd.com/disclosures",
    "https://bugcrowd.com/programs",
    "https://bugcrowd.com/bugs",
    # crowdstream filter variants
    "https://bugcrowd.com/crowdstream?filter_by=disclosed",
    "https://bugcrowd.com/crowdstream?filter_by=disclosures",
]


async def probe_one(name: str, url: str) -> None:
    print(f"\n{'=' * 60}\n{name}: {url}\n{'=' * 60}")
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        page = await browser.new_page(
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        captured: list[dict] = []

        async def on_response(resp):
            try:
                ct = resp.headers.get("content-type", "")
                if "json" not in ct:
                    return
                if resp.request.resource_type not in ("xhr", "fetch", "document"):
                    return
                snippet = ""
                try:
                    body = await resp.json()
                    snippet = json.dumps(body)[:400]
                except Exception:
                    pass
                captured.append({
                    "url": resp.url,
                    "status": resp.status,
                    "snippet": snippet,
                })
            except Exception:
                pass

        page.on("response", on_response)
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            final_url = page.url
            print(f"  final URL: {final_url}")
        except Exception as exc:
            print(f"  navigation error: {exc}")
            await browser.close()
            return
        await asyncio.sleep(5)

        # Also try grabbing visible disclosure links from the rendered HTML
        try:
            links = await page.evaluate(
                "() => Array.from(document.querySelectorAll('a[href*=\"disclos\"], a[href*=\"submission\"]')).map(a => a.href).slice(0, 8)"
            )
            if links:
                print("  visible disclosure-ish links:")
                for l in links:
                    print(f"    {l}")
        except Exception:
            pass

        print(f"\n  captured {len(captured)} JSON responses")
        for entry in captured[:6]:
            print(f"    [{entry['status']}] {entry['url'][:90]}")
            if entry["snippet"]:
                print(f"      {entry['snippet'][:200]}")
        await browser.close()


async def main() -> None:
    for i, url in enumerate(CANDIDATE_PAGES):
        try:
            await probe_one(f"page_{i}", url)
        except Exception as exc:
            print(f"  failed: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
