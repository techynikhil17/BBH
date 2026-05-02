"""Diagnostic: log all XHRs the hacktivity / crowdstream pages fire.

Run once when the collector returns 0 reports — gives us the actual URL
patterns and GraphQL operation names so we can fix the collectors.
Discardable: not part of the production pipeline.
"""

import asyncio
import json
from playwright.async_api import async_playwright

TARGETS = [
    ("hackerone", "https://hackerone.com/hacktivity?querystring=disclosed"),
    ("bugcrowd", "https://bugcrowd.com/crowdstream"),
]


async def diag(name: str, url: str) -> None:
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
                # Only XHR / fetch responses
                if resp.request.resource_type not in ("xhr", "fetch"):
                    return
                body_preview = ""
                try:
                    body = await resp.json()
                    body_preview = json.dumps(body)[:300]
                except Exception:
                    pass
                req_body_preview = ""
                try:
                    pd = resp.request.post_data
                    if pd:
                        req_body_preview = pd[:300]
                except Exception:
                    pass
                captured.append({
                    "url": resp.url,
                    "status": resp.status,
                    "method": resp.request.method,
                    "request_body": req_body_preview,
                    "response_body": body_preview,
                })
            except Exception as exc:
                pass

        page.on("response", on_response)
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
        except Exception as exc:
            print(f"navigation error (probably timeout): {exc}")
        await asyncio.sleep(3)  # let trailing XHRs flush

        # Print summary
        print(f"\nTotal JSON XHR responses captured: {len(captured)}")
        for entry in captured:
            print(f"\n  [{entry['method']} {entry['status']}] {entry['url']}")
            if entry["request_body"]:
                print(f"    REQ:  {entry['request_body'][:200]}")
            if entry["response_body"]:
                print(f"    RESP: {entry['response_body'][:200]}")
        await browser.close()


async def main() -> None:
    for name, url in TARGETS:
        try:
            await diag(name, url)
        except Exception as exc:
            print(f"{name}: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
