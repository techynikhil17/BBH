"""Capture full JSON of HacktivitySearchQuery and crowdstream.json so the
collectors can be updated to the current shapes."""

import asyncio
import json
from pathlib import Path

from playwright.async_api import async_playwright

OUT = Path("/tmp/h1bc_diag")
OUT.mkdir(parents=True, exist_ok=True)


async def dump(name: str, url: str, match) -> None:
    print(f"=== {name} ===")
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
            if not match(resp):
                return
            try:
                body = await resp.json()
            except Exception:
                return
            req_body = ""
            try:
                if resp.request.post_data:
                    req_body = resp.request.post_data
            except Exception:
                pass
            captured.append({
                "url": resp.url,
                "method": resp.request.method,
                "request_body": req_body,
                "response_body": body,
            })

        page.on("response", on_response)
        try:
            # `domcontentloaded` is permissive — captures late XHRs better than networkidle
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        except Exception as exc:
            print(f"  navigation error: {exc}")
        await asyncio.sleep(8)  # let lazy XHRs finish
        out_path = OUT / f"{name}.json"
        out_path.write_text(json.dumps(captured, indent=2)[:200000], encoding="utf-8")
        print(f"  wrote {len(captured)} matches to {out_path}")
        await browser.close()


async def main() -> None:
    # HackerOne — try with longer wait and looser navigation gate
    await dump(
        "hackerone",
        "https://hackerone.com/hacktivity?querystring=disclosed",
        match=lambda r: "/graphql" in r.url and "HacktivitySearchQuery" in (r.request.post_data or ""),
    )
    # Bugcrowd disclosures page — full public writeups (vs crowdstream's metadata)
    await dump(
        "bugcrowd_disclosures",
        "https://bugcrowd.com/disclosures",
        match=lambda r: "/disclosures" in r.url and "json" in r.headers.get("content-type", ""),
    )


if __name__ == "__main__":
    asyncio.run(main())
