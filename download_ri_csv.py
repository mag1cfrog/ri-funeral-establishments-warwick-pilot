import asyncio, os, pathlib
from typing import Sequence, Optional, Union
from playwright.async_api import async_playwright, Page, Frame

RI_URL = "https://health.ri.gov/licensing/licensee-lists"

PROFESSION_SELECT = '#jx-profession'
LICENSE_SELECT = '#jx-license'
DOWNLOAD_BUTTON = '#downloadbutton'

Scope = Union[Page, Frame]

async def _has_all(scope: Scope, selectors: Sequence[str]) -> bool:
    counts = await asyncio.gather(*(scope.locator(sel).count() for sel in selectors))
    return all(c> 0 for c in counts)

async def find_common_scope(page: Page, selectors: Sequence[str]) -> Optional[Frame|Page]:
    # 1) try main page
    if await _has_all(page, selectors):
        return page
    # 2) try each frame
    for f in page.frames:
        if await _has_all(f, selectors):
            return f
    return None

async def download_csv(out_path: str) -> str:
    out = pathlib.Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context(
            accept_downloads=True,
            locale="en-US",
            user_agent=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"),
        )
        page = await ctx.new_page()
        await page.goto(RI_URL, wait_until="networkidle")

        # 1) find ONE document (page or frame) that contains all 3 controls
        scope = await find_common_scope(page, [PROFESSION_SELECT, LICENSE_SELECT, DOWNLOAD_BUTTON])
        if not scope:
            # tiny grace + retry (widgets can lazy-load)
            await page.wait_for_timeout(1500)
            scope = await find_common_scope(page, [PROFESSION_SELECT, LICENSE_SELECT, DOWNLOAD_BUTTON])
            if not scope:
                raise RuntimeError("Could not find a single document (page/frame) with all 3 controls")
            
        
        # ensure the profession select is visible & enabled
        await scope.locator(PROFESSION_SELECT).wait_for(state="visible", timeout=60000)

        # select profession
        await scope.locator(PROFESSION_SELECT).select_option(label="Embalming/Funeral Directing")

        # wait for license option to appear
        license_select = scope.locator(LICENSE_SELECT)
        await license_select.wait_for(state="visible", timeout=60000)

        # wait for the exact option to be present **inside** the license select (existence, not visibility)
        target_opt = scope.locator(f"{LICENSE_SELECT} >> option[value='Funeral Establishment']")
        await target_opt.wait_for(state="attached", timeout=60000)

        # select by VALUE
        await license_select.select_option(label="Funeral Establishment")

        # click Search Active Licensees
        search_btn = scope.locator("#countbutton")
        await search_btn.wait_for(state="visible", timeout=30000)
        await search_btn.click()

        # wait for the download button to be visible
        dl_btn = scope.locator(DOWNLOAD_BUTTON)
        await dl_btn.wait_for(state="visible", timeout=120000)
        
        # Trigger download
        async with page.expect_download() as dl_info:
            await dl_btn.click()
        download = await dl_info.value

        out_posix = out.as_posix()
        await download.save_as(out_posix)

        await ctx.close()
        await browser.close()
    return out_posix

if __name__ == "__main__":
    asyncio.run(download_csv("data/raw/ri_ef_funeral_establishments.csv"))