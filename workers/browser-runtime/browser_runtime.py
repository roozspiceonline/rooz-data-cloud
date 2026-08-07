from __future__ import annotations

import argparse
import json
import sys

from playwright.sync_api import sync_playwright


def _self_test() -> dict[str, object]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            context = browser.new_context(
                accept_downloads=False,
                service_workers="block",
            )
            try:
                page = context.new_page()
                page.goto("about:blank", wait_until="load", timeout=5_000)
                return {
                    "schema_version": "rdc.browser-runtime-self-test/v1",
                    "browser": "chromium",
                    "page_url": page.url,
                    "downloads_enabled": False,
                    "service_workers": "blocked",
                    "remote_cdp": False,
                    "external_navigation": False,
                }
            finally:
                context.close()
        finally:
            browser.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run the isolated about:blank Chromium self-test.",
    )
    args = parser.parse_args()

    if not args.self_test:
        print(
            "Phase 1L browser runtime is not connected to live navigation.",
            file=sys.stderr,
        )
        return 64

    print(
        json.dumps(
            _self_test(),
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
