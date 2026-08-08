from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.run_schemas import BrowserNavigationInput, CreateRunRequest


def valid_navigation() -> dict[str, object]:
    return {
        "schema_version": "rdc.browser/v2",
        "steps": [
            {
                "id": "open",
                "type": "goto",
                "url": "https://example.com/",
                "wait_until": "domcontentloaded",
            },
            {
                "id": "wait",
                "type": "wait_for_selector",
                "selector": "main",
                "state": "visible",
                "timeout_ms": 5000,
            },
            {
                "id": "text",
                "type": "extract_text",
                "selector": "h1",
                "max_chars": 8192,
            },
            {
                "id": "html",
                "type": "extract_html",
                "selector": "main",
                "max_bytes": 262144,
            },
            {
                "id": "shot",
                "type": "screenshot",
                "full_page": False,
            },
        ],
    }


def test_phase1m_navigation_schema_accepts_bounded_v2_intent() -> None:
    navigation = BrowserNavigationInput.model_validate(valid_navigation())
    assert navigation.schema_version == "rdc.browser/v2"
    assert navigation.steps[0].type == "goto"
    assert navigation.steps[-1].type == "screenshot"


def test_phase1m_navigation_schema_rejects_unsafe_surface() -> None:
    click = valid_navigation()
    click["steps"] = [
        {
            "id": "click",
            "type": "click",
            "selector": "button",
        }
    ]
    with pytest.raises(ValidationError):
        BrowserNavigationInput.model_validate(click)

    full_page = valid_navigation()
    full_page["steps"] = [
        {
            "id": "open",
            "type": "goto",
            "url": "https://example.com/",
            "wait_until": "load",
        },
        {
            "id": "shot",
            "type": "screenshot",
            "full_page": True,
        },
    ]
    with pytest.raises(ValidationError):
        BrowserNavigationInput.model_validate(full_page)

    bad_selector = valid_navigation()
    bad_selector["steps"] = [
        {
            "id": "open",
            "type": "goto",
            "url": "https://example.com/",
            "wait_until": "load",
        },
        {
            "id": "wait",
            "type": "wait_for_selector",
            "selector": "main\nscript",
            "state": "visible",
            "timeout_ms": 5000,
        },
    ]
    with pytest.raises(ValidationError):
        BrowserNavigationInput.model_validate(bad_selector)


def test_phase1m_run_request_allows_only_one_external_surface() -> None:
    payload = {
        "build_id": str(uuid4()),
        "browser_navigation": valid_navigation(),
        "web_fetch": {
            "schema_version": "rdc.web-fetch/v1",
            "requests": [
                {
                    "id": "fetch",
                    "method": "GET",
                    "url": "https://example.com/",
                }
            ],
        },
    }
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(payload)
