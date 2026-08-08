from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.run_schemas import CreateRunRequest


def browser_plan() -> dict[str, object]:
    return {
        "schema_version": "rdc.browser/v1",
        "start_url": "https://example.com/",
        "wait_until": "domcontentloaded",
        "actions": [
            {"id": "page", "type": "snapshot", "include_html": True}
        ],
    }


def base_payload() -> dict[str, object]:
    return {"build_id": str(uuid4()), "input": {"query": "browser"}}


def test_phase1l_run_accepts_versioned_browser_plan() -> None:
    raw = base_payload()
    raw["browser"] = browser_plan()
    payload = CreateRunRequest.model_validate(raw)
    assert payload.browser is not None
    assert payload.browser.schema_version == "rdc.browser/v1"


def test_phase1l_browser_requires_https() -> None:
    raw = base_payload()
    plan = browser_plan()
    plan["start_url"] = "http://example.com/"
    raw["browser"] = plan
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(raw)


def test_phase1l_browser_rejects_url_credentials() -> None:
    raw = base_payload()
    plan = browser_plan()
    plan["start_url"] = "https://user:pass@example.com/"
    raw["browser"] = plan
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(raw)


def test_phase1l_browser_rejects_non_snapshot_action() -> None:
    raw = base_payload()
    plan = browser_plan()
    plan["actions"] = [{"id": "click", "type": "click", "include_html": False}]
    raw["browser"] = plan
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(raw)


def test_phase1l_browser_rejects_duplicate_action_ids() -> None:
    raw = base_payload()
    plan = browser_plan()
    plan["actions"] = [
        {"id": "same", "type": "snapshot", "include_html": True},
        {"id": "same", "type": "snapshot", "include_html": False},
    ]
    raw["browser"] = plan
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(raw)


def test_phase1l_browser_and_web_fetch_are_mutually_exclusive() -> None:
    raw = base_payload()
    raw["browser"] = browser_plan()
    raw["web_fetch"] = {
        "schema_version": "rdc.web-fetch/v1",
        "requests": [
            {"id": "fetch", "method": "GET", "url": "https://example.com/"}
        ],
    }
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(raw)
