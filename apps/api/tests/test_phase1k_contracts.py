from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.run_schemas import CreateRunRequest


def make_request(web_fetch: object | None = None) -> dict[str, object]:
    value: dict[str, object] = {
        "build_id": str(uuid4()),
        "input": {"query": "spices"},
    }
    if web_fetch is not None:
        value["web_fetch"] = web_fetch
    return value


def valid_web_fetch() -> dict[str, object]:
    return {
        "schema_version": "rdc.web-fetch/v1",
        "requests": [
            {
                "id": "homepage",
                "method": "GET",
                "url": "https://example.com/",
            }
        ],
    }


def test_phase1k_run_accepts_versioned_web_fetch() -> None:
    payload = CreateRunRequest.model_validate(make_request(valid_web_fetch()))
    assert payload.web_fetch is not None
    assert payload.web_fetch.schema_version == "rdc.web-fetch/v1"
    assert payload.web_fetch.requests[0].method == "GET"


def test_phase1k_run_without_web_fetch_remains_valid() -> None:
    payload = CreateRunRequest.model_validate(make_request())
    assert payload.web_fetch is None


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("POST", "https://example.com/"),
        ("GET", "http://example.com/"),
        ("GET", "https://user:pass@example.com/"),
    ],
)
def test_phase1k_rejects_unsafe_web_fetch(
    method: str,
    url: str,
) -> None:
    value = valid_web_fetch()
    value["requests"] = [
        {
            "id": "unsafe",
            "method": method,
            "url": url,
        }
    ]
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(make_request(value))


def test_phase1k_rejects_duplicate_request_ids() -> None:
    value = valid_web_fetch()
    value["requests"] = [
        {
            "id": "duplicate",
            "method": "GET",
            "url": "https://example.com/one",
        },
        {
            "id": "duplicate",
            "method": "HEAD",
            "url": "https://example.com/two",
        },
    ]
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(make_request(value))


def test_phase1k_rejects_agent_authored_headers() -> None:
    value = valid_web_fetch()
    value["requests"] = [
        {
            "id": "headers",
            "method": "GET",
            "url": "https://example.com/",
            "headers": {"Authorization": "Bearer forbidden"},
        }
    ]
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(make_request(value))


def test_phase1k_rejects_oversized_web_fetch_envelope() -> None:
    requests = [
        {
            "id": f"request-{index}",
            "method": "GET",
            "url": "https://example.com/" + ("a" * 8000) + str(index),
        }
        for index in range(9)
    ]
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(
            make_request(
                {
                    "schema_version": "rdc.web-fetch/v1",
                    "requests": requests,
                }
            )
        )
