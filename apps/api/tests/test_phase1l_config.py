import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_phase1l_browser_defaults_disabled() -> None:
    settings = Settings()
    assert settings.sandbox_canary_browser_enabled is False
    assert settings.sandbox_canary_browser_max_pages == 1
    assert settings.sandbox_canary_browser_max_actions == 8


def test_phase1l_browser_requires_canary_and_web_egress() -> None:
    with pytest.raises(ValidationError):
        Settings(sandbox_canary_browser_enabled=True)


def test_phase1l_browser_limits_fail_closed() -> None:
    with pytest.raises(ValidationError):
        Settings(sandbox_canary_browser_max_pages=3)
    with pytest.raises(ValidationError):
        Settings(sandbox_canary_browser_max_actions=17)
