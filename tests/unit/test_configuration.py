"""Unit tests for strict environment parsing."""

from __future__ import annotations

import pytest
from django.core.exceptions import ImproperlyConfigured

from anva.config.settings import database_settings, env_bool


@pytest.mark.unit
@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [("true", True), ("YES", True), ("0", False), ("off", False)],
)
def test_env_bool_accepts_explicit_values(
    raw_value: str,
    expected: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BOOLEAN_UNDER_TEST", raw_value)

    assert env_bool("BOOLEAN_UNDER_TEST", default=not expected) is expected


@pytest.mark.unit
def test_env_bool_uses_default_and_rejects_ambiguous_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("BOOLEAN_UNDER_TEST", raising=False)
    assert env_bool("BOOLEAN_UNDER_TEST", default=True)

    monkeypatch.setenv("BOOLEAN_UNDER_TEST", "sometimes")
    with pytest.raises(ImproperlyConfigured, match="must be a boolean"):
        env_bool("BOOLEAN_UNDER_TEST", default=True)


@pytest.mark.unit
def test_database_settings_parses_percent_encoded_credentials() -> None:
    settings = database_settings("postgresql://user:p%40ss@database:5433/anva")

    assert settings["NAME"] == "anva"
    assert settings["USER"] == "user"
    assert settings["PASSWORD"] == "p@ss"  # noqa: S105 - intentionally synthetic fixture
    assert settings["HOST"] == "database"
    assert settings["PORT"] == 5433


@pytest.mark.unit
@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///tmp/anva.db",
        "postgresql:///anva",
        "postgresql://user@/anva",
        "postgresql://user@database",
        "postgresql://user@database:notaport/anva",
    ],
)
def test_database_settings_rejects_invalid_input(url: str) -> None:
    with pytest.raises(ImproperlyConfigured):
        database_settings(url)
