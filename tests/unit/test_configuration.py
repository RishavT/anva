"""Unit tests for strict environment parsing."""

from __future__ import annotations

import os
import runpy
from pathlib import Path

import pytest
from django.core.exceptions import ImproperlyConfigured

import anva.config.settings as anva_settings
from anva.config.settings import bootstrap_secret, database_settings, env_bool, env_int


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
def test_env_int_uses_default_and_accepts_inclusive_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("INTEGER_UNDER_TEST", raising=False)
    assert env_int("INTEGER_UNDER_TEST", default=5, minimum=1, maximum=10) == 5

    monkeypatch.setenv("INTEGER_UNDER_TEST", "1")
    assert env_int("INTEGER_UNDER_TEST", default=5, minimum=1, maximum=10) == 1

    monkeypatch.setenv("INTEGER_UNDER_TEST", "10")
    assert env_int("INTEGER_UNDER_TEST", default=5, minimum=1, maximum=10) == 10


@pytest.mark.unit
@pytest.mark.parametrize("raw_value", ["not-an-integer", "0", "11"])
def test_env_int_rejects_malformed_and_out_of_range_values(
    raw_value: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INTEGER_UNDER_TEST", raw_value)

    with pytest.raises(ImproperlyConfigured, match="INTEGER_UNDER_TEST must be"):
        env_int("INTEGER_UNDER_TEST", default=5, minimum=1, maximum=10)


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


@pytest.mark.unit
def test_bootstrap_secret_reads_protected_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = tmp_path / "bootstrap.raw"
    secret.write_text("a" * 64)
    secret.chmod(0o400)
    monkeypatch.delenv("ANVA_BOOTSTRAP_SECRET", raising=False)
    monkeypatch.setenv("ANVA_BOOTSTRAP_SECRET_FILE", str(secret))

    assert bootstrap_secret() == "a" * 64


@pytest.mark.unit
def test_bootstrap_secret_rejects_direct_and_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = tmp_path / "bootstrap.raw"
    secret.write_text("a" * 64)
    secret.chmod(0o400)
    monkeypatch.setenv("ANVA_BOOTSTRAP_SECRET", "direct")
    monkeypatch.setenv("ANVA_BOOTSTRAP_SECRET_FILE", str(secret))

    with pytest.raises(ImproperlyConfigured, match="mutually exclusive"):
        bootstrap_secret()


@pytest.mark.unit
@pytest.mark.parametrize("attack", ["symlink", "hardlink", "mode", "newline"])
def test_bootstrap_secret_file_rejects_inode_and_content_attacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attack: str
) -> None:
    secret = tmp_path / "bootstrap.raw"
    secret.write_text("a" * 64 + ("\n" if attack == "newline" else ""))
    secret.chmod(0o400)
    selected = secret
    if attack == "symlink":
        selected = tmp_path / "linked.raw"
        selected.symlink_to(secret)
    elif attack == "hardlink":
        selected = tmp_path / "linked.raw"
        os.link(secret, selected)
    elif attack == "mode":
        secret.chmod(0o600)
    monkeypatch.delenv("ANVA_BOOTSTRAP_SECRET", raising=False)
    monkeypatch.setenv("ANVA_BOOTSTRAP_SECRET_FILE", str(selected))

    with pytest.raises(ImproperlyConfigured):
        bootstrap_secret()


def _production_environment(**overrides: str) -> dict[str, str]:
    environment = {
        "ANVA_ENV": "production",
        "ANVA_SECRET_KEY": "production-secret-key",
        "ANVA_TOKEN_PEPPER": "production-token-pepper",
        "ANVA_BOOTSTRAP_SECRET": "production-bootstrap-secret",
        "ANVA_METRICS_TOKEN": "production-metrics-token",
        "ANVA_OBJECT_STORAGE_SECRET_KEY": "production-storage-secret",
        "ANVA_RATE_LIMIT_ENABLED": "true",
    }
    environment.update(overrides)
    return environment


def _settings_path() -> str:
    path = anva_settings.__file__
    assert path is not None
    return Path(path).as_posix()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"ANVA_DEBUG": "true"},
            "ANVA_DEBUG cannot be enabled in production",
        ),
        (
            {"ANVA_RATE_LIMIT_ENABLED": "false"},
            "ANVA_RATE_LIMIT_ENABLED cannot be disabled in production",
        ),
        (
            {"ANVA_METRICS_TOKEN": ""},
            "ANVA_METRICS_TOKEN must be set in production",
        ),
        (
            {"ANVA_OBJECT_STORAGE_SECRET_KEY": "anva-local-only"},
            "ANVA_OBJECT_STORAGE_SECRET_KEY must be changed in production",
        ),
    ],
)
def test_production_settings_fail_closed(
    overrides: dict[str, str],
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as isolated:
        for name in tuple(os.environ):
            if name.startswith("ANVA_"):
                isolated.delenv(name, raising=False)
        for name, value in _production_environment(**overrides).items():
            isolated.setenv(name, value)

        with pytest.raises(ImproperlyConfigured, match=message):
            runpy.run_path(_settings_path())


@pytest.mark.unit
def test_production_settings_enable_transport_security_and_rate_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as isolated:
        for name in tuple(os.environ):
            if name.startswith("ANVA_"):
                isolated.delenv(name, raising=False)
        for name, value in _production_environment().items():
            isolated.setenv(name, value)

        loaded = runpy.run_path(_settings_path())

    assert loaded["SECURE_SSL_REDIRECT"] is True
    assert loaded["SECURE_HSTS_SECONDS"] == 31_536_000
    assert loaded["SESSION_COOKIE_SECURE"] is True
    assert loaded["CSRF_COOKIE_SECURE"] is True
    assert loaded["ANVA_RATE_LIMIT_ENABLED"] is True
    assert loaded["DEBUG"] is False
    assert loaded["SECURE_REDIRECT_EXEMPT"] == [r"^health/"]
