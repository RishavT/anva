"""Django settings sourced from an explicit, validated process environment."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote, urlparse

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parents[3]


def env_bool(name: str, *, default: bool) -> bool:
    """Parse a strict boolean environment variable."""
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ImproperlyConfigured(f"{name} must be a boolean")


def database_settings(url: str) -> dict[str, str | int]:
    """Parse the supported PostgreSQL URL into Django's database schema."""
    parsed = urlparse(url)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise ImproperlyConfigured("ANVA_DATABASE_URL must use postgresql://")
    if not all((parsed.hostname, parsed.path.removeprefix("/"), parsed.username)):
        raise ImproperlyConfigured("ANVA_DATABASE_URL must include host, database, and user")
    try:
        port = parsed.port or 5432
    except ValueError as error:
        raise ImproperlyConfigured("ANVA_DATABASE_URL contains an invalid port") from error
    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": unquote(parsed.path.removeprefix("/")),
        "USER": unquote(parsed.username or ""),
        "PASSWORD": unquote(parsed.password or ""),
        "HOST": parsed.hostname or "",
        "PORT": port,
        "CONN_MAX_AGE": 60,
    }


ENVIRONMENT = os.getenv("ANVA_ENV", "development")
DEBUG = env_bool("ANVA_DEBUG", default=ENVIRONMENT == "development")
SECRET_KEY = os.getenv("ANVA_SECRET_KEY", "local-only-change-me")
if ENVIRONMENT == "production" and SECRET_KEY == "local-only-change-me":
    raise ImproperlyConfigured("ANVA_SECRET_KEY must be changed in production")

ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv("ANVA_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if host.strip()
]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.staticfiles",
    "anva.foundation",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "anva.config.urls"
WSGI_APPLICATION = "anva.config.wsgi.application"
ASGI_APPLICATION = "anva.config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "src" / "anva" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
            ],
        },
    },
]

DATABASES = {
    "default": database_settings(
        os.getenv(
            "ANVA_DATABASE_URL",
            "postgresql://anva:anva-local-only@postgres:5432/anva",
        )
    )
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = Path("/app/staticfiles") if ENVIRONMENT == "test" else BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "src" / "anva" / "static"]
STORAGES = {
    "staticfiles": {
        "BACKEND": (
            "django.contrib.staticfiles.storage.StaticFilesStorage"
            if ENVIRONMENT == "test"
            else "whitenoise.storage.CompressedManifestStaticFilesStorage"
        ),
    }
}
WHITENOISE_USE_FINDERS = ENVIRONMENT == "test"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

OBJECT_STORAGE_ENDPOINT = os.getenv("ANVA_OBJECT_STORAGE_ENDPOINT", "http://minio:9000")
OBJECT_STORAGE_BUCKET = os.getenv("ANVA_OBJECT_STORAGE_BUCKET", "anva")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "structured": {
            "format": (
                '{"timestamp":"%(asctime)s","level":"%(levelname)s",'
                '"logger":"%(name)s","message":"%(message)s"}'
            ),
            "style": "%",
        }
    },
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "structured"}},
    "root": {
        "handlers": ["console"],
        "level": os.getenv("ANVA_LOG_LEVEL", "INFO").upper(),
    },
}
