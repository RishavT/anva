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
TOKEN_PEPPER = os.getenv("ANVA_TOKEN_PEPPER", SECRET_KEY)
TOKEN_ISSUER = os.getenv("ANVA_TOKEN_ISSUER", "anva-local")
TOKEN_AUDIENCE = os.getenv("ANVA_TOKEN_AUDIENCE", "anva-api")
BOOTSTRAP_SECRET = os.getenv("ANVA_BOOTSTRAP_SECRET", "anva-local-bootstrap")
if not all((TOKEN_PEPPER, TOKEN_ISSUER, TOKEN_AUDIENCE, BOOTSTRAP_SECRET)):
    raise ImproperlyConfigured("Token and bootstrap settings must not be empty")
if ENVIRONMENT == "production" and TOKEN_PEPPER == SECRET_KEY:
    raise ImproperlyConfigured("ANVA_TOKEN_PEPPER must be separate in production")
if ENVIRONMENT == "production" and BOOTSTRAP_SECRET == "anva-local-bootstrap":
    raise ImproperlyConfigured("ANVA_BOOTSTRAP_SECRET must be changed in production")

ANVA_PUBLIC_BASE_URL = os.getenv("ANVA_PUBLIC_BASE_URL", "http://localhost:8000")
if not ANVA_PUBLIC_BASE_URL.startswith(("http://", "https://")):
    raise ImproperlyConfigured("ANVA_PUBLIC_BASE_URL must be an HTTP(S) URL")
ANVA_MCP_PUBLIC_BASE_URL = os.getenv("ANVA_MCP_PUBLIC_BASE_URL", "http://localhost:8001")
if not ANVA_MCP_PUBLIC_BASE_URL.startswith(("http://", "https://")):
    raise ImproperlyConfigured("ANVA_MCP_PUBLIC_BASE_URL must be an HTTP(S) URL")
ANVA_MCP_READ_ONLY = env_bool("ANVA_MCP_READ_ONLY", default=False)
ANVA_GITHUB_WEBHOOK_SECRETS = tuple(
    value
    for value in os.getenv(
        "ANVA_GITHUB_WEBHOOK_SECRETS",
        "test-github-webhook-secret"
        if ENVIRONMENT == "test"
        else "local-only-github-webhook-secret",
    ).split(",")
    if value
)
if not ANVA_GITHUB_WEBHOOK_SECRETS:
    raise ImproperlyConfigured("ANVA_GITHUB_WEBHOOK_SECRETS must not be empty")
ANVA_GITHUB_WEBHOOK_CONFIGURED = not (
    ENVIRONMENT == "production"
    and ANVA_GITHUB_WEBHOOK_SECRETS == ("local-only-github-webhook-secret",)
)
ANVA_GITHUB_ENABLED = env_bool("ANVA_GITHUB_ENABLED", default=False)
try:
    ANVA_GITHUB_APP_ID = int(os.getenv("ANVA_GITHUB_APP_ID", "0"))
except ValueError as error:
    raise ImproperlyConfigured("ANVA_GITHUB_APP_ID must be an integer") from error
ANVA_GITHUB_APP_SLUG = os.getenv("ANVA_GITHUB_APP_SLUG", "")
ANVA_GITHUB_APP_PRIVATE_KEY_FILE = os.getenv(
    "ANVA_GITHUB_APP_PRIVATE_KEY_FILE",
    "/run/secrets/github_app_private_key",
)
if ANVA_GITHUB_ENABLED and (
    ANVA_GITHUB_APP_ID < 1
    or not ANVA_GITHUB_APP_SLUG
    or not Path(ANVA_GITHUB_APP_PRIVATE_KEY_FILE).is_absolute()
):
    raise ImproperlyConfigured("Enabled GitHub integration requires App ID, slug, and key path")

ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv("ANVA_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if host.strip()
]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.staticfiles",
    "anva.core",
    "anva.foundation",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "anva.core.middleware.ProductSecurityHeadersMiddleware",
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
DATA_UPLOAD_MAX_MEMORY_SIZE = 1_100_000

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = ENVIRONMENT == "production"
SESSION_COOKIE_AGE = 60 * 60 * 12
SESSION_SAVE_EVERY_REQUEST = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = ENVIRONMENT == "production"
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_REFERRER_POLICY = "same-origin"
ANVA_WEB_READ_ONLY = env_bool("ANVA_WEB_READ_ONLY", default=False)

OBJECT_STORAGE_ENDPOINT = os.getenv("ANVA_OBJECT_STORAGE_ENDPOINT", "http://minio:9000")
OBJECT_STORAGE_BUCKET = os.getenv("ANVA_OBJECT_STORAGE_BUCKET", "anva")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "structured": {
            "()": "anva.core.logging.StructuredJsonFormatter",
        }
    },
    "filters": {
        "redact_secrets": {
            "()": "anva.core.logging.SecretRedactionFilter",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "structured",
            "filters": ["redact_secrets"],
        }
    },
    "root": {
        "handlers": ["console"],
        "level": os.getenv("ANVA_LOG_LEVEL", "INFO").upper(),
    },
}
