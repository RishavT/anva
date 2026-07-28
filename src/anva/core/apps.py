"""Django application configuration for the core domain."""

from __future__ import annotations

from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Configure migration-backed core domain records."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "anva.core"
