"""Django application configuration."""

from __future__ import annotations

from django.apps import AppConfig


class FoundationConfig(AppConfig):
    """Configuration for the dependency-free foundation domain."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "anva.foundation"
