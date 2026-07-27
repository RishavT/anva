"""Shared process bootstrap kept separate from domain operations."""

from __future__ import annotations

import os


def configure_django() -> None:
    """Configure Django exactly once for non-web entrypoints."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "anva.config.settings")
    import django

    django.setup()
