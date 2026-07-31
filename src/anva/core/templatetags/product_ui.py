"""Presentation-only filters for stable machine identifiers."""

from __future__ import annotations

from django import template

register = template.Library()


@register.filter
def humanize_identifier(value: object) -> str:
    """Render an enum or relationship identifier as readable sentence case."""
    normalized = " ".join(str(value or "").replace("_", " ").replace("-", " ").split())
    return normalized.lower().capitalize()
