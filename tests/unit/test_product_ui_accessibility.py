"""Static safety and accessibility regressions for the browser-native UI."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.mark.unit
def test_product_css_has_visible_focus_reduced_motion_and_responsive_rules() -> None:
    css = Path("src/anva/static/anva/app.css").read_text()

    assert ":focus-visible" in css
    assert "prefers-reduced-motion" in css
    assert "@media (max-width:" in css
    assert "forced-colors" in css


@pytest.mark.unit
def test_product_javascript_is_progressive_and_does_not_embed_credentials() -> None:
    script = Path("src/anva/static/anva/app.js").read_text()

    assert "document.documentElement.classList" not in script
    assert "localStorage" not in script
    assert "access_token" not in script
    assert "Authorization" not in script
