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


@pytest.mark.unit
def test_mobile_navigation_is_semantic_and_available_without_javascript() -> None:
    template = Path("src/anva/templates/product/base.html").read_text()
    script = Path("src/anva/static/anva/app.js").read_text()
    css = Path("src/anva/static/anva/app.css").read_text()

    assert '<details class="sidebar" id="primary-navigation" data-navigation open>' in template
    assert "<summary" in template
    assert "data-nav-toggle" not in template
    assert "navigation.open" in script
    assert ".sidebar:not([open])" in css
    assert "overflow-y: auto" not in css[css.index("@media (max-width: 56rem)") :]


@pytest.mark.unit
def test_product_templates_humanize_machine_identifiers_and_search_empty_state() -> None:
    templates = Path("src/anva/templates/product")
    rendered_sources = "\n".join(path.read_text() for path in sorted(templates.glob("*.html")))

    assert 'cut:"_"|title' not in rendered_sources
    assert 'cut:"_"|lower' not in rendered_sources
    assert "humanize_identifier" in rendered_sources
    explorer = (templates / "explorer.html").read_text()
    assert "No authorized source excerpts match this search." in explorer


@pytest.mark.unit
def test_compose_forwards_product_runtime_configuration() -> None:
    compose = Path("compose.yaml").read_text()
    example = Path(".env.example").read_text()

    assert "ANVA_MCP_URL: ${ANVA_MCP_URL:-http://mcp:8001/mcp}" in compose
    assert "ANVA_WEB_READ_ONLY: ${ANVA_WEB_READ_ONLY:-false}" in compose
    assert "ANVA_MCP_URL=http://mcp:8001/mcp" in example
    assert "ANVA_WEB_READ_ONLY=false" in example


@pytest.mark.unit
def test_runtime_image_installs_a_wheel_without_project_source() -> None:
    dockerfile = Path("Dockerfile").read_text()
    runtime = dockerfile[
        dockerfile.index("FROM base AS runtime") : dockerfile.index("FROM base AS test")
    ]

    assert "uv build --wheel" in dockerfile
    assert "uv pip install --no-deps" in runtime
    assert "COPY src" not in runtime
    assert "uv sync" not in runtime
