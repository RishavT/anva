"""Static Canvas enhancement, accessibility, and supply-chain regressions."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


@pytest.mark.unit
def test_canvas_template_keeps_a_complete_no_javascript_relationship_table() -> None:
    template = Path("src/anva/templates/product/canvas.html").read_text()

    assert "<table" in template
    assert "<caption" in template
    assert "data-canvas-viewport" in template
    assert "data-canvas-inspector" in template
    assert "data-canvas-focus-select" in template
    assert "canvas-as-of-control" in template
    assert "data-canvas-draw-relationship" in template
    assert "data-canvas-proposal-edge" in template
    assert "not page.resolved_query.layers or key in page.resolved_query.layers" in template
    assert "Revoke this share" in template
    assert "Why are these connected?" in template
    assert "{% csrf_token %}" in template


@pytest.mark.unit
def test_canvas_script_has_keyboard_minimap_and_no_browser_secret_storage() -> None:
    script = Path("src/anva/static/anva/canvas.js").read_text()

    for required in (
        "ArrowLeft",
        "setPointerCapture",
        "data-canvas-minimap",
        "textContent",
        "applyLocalFilters",
        "anva-canvas-shell-interactive",
        "anva-canvas-layout",
        "anva-canvas-gesture-frame",
        "PerformanceObserver",
        "chooseProposalEndpoint",
        "drawProposalPath",
        "requestSubmit",
        "connectedNodeIds",
        "unconnectedColumns",
        'ranker: "tight-tree"',
    ):
        assert required in script
    for forbidden in ("innerHTML", "localStorage", "sessionStorage", "Authorization", "eval("):
        assert forbidden not in script


@pytest.mark.unit
def test_canvas_css_has_accessibility_and_print_modes() -> None:
    css = Path("src/anva/static/anva/canvas.css").read_text()

    assert "prefers-reduced-motion" in css
    assert "forced-colors" in css
    assert "@media print" in css
    assert "min-height: 44px" in css
    assert "min-width: 20rem" not in css


@pytest.mark.unit
def test_vendored_dagre_bytes_and_licenses_match_reviewed_release() -> None:
    root = Path("src/anva/static/anva/vendor/dagre-2.0.0")
    expected = {
        "dagre.min.js": "e073937ba0b6918fd3bba7d50a61d525b18e9dabf6ed8b208abbc0eed11be1ee",
        "LEGAL.txt": "9148bffb1e84382a8b6668eeb2b53c6a554341d714fba129856ea5eb350d35f3",
        "LICENSE": "6a349742a6cb219d5a2fc8d0844f6d89a6efc62e20c664450d884fc7ff2d6015",
    }

    assert {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in expected
    } == expected
    script = (root / "dagre.min.js").read_text()
    assert "fetch(" not in script
    assert "XMLHttpRequest" not in script
    assert "sourceMappingURL" not in script
