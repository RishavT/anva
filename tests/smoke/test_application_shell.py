"""Browser-visible application shell smoke tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from django.contrib.staticfiles import finders
from django.test import Client


@pytest.mark.smoke
def test_home_page_is_semantic_and_has_no_frontend_build_dependency(client: Client) -> None:
    response = client.get("/")
    content = response.content.decode()

    assert response.status_code == 200
    assert "<main" in content
    assert 'href="#main"' in content
    assert "data-health-message" in content
    assert "The connective intelligence" in content


@pytest.mark.smoke
def test_browser_javascript_is_plain_static_source() -> None:
    script = Path("src/anva/static/anva/app.js").read_text()

    assert "fetch(" in script
    assert "import " not in script
    assert "require(" not in script


@pytest.mark.smoke
def test_application_assets_are_discoverable_without_a_frontend_build() -> None:
    assert finders.find("anva/app.css") is not None
    assert finders.find("anva/app.js") is not None
