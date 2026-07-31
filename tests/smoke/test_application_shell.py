"""Browser-visible application shell smoke tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from django.contrib.staticfiles import finders
from django.test import Client


@pytest.mark.smoke
@pytest.mark.django_db
def test_home_page_is_semantic_and_has_no_frontend_build_dependency(client: Client) -> None:
    response = client.get("/", follow=True)
    content = response.content.decode()

    assert response.status_code == 200
    assert "<main" in content
    assert 'href="#main-content"' in content
    assert "Organization bootstrap" in content
    assert "Make organizational context operational" in content
    assert 'name="csrfmiddlewaretoken"' in content


@pytest.mark.smoke
def test_browser_javascript_is_plain_static_source() -> None:
    script = Path("src/anva/static/anva/app.js").read_text()

    assert "addEventListener(" in script
    assert "import " not in script
    assert "require(" not in script


@pytest.mark.smoke
def test_application_assets_are_discoverable_without_a_frontend_build() -> None:
    assert finders.find("anva/app.css") is not None
    assert finders.find("anva/app.js") is not None
