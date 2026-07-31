"""Static guard against analyzing stale code baked into a bind-mounted test image."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


@pytest.mark.unit
def test_bind_mounted_test_services_import_workspace_source() -> None:
    compose = Path("compose.yaml").read_text(encoding="utf-8")

    for service in ("test", "browser-test", "mcp-client-test"):
        match = re.search(
            rf"^  {re.escape(service)}:\n(?P<body>(?:^(?:    |$).*\n?)*)",
            compose,
            flags=re.MULTILINE,
        )
        assert match is not None
        body = match.group("body")
        assert "- .:/workspace" in body
        assert "PYTHONPATH: /workspace/src" in body
