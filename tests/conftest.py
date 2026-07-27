"""Shared test fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import patch

import pytest

from anva.foundation.services import DependencyStatus


@pytest.fixture
def ready_dependencies() -> Iterator[None]:
    """Make request-level tests independent of infrastructure."""
    database = DependencyStatus("database", True, "available")
    object_storage = DependencyStatus("object_storage", True, "available")
    with (
        patch("anva.foundation.services.check_database", return_value=database),
        patch("anva.foundation.services.check_object_storage", return_value=object_storage),
    ):
        yield
