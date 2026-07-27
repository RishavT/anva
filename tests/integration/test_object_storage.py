"""Object-storage boundary integration tests."""

from __future__ import annotations

import pytest

from anva.foundation.services import check_object_storage


@pytest.mark.integration
def test_object_storage_health_endpoint() -> None:
    status = check_object_storage()

    assert status.healthy, status.detail
