"""PostgreSQL and migration integration tests."""

from __future__ import annotations

import pytest
from django.db import connection

from anva.foundation.services import check_database


@pytest.mark.integration
@pytest.mark.django_db
def test_database_health_and_pgvector_extension() -> None:
    assert check_database().healthy

    with connection.cursor() as cursor:
        cursor.execute("SELECT extname FROM pg_extension WHERE extname = 'vector'")
        extension = cursor.fetchone()

    assert extension == ("vector",)
