"""Enable PostgreSQL's pgvector extension for later knowledge storage."""

from __future__ import annotations

from typing import ClassVar

from django.contrib.postgres.operations import CreateExtension
from django.db import migrations


class Migration(migrations.Migration):
    """Install the extension inside the database migration lifecycle."""

    initial = True
    dependencies: ClassVar[list[tuple[str, str]]] = []
    operations: ClassVar[list[CreateExtension]] = [CreateExtension("vector")]
