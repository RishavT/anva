from __future__ import annotations

from typing import ClassVar

from django.db import migrations, models
from django.db.models import Q


class Migration(migrations.Migration):
    dependencies: ClassVar[list[tuple[str, str]]] = [("core", "0025_evaluator_reviewer_binding")]

    operations: ClassVar[list[migrations.operations.base.Operation]] = [
        migrations.AddIndex(
            model_name="assertionconflict",
            index=models.Index(
                fields=["organization", "left_assertion", "id"],
                condition=Q(status="OPEN"),
                name="core_conflict_open_left_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="assertionconflict",
            index=models.Index(
                fields=["organization", "right_assertion", "id"],
                condition=Q(status="OPEN"),
                name="core_conflict_open_right_idx",
            ),
        ),
    ]
