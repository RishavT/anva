from typing import ClassVar

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies: ClassVar[list[tuple[str, str]]] = [
        ("core", "0018_assertionprovenance_core_assertprov_order_idx_and_more")
    ]

    operations: ClassVar[list[migrations.operations.base.Operation]] = [
        migrations.AddIndex(
            model_name="canvasview",
            index=models.Index(
                fields=["organization", "is_archived", "name", "id"],
                name="core_canvas_view_list_idx",
            ),
        ),
    ]
