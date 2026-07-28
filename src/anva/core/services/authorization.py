"""Tenant-safe governed-record lookups for authoritative operations."""

from __future__ import annotations

import uuid

from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Model, QuerySet

from anva.core.exceptions import ResourceNotFoundError

NOT_FOUND_MESSAGE = "Governed record was not found"


def get_tenant_record[GovernedModel: Model](
    *,
    queryset: QuerySet[GovernedModel],
    record_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> GovernedModel:
    """Return a tenant-owned record without distinguishing foreign from absent IDs."""
    try:
        return queryset.get(id=record_id, organization_id=organization_id)
    except ObjectDoesNotExist:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE) from None


def get_tenant_record_for_update[GovernedModel: Model](
    *,
    queryset: QuerySet[GovernedModel],
    record_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> GovernedModel:
    """Lock and return a tenant-owned record without an existence oracle."""
    return get_tenant_record(
        queryset=queryset.select_for_update(),
        record_id=record_id,
        organization_id=organization_id,
    )
