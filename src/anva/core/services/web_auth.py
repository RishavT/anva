"""Human-only browser session resolution.

Repository bearer credentials deliberately never enter this boundary. Browser sessions
store only opaque user and organization identifiers; active membership and role state are
resolved from the database for every request.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass

from django.conf import settings
from django.http import HttpRequest

from anva.core.exceptions import AuthenticationError
from anva.core.models import Membership, Organization, User
from anva.core.services.authorization import INVALID_CREDENTIAL_MESSAGE
from anva.core.services.context import ActorContext

WEB_USER_SESSION_KEY = "anva_web_user_id"
WEB_ORGANIZATION_SESSION_KEY = "anva_web_organization_id"


@dataclass(frozen=True, slots=True)
class WebPrincipal:
    """A freshly resolved active browser principal."""

    actor: ActorContext
    organization: Organization
    user: User
    membership: Membership


def _session_uuid(request: HttpRequest, name: str) -> uuid.UUID:
    value = request.session.get(name)
    if not isinstance(value, str):
        raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
    try:
        return uuid.UUID(value)
    except ValueError:
        raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE) from None


def _source_ip_hash(request: HttpRequest) -> str:
    raw_ip = request.META.get("REMOTE_ADDR", "")
    if not isinstance(raw_ip, str) or not raw_ip:
        return ""
    return hmac.new(
        str(settings.SECRET_KEY).encode(),
        raw_ip.encode(),
        hashlib.sha256,
    ).hexdigest()


def resolve_web_principal(request: HttpRequest) -> WebPrincipal:
    """Resolve the session to an active user and membership without trusting form state."""
    user_id = _session_uuid(request, WEB_USER_SESSION_KEY)
    organization_id = _session_uuid(request, WEB_ORGANIZATION_SESSION_KEY)
    membership = (
        Membership.objects.select_related("organization", "user", "role")
        .filter(
            organization_id=organization_id,
            user_id=user_id,
            is_active=True,
            user__is_active=True,
        )
        .first()
    )
    if membership is None:
        raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
    actor = ActorContext(
        organization_id=membership.organization_id,
        actor_type="USER",
        actor_id=str(membership.user_id),
        authorization_path=f"web-session:membership:{membership.id}",
        request_id=uuid.uuid4(),
        source_ip_hash=_source_ip_hash(request),
    )
    return WebPrincipal(
        actor=actor,
        organization=membership.organization,
        user=membership.user,
        membership=membership,
    )


def establish_web_session(
    request: HttpRequest,
    *,
    user_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> None:
    """Rotate and establish a human session using server-produced identities only."""
    request.session.cycle_key()
    request.session[WEB_USER_SESSION_KEY] = str(user_id)
    request.session[WEB_ORGANIZATION_SESSION_KEY] = str(organization_id)


def clear_web_session(request: HttpRequest) -> None:
    """Invalidate all browser session state."""
    request.session.flush()
