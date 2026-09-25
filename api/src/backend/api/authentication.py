import logging
from datetime import timedelta
from math import isfinite
from uuid import UUID

from api.db_router import MainRouter
from api.models import TenantAPIKey, TenantAPIKeyManager
from cryptography.fernet import InvalidToken
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q
from django.utils import timezone
from drf_simple_apikey.backends import APIKeyAuthentication as BaseAPIKeyAuth
from drf_simple_apikey.crypto import get_crypto
from drf_simple_apikey.settings import package_settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request
from rest_framework_simplejwt.authentication import JWTAuthentication

logger = logging.getLogger(__name__)

# Writing on every request makes all requests of a busy key contend on one row
API_KEY_LAST_USED_AT_THROTTLE_SECONDS = 60


class OrphanedAPIKeyError(Exception):
    """Raised when an API key outlived the user that owns it.

    The revocation is written by a plain `update()` before this is raised, so it is
    already persisted by the time `authenticate` catches it and rejects the request.
    """


class TenantAPIKeyAuthentication(BaseAPIKeyAuth):
    model = TenantAPIKey

    def __init__(self):
        self.key_crypto = get_crypto()

    def _authenticate_credentials(self, request, key):
        """
        Override to use admin connection, bypassing RLS during authentication.

        Returns the validated API key row from a single read. `authenticate` builds
        the auth claims from that same row instead of looking it up again, so a key
        revoked or orphaned right after validation can't still authenticate.
        """
        try:
            payload = self.key_crypto.decrypt(key)
        except (ValueError, InvalidToken):
            raise AuthenticationFailed("Invalid API Key.")

        if not isinstance(payload, dict):
            raise AuthenticationFailed("Invalid API Key.")

        payload_pk = payload.get("_pk")
        payload_exp = payload.get("_exp")
        if (
            not isinstance(payload_pk, str)
            or isinstance(payload_exp, bool)
            or not isinstance(payload_exp, (int, float))
            or not isfinite(payload_exp)
        ):
            raise AuthenticationFailed("Invalid API Key.")

        try:
            api_key_pk = UUID(payload_pk)
        except ValueError:
            raise AuthenticationFailed("Invalid API Key.")

        if payload_exp < timezone.now().timestamp():
            raise AuthenticationFailed("API Key has already expired.")

        try:
            api_key = self.model.objects.using(MainRouter.admin_db).get(id=api_key_pk)
        except ObjectDoesNotExist:
            raise AuthenticationFailed("No entity matching this api key.")

        if api_key.revoked:
            raise AuthenticationFailed("This API Key has been revoked.")

        # `entity` is nullable and `on_delete=SET_NULL` leaves the key behind when its
        # owner is deleted, so a key can outlive its user. Reject it here: further down
        # the authentication would return `None` as the authenticated user, which blows
        # up while building the auth dict and surfaces as a 500 instead of a 401.
        # Revoke it as well, so it stops showing up as active and later attempts fail
        # the `revoked` check above like any other revoked key.
        if api_key.entity_id is None:
            self.model.objects.using(MainRouter.admin_db).filter(
                id=api_key.id, revoked=False
            ).update(revoked=True)
            logger.warning(
                "Revoked orphaned API key: prefix=%s tenant=%s",
                api_key.prefix,
                api_key.tenant_id,
            )
            raise OrphanedAPIKeyError

        client_ip = request.META.get(package_settings.IP_ADDRESS_HEADER)
        if api_key.blacklisted_ips and client_ip in api_key.blacklisted_ips:
            raise AuthenticationFailed("Access denied from blacklisted IP.")

        if api_key.whitelisted_ips and client_ip not in api_key.whitelisted_ips:
            raise AuthenticationFailed("Access restricted to specific IP addresses.")

        return api_key

    def authenticate(self, request: Request):
        prefixed_key = self.get_key(request)

        # Split prefix from key (format: pk_xxxxxxxx.encrypted_key)
        try:
            prefix, key = prefixed_key.split(TenantAPIKeyManager.separator, 1)
        except ValueError:
            raise AuthenticationFailed("Invalid API Key.")

        try:
            api_key = self._authenticate_credentials(request, key)
        except OrphanedAPIKeyError:
            raise AuthenticationFailed("No entity matching this api key.")

        # The prefix used to be checked by the second lookup
        if api_key.prefix != prefix:
            raise AuthenticationFailed("Invalid API Key.")

        self._throttled_touch_last_used_at(api_key)

        entity = api_key.entity
        return entity, {
            "tenant_id": str(api_key.tenant_id),
            "sub": str(entity.id),
            "api_key_prefix": api_key.prefix,
        }

    @staticmethod
    def _throttled_touch_last_used_at(api_key: TenantAPIKey) -> None:
        """Write `last_used_at` at most once per throttle interval, without locking the row."""
        now = timezone.now()
        stale_before = now - timedelta(seconds=API_KEY_LAST_USED_AT_THROTTLE_SECONDS)

        if api_key.last_used_at is not None and api_key.last_used_at >= stale_before:
            return

        TenantAPIKey.objects.using(MainRouter.admin_db).filter(
            id=api_key.id, revoked=False
        ).filter(
            Q(last_used_at__isnull=True) | Q(last_used_at__lt=stale_before)
        ).update(last_used_at=now)


class CombinedJWTOrAPIKeyAuthentication(BaseAuthentication):
    jwt_auth = JWTAuthentication()
    api_key_auth = TenantAPIKeyAuthentication()

    def authenticate(self, request: Request) -> tuple[object, dict] | None:
        auth_header = request.headers.get("Authorization", "")

        # Prioritize JWT authentication if both are present
        if auth_header.startswith("Bearer "):
            return self.jwt_auth.authenticate(request)

        if auth_header.startswith("Api-Key "):
            return self.api_key_auth.authenticate(request)

        # Default fallback
        return self.jwt_auth.authenticate(request)


class SSEAuthentication(CombinedJWTOrAPIKeyAuthentication):
    """JWT/API-Key auth that also accepts `?access_token=<jwt>`.

    Browser `EventSource` is the only widely available SSE client API
    and it cannot set the `Authorization` header (its constructor takes
    only a URL and `withCredentials`). To keep browser SSE clients on
    the same auth stack as the rest of the API, SSE endpoints additionally
    accept a JWT via the `?access_token=<jwt>` query parameter — the
    standard parameter name defined in RFC 6750 Section 2.3 for bearer tokens.
    """

    def authenticate(self, request: Request):
        auth_header = request.headers.get("Authorization", "")
        if auth_header:
            return super().authenticate(request)

        raw_token = request.query_params.get("access_token")
        if not raw_token:
            # No header and no query token — let the default path raise
            # the canonical AuthenticationFailed via the parent class.
            return super().authenticate(request)

        validated_token = self.jwt_auth.get_validated_token(raw_token)
        user = self.jwt_auth.get_user(validated_token)
        return user, validated_token
