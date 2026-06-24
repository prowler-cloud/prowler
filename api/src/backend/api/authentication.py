from typing import Optional, Tuple
from math import isfinite
from uuid import UUID

from cryptography.fernet import InvalidToken
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from drf_simple_apikey.backends import APIKeyAuthentication as BaseAPIKeyAuth
from drf_simple_apikey.crypto import get_crypto
from drf_simple_apikey.settings import package_settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request
from rest_framework_simplejwt.authentication import JWTAuthentication

from api.db_router import MainRouter
from api.models import TenantAPIKey, TenantAPIKeyManager


class TenantAPIKeyAuthentication(BaseAPIKeyAuth):
    model = TenantAPIKey

    def __init__(self):
        self.key_crypto = get_crypto()

    def _authenticate_credentials(self, request, key):
        """
        Override to use admin connection, bypassing RLS during authentication.
        """
        try:
            payload = self.key_crypto.decrypt(key)
        except ValueError:
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

        client_ip = request.META.get(package_settings.IP_ADDRESS_HEADER)
        if api_key.blacklisted_ips and client_ip in api_key.blacklisted_ips:
            raise AuthenticationFailed("Access denied from blacklisted IP.")

        if api_key.whitelisted_ips and client_ip not in api_key.whitelisted_ips:
            raise AuthenticationFailed("Access restricted to specific IP addresses.")

        return api_key.entity, key

    def authenticate(self, request: Request):
        prefixed_key = self.get_key(request)

        # Split prefix from key (format: pk_xxxxxxxx.encrypted_key)
        try:
            prefix, key = prefixed_key.split(TenantAPIKeyManager.separator, 1)
        except ValueError:
            raise AuthenticationFailed("Invalid API Key.")

        try:
            entity, _ = self._authenticate_credentials(request, key)
        except InvalidToken:
            raise AuthenticationFailed("Invalid API Key.")

        # Get the API key instance to update last_used_at and retrieve tenant info
        # We need to decrypt again to get the pk (already validated by _authenticate_credentials)
        payload = self.key_crypto.decrypt(key)
        api_key_pk = payload["_pk"]

        # Convert string UUID back to UUID object for lookup
        if isinstance(api_key_pk, str):
            api_key_pk = UUID(api_key_pk)

        try:
            api_key_instance = TenantAPIKey.objects.using(MainRouter.admin_db).get(
                id=api_key_pk, prefix=prefix
            )
        except TenantAPIKey.DoesNotExist:
            raise AuthenticationFailed("Invalid API Key.")

        # Update last_used_at
        api_key_instance.last_used_at = timezone.now()
        api_key_instance.save(update_fields=["last_used_at"], using=MainRouter.admin_db)

        return entity, {
            "tenant_id": str(api_key_instance.tenant_id),
            "sub": str(api_key_instance.entity.id),
            "api_key_prefix": prefix,
        }


class CombinedJWTOrAPIKeyAuthentication(BaseAuthentication):
    jwt_auth = JWTAuthentication()
    api_key_auth = TenantAPIKeyAuthentication()

    def authenticate(self, request: Request) -> Optional[Tuple[object, dict]]:
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
