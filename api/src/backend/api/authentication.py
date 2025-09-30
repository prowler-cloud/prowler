from typing import Optional, Tuple
from uuid import UUID

from django.utils import timezone
from drf_simple_apikey.backends import APIKeyAuthentication as BaseAPIKeyAuth
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request
from rest_framework_simplejwt.authentication import JWTAuthentication

from api.db_utils import ProwlerApiCrypto
from api.models import TenantAPIKey, TenantAPIKeyManager


class TenantAPIKeyAuthentication(BaseAPIKeyAuth):
    model = TenantAPIKey

    def __init__(self):
        self.key_crypto = ProwlerApiCrypto()

    def authenticate(self, request: Request):
        prefixed_key = self.get_key(request)

        # Split prefix from key (format: pk_xxxxxxxx.encrypted_key)
        try:
            prefix, key = prefixed_key.split(TenantAPIKeyManager.separator, 1)
        except ValueError:
            raise AuthenticationFailed("Invalid API Key.")

        entity, _ = self._authenticate_credentials(request, key)

        # Get the API key instance to update last_used_at and retrieve tenant info
        # We need to decrypt again to get the pk (already validated by _authenticate_credentials)
        payload = self.key_crypto.decrypt(key)
        api_key_pk = payload["_pk"]

        # Convert string UUID back to UUID object for lookup
        if isinstance(api_key_pk, str):
            api_key_pk = UUID(api_key_pk)

        api_key_instance = TenantAPIKey.objects.get(id=api_key_pk)

        # Update last_used_at
        api_key_instance.last_used_at = timezone.now()
        api_key_instance.save(update_fields=["last_used_at"])

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
