from typing import Optional, Tuple
from uuid import UUID

from cryptography.fernet import InvalidToken
from django.utils import timezone
from drf_simple_apikey.backends import APIKeyAuthentication as BaseAPIKeyAuth
from drf_simple_apikey.crypto import get_crypto
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
        Delegates to parent after temporarily routing model queries to admin DB.
        """
        # Temporarily point the model's manager to admin database
        original_objects = self.model.objects
        self.model.objects = self.model.objects.using(MainRouter.admin_db)

        try:
            # Call parent method which will now use admin database
            return super()._authenticate_credentials(request, key)
        finally:
            # Restore original manager
            self.model.objects = original_objects

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
