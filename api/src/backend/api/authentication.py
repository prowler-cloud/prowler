from typing import Optional, Tuple

from drf_simple_apikey.backends import APIKeyAuthentication as BaseAPIKeyAuth
from rest_framework.authentication import BaseAuthentication
from rest_framework.request import Request
from rest_framework_simplejwt.authentication import JWTAuthentication

from api.models import TenantAPIKey


class TenantAPIKeyAuthentication(BaseAPIKeyAuth):
    model = TenantAPIKey

    def authenticate(self, request: Request):
        key = self.get_key(request)
        self._authenticate_credentials(request, key)

        key_crypto = self.key_crypto
        payload = key_crypto.decrypt(key)
        api_key_pk = payload["_pk"]

        api_key_instance = TenantAPIKey.objects.get(id=api_key_pk)

        return api_key_instance.entity, {"tenant_id": str(api_key_instance.tenant_id)}


class CombinedJWTOrAPIKeyAuthentication(BaseAuthentication):
    jwt_auth = JWTAuthentication()
    api_key_auth = TenantAPIKeyAuthentication()

    def authenticate(self, request: Request) -> Optional[Tuple[object, dict]]:
        auth_header = request.headers.get("Authorization", "")

        if auth_header.startswith("Bearer "):
            return self.jwt_auth.authenticate(request)

        if auth_header.startswith("Api-Key "):
            return self.api_key_auth.authenticate(request)
