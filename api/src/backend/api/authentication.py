"""
API Key Authentication for Prowler API.
"""

import logging

from rest_framework import authentication, exceptions

from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import APIKey, APIKeyUser

logger = logging.getLogger(__name__)


class APIKeyAuthentication(authentication.BaseAuthentication):
    """
    API key authentication

    Clients should authenticate by passing the API key in the "Authorization"
    HTTP header, prepended with the string "ApiKey ". For example:

        Authorization: ApiKey <generated-api-key>
    """

    keyword = "ApiKey"

    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).decode("utf-8")

        if not auth_header:
            return None

        try:
            auth_type, api_key = auth_header.split(" ", 1)
        except ValueError:
            return None

        if auth_type.lower() != self.keyword.lower():
            return None

        return self.authenticate_credentials(api_key.strip(), request)

    def authenticate_credentials(self, key, request):
        """
        Authenticate the API key with RLS support.
        """
        logger.debug(f"Authenticating API key: {key[:10]}...")

        try:
            # Use admin database to bypass RLS since we don't have tenant context yet
            # This is necessary because we need to authenticate the API key to GET the tenant context
            # Note: We need to get the manager for admin DB, not a queryset
            admin_manager = APIKey.objects.db_manager(MainRouter.admin_db)
            api_key = admin_manager.get_from_key(key)
        except APIKey.DoesNotExist:
            logger.info("No valid API key found for provided key")
            raise exceptions.AuthenticationFailed("Invalid API key.")

        logger.debug(f"Found valid API key: {api_key.id}")

        # Check if the key is active (not revoked and not expired)
        if not api_key.is_active():
            if api_key.revoked:
                raise exceptions.AuthenticationFailed("API key has been revoked.")
            elif api_key.has_expired:
                raise exceptions.AuthenticationFailed("API key has expired.")

        logger.debug("API key is valid, updating last_used_at")

        # Update last used timestamp within tenant context
        try:
            with rls_transaction(str(api_key.tenant_id)):
                api_key.update_last_used()
                logger.debug("Successfully updated last_used_at")
        except Exception as e:
            logger.warning(f"Failed to update last_used_at: {type(e).__name__}: {e}")
            # Don't fail authentication if we can't update the timestamp

        # Return APIKeyUser and auth token
        # For API Key auth, the tenant_id comes from the API key itself
        auth_info = {
            "api_key_id": str(api_key.id),
            "api_key_name": api_key.name,
            "tenant_id": str(api_key.tenant_id),
        }

        logger.debug(
            f"Returning successful authentication for tenant: {api_key.tenant_id}"
        )

        # Create APIKeyUser instance for RBAC
        api_key_user = APIKeyUser(
            api_key_id=str(api_key.id),
            api_key_name=api_key.name,
            tenant_id=str(api_key.tenant_id),
            role=api_key.role,  # Include the role for RBAC
        )

        return (api_key_user, auth_info)

    def authenticate_header(self, request):
        return self.keyword
