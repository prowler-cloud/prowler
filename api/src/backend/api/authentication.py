"""
API Key Authentication for Prowler API.
"""

import logging

from django.contrib.auth.models import AnonymousUser
from django.utils import timezone
from rest_framework import authentication, exceptions

from api.models import APIKey

logger = logging.getLogger(__name__)


class APIKeyAuthentication(authentication.BaseAuthentication):
    """
    Simple API key authentication.

    Clients should authenticate by passing the API key in the "Authorization"
    HTTP header, prepended with the string "ApiKey ". For example:

        Authorization: ApiKey pk_abcdef.1234567890abcdef...
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
        # Extract prefix for faster lookup
        try:
            prefix = APIKey.extract_prefix(key)
        except ValueError:
            raise exceptions.AuthenticationFailed("Invalid API key format.")

        logger.debug(f"Looking for API key with prefix: {prefix}")

        # Find potential API keys by prefix, then verify with password check
        # Use all_objects to bypass RLS since we don't have tenant context yet
        # This is necessary because we need to authenticate the API key to GET the tenant context
        candidate_keys = APIKey.all_objects.filter(prefix=prefix)

        logger.debug(f"Found {candidate_keys.count()} candidate keys")

        api_key = None
        for candidate in candidate_keys:
            logger.debug(f"Checking candidate key ID: {candidate.id}")
            if APIKey.verify_key(key, candidate.key_hash):
                api_key = candidate
                logger.debug(f"Key verification successful for ID: {candidate.id}")
                break
            else:
                logger.debug(f"Key verification failed for ID: {candidate.id}")

        if not api_key:
            logger.info("No valid API key found for provided key")
            raise exceptions.AuthenticationFailed("Invalid API key.")

        logger.debug(f"Found valid API key: {api_key.id}")

        # Check if the key is valid
        if not api_key.is_valid():
            if api_key.revoked_at:
                raise exceptions.AuthenticationFailed("API key has been revoked.")
            else:
                raise exceptions.AuthenticationFailed("API key has expired.")

        logger.debug("API key is valid, updating last_used_at")

        # Update last used timestamp within RLS context
        from api.db_utils import rls_transaction

        try:
            with rls_transaction(str(api_key.tenant_id)):
                api_key.last_used_at = timezone.now()
                api_key.save(update_fields=["last_used_at"])
                logger.debug("Successfully updated last_used_at")
        except Exception as e:
            logger.warning(f"Failed to update last_used_at: {type(e).__name__}: {e}")
            # Don't fail authentication if we can't update the timestamp

        # Return anonymous user and auth token
        # For API Key auth, the tenant_id comes from the API key itself
        auth_info = {
            "api_key_id": str(api_key.id),
            "api_key_name": api_key.name,
            "tenant_id": str(api_key.tenant_id),
        }

        logger.debug(
            f"Returning successful authentication for tenant: {api_key.tenant_id}"
        )
        return (AnonymousUser(), auth_info)

    def authenticate_header(self, request):
        return self.keyword
