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
    keyword = 'ApiKey'
    
    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).decode('utf-8')
        
        if not auth_header:
            return None
            
        try:
            auth_type, api_key = auth_header.split(' ', 1)
        except ValueError:
            return None
            
        if auth_type.lower() != self.keyword.lower():
            return None
            
        return self.authenticate_credentials(api_key, request)
    
    def authenticate_credentials(self, key, request):
        # Hash the provided key
        key_hash = APIKey.hash_key(key)
        
        # Extract prefix for faster lookup
        try:
            prefix = key.split('.')[0]
        except (IndexError, AttributeError):
            raise exceptions.AuthenticationFailed('Invalid API key format.')
        
        # Try to find the API key
        try:
            api_key = APIKey.objects.select_related('user').get(
                prefix=prefix,
                key_hash=key_hash
            )
        except APIKey.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid API key.')
        
        # Check if the key is valid
        if not api_key.is_valid():
            if api_key.revoked_at:
                raise exceptions.AuthenticationFailed('API key has been revoked.')
            else:
                raise exceptions.AuthenticationFailed('API key has expired.')
        
        # Check if the user is active
        if not api_key.user.is_active:
            raise exceptions.AuthenticationFailed('User inactive or deleted.')
        
        # Update last used timestamp and IP
        api_key.last_used_at = timezone.now()
        api_key.last_used_ip = request.META.get('REMOTE_ADDR')
        api_key.save(update_fields=['last_used_at', 'last_used_ip'])
        
        # Return user and auth token (similar to JWT auth)
        # For API Key auth, we need to include tenant_id for RLS
        # Get the user's first membership to determine tenant_id
        membership = api_key.user.memberships.first()
        if not membership:
            raise exceptions.AuthenticationFailed('User has no tenant memberships.')
        
        auth_info = {
            'api_key_id': str(api_key.id),
            'api_key_name': api_key.name,
            'user_id': str(api_key.user.id),
            'tenant_id': str(membership.tenant_id),
        }
        
        return (api_key.user, auth_info)
    
    def authenticate_header(self, request):
        return self.keyword 