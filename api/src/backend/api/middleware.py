import logging
import time
from typing import Optional, Dict, Any

from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
from django.utils import timezone

from config.custom_logging import BackendLogger
from api.rbac.permissions import get_role


def extract_auth_info(request) -> Dict[str, Optional[str]]:
    """Extract authentication information from the request."""
    user_id = None
    tenant_id = None
    api_key_id = None
    
    if hasattr(request, 'auth') and request.auth:
        user_id = request.auth.get('user_id')
        tenant_id = request.auth.get('tenant_id')
        api_key_id = request.auth.get('api_key_id')
    
    return {
        'user_id': user_id,
        'tenant_id': tenant_id,
        'api_key_id': api_key_id,
    }


class APILoggingMiddleware:
    """
    Middleware for comprehensive API request logging.

    This middleware logs details of API requests, including authentication information,
    request metadata, and enhanced API key activity logging for security and compliance.

    Args:
        get_response (Callable): A callable to get the response, typically the next middleware or view.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger(BackendLogger.API)

    def __call__(self, request):
        request_start_time = time.time()

        response = self.get_response(request)
        duration = time.time() - request_start_time
        auth_info = extract_auth_info(request)
        
        # Build base log data
        log_data = {
            "user_id": auth_info["user_id"],
            "tenant_id": auth_info["tenant_id"],
            "method": request.method,
            "path": request.path,
            "query_params": request.GET.dict(),
            "status_code": response.status_code,
            "duration": duration,
            "source_ip": request.META.get('REMOTE_ADDR'),
            "user_agent": request.META.get('HTTP_USER_AGENT'),
            "content_length": response.get('Content-Length'),
        }
        
        # Add API key specific information for enhanced audit logging
        if auth_info.get("api_key_id"):
            log_data.update({
                "api_key_id": auth_info["api_key_id"],
                "api_key_name": auth_info.get("api_key_name"),
                "authentication_method": "api_key",
                "is_api_key_request": True,
            })
        else:
            log_data.update({
                "authentication_method": "jwt" if auth_info.get("user_id") else "unauthenticated",
                "is_api_key_request": False,
            })
        
        # Log the request with comprehensive data
        message = f"API Request: {request.method} {request.path}"
        if auth_info.get("api_key_id"):
            message += f" [API Key: {auth_info.get('api_key_name', 'unnamed')}]"
        
        self.logger.info(message, extra=log_data)
        
        # For API key requests, also save to the database for persistent audit logging
        if auth_info.get("api_key_id"):
            self._save_api_key_activity(request, response, auth_info, duration)

        return response
    
    def _save_api_key_activity(self, request, response, auth_info, duration):
        """
        Save API key activity to the database for persistent audit logging.
        
        This provides a structured audit trail that can be queried for:
        - Security incident investigation
        - Compliance reporting
        - Usage pattern analysis
        - Compromised key detection
        """
        try:
            from api.models import APIKeyActivity, APIKey
            
            # Get the API key object
            try:
                api_key = APIKey.objects.get(id=auth_info["api_key_id"])
            except APIKey.DoesNotExist:
                # Log error but don't fail the request
                self.logger.warning(
                    f"API Key not found for activity logging: {auth_info['api_key_id']}"
                )
                return
            
            # Extract response size if available
            response_size = None
            if hasattr(response, 'get') and response.get('Content-Length'):
                try:
                    response_size = int(response['Content-Length'])
                except (ValueError, TypeError):
                    pass
            
            # Convert duration to milliseconds
            duration_ms = int(duration * 1000) if duration is not None else None
            
            # Create the activity record
            APIKeyActivity.objects.create(
                api_key=api_key,
                user=api_key.created_by,
                tenant_id=api_key.tenant_id,
                method=request.method,
                endpoint=request.path,
                source_ip=request.META.get('REMOTE_ADDR', ''),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                status_code=response.status_code,
                response_size=response_size,
                duration_ms=duration_ms,
                query_params=request.GET.dict(),
                is_rate_limited=response.status_code == 429,
            )
            
        except Exception as e:
            # Log the error but don't fail the request
            self.logger.error(
                f"Failed to save API key activity: {e}",
                extra={
                    "api_key_id": auth_info.get("api_key_id"),
                    "error": str(e),
                    "path": request.path,
                    "method": request.method,
                }
            )


class APIKeyRateLimitMiddleware:
    """
    Rate limiting middleware for API key authentication.
    
    This middleware enforces rate limits on API key usage to prevent abuse,
    accidental loops, and protect against credential leaks. It tracks usage
    per minute, hour, and day with separate configurable limits.
    
    Rate limits are bypassed for users with unlimited visibility roles.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger(BackendLogger.API)
        
        # Rate limit settings
        self.enabled = getattr(settings, 'API_RATE_LIMIT_ENABLED', True)
        self.requests_per_minute = getattr(settings, 'API_RATE_LIMIT_REQUESTS_PER_MINUTE', 120)
        
        # Cache key prefixes
        self.cache_prefix = "api_rate_limit"

    def __call__(self, request):
        # Skip if rate limiting is disabled
        if not self.enabled:
            return self.get_response(request)
        
        # Only apply rate limiting to API key authentication
        auth_info = extract_auth_info(request)
        api_key_id = auth_info.get('api_key_id')
        
        if not api_key_id:
            # Not using API key authentication, skip rate limiting
            return self.get_response(request)
        
        # Check if user has unlimited visibility (admin bypass)
        if self._should_bypass_rate_limit(request):
            return self.get_response(request)
        
        # Check rate limits
        rate_limit_response = self._check_rate_limits(api_key_id, request)
        if rate_limit_response:
            return rate_limit_response
        
        # Increment counters after successful request
        response = self.get_response(request)
        
        # Only increment counters for successful requests (2xx status codes)
        if 200 <= response.status_code < 300:
            self._increment_counters(api_key_id)
        
        return response

    def _should_bypass_rate_limit(self, request) -> bool:
        """
        Check if the request should bypass rate limiting.
        Users with unlimited visibility roles bypass rate limits.
        """
        try:
            if hasattr(request, 'user') and request.user and request.user.is_authenticated:
                user_role = get_role(request.user)
                if user_role and user_role.unlimited_visibility:
                    return True
        except Exception as e:
            # Log the error but don't fail the request
            self.logger.warning(
                "Error checking user role for rate limit bypass",
                extra={"error": str(e), "user_id": getattr(request.user, 'id', None)}
            )
        
        return False

    def _check_rate_limits(self, api_key_id: str, request) -> Optional[JsonResponse]:
        """
        Check if the API key has exceeded any rate limits.
        Returns a rate limit response if exceeded, None otherwise.
        """
        now = timezone.now()
        
        # Define time windows
        windows = [
            ('minute', 60, self.requests_per_minute),
        ]
        
        for window_name, window_seconds, limit in windows:
            if limit <= 0:  # Skip if limit is disabled (0 or negative)
                continue
                
            cache_key = self._get_cache_key(api_key_id, window_name, now, window_seconds)
            current_count = cache.get(cache_key, 0)
            
            if current_count >= limit:
                # Rate limit exceeded
                self.logger.warning(
                    f"API key rate limit exceeded: {window_name}",
                    extra={
                        "api_key_id": api_key_id,
                        "window": window_name,
                        "limit": limit,
                        "current_count": current_count,
                        "path": request.path,
                        "method": request.method,
                        "ip": request.META.get('REMOTE_ADDR'),
                    }
                )
                
                return self._create_rate_limit_response(window_name, limit, window_seconds)
        
        return None

    def _increment_counters(self, api_key_id: str):
        """
        Increment the rate limit counters for all time windows.
        """
        now = timezone.now()
        
        windows = [
            ('minute', 60),
            ('hour', 3600),
            ('day', 86400),
        ]
        
        for window_name, window_seconds in windows:
            cache_key = self._get_cache_key(api_key_id, window_name, now, window_seconds)
            
            try:
                # Try to increment, if key doesn't exist, set to 1
                current_count = cache.get(cache_key, 0)
                cache.set(cache_key, current_count + 1, timeout=window_seconds)
            except Exception as e:
                # Log cache error but don't fail the request
                self.logger.error(
                    f"Failed to increment rate limit counter for {window_name}",
                    extra={
                        "api_key_id": api_key_id,
                        "cache_key": cache_key,
                        "error": str(e)
                    }
                )

    def _get_cache_key(self, api_key_id: str, window: str, now: timezone.datetime, window_seconds: int) -> str:
        """
        Generate a cache key for the given API key and time window.
        The key includes a time bucket to ensure proper window boundaries.
        """
        # Calculate the time bucket based on the window
        timestamp = int(now.timestamp())
        time_bucket = timestamp // window_seconds
        
        return f"{self.cache_prefix}:{api_key_id}:{window}:{time_bucket}"

    def _create_rate_limit_response(self, window: str, limit: int, window_seconds: int) -> JsonResponse:
        """
        Create a JSON:API compliant rate limit error response.
        """
        # Calculate retry after header
        now = timezone.now()
        timestamp = int(now.timestamp())
        time_bucket = timestamp // window_seconds
        next_window_start = (time_bucket + 1) * window_seconds
        retry_after = next_window_start - timestamp
        
        error_data = {
            "errors": [
                {
                    "status": "429",
                    "code": "rate_limit_exceeded",
                    "title": "Rate Limit Exceeded",
                    "detail": f"API key has exceeded the rate limit of {limit} requests per {window}. Please try again later.",
                    "meta": {
                        "limit": limit,
                        "window": window,
                        "retry_after": retry_after,
                    }
                }
            ]
        }
        
        response = JsonResponse(error_data, status=429)
        response['Retry-After'] = str(retry_after)
        response['X-RateLimit-Limit'] = str(limit)
        response['X-RateLimit-Window'] = window
        response['X-RateLimit-Retry-After'] = str(retry_after)
        
        return response
