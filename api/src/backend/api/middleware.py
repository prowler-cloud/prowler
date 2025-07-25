import logging
import time
from typing import Optional, Dict

from config.custom_logging import BackendLogger


def extract_auth_info(request) -> Dict[str, Optional[str]]:
    """Extract authentication information from the request."""
    user_id = None
    tenant_id = None
    api_key_id = None

    if hasattr(request, "auth") and request.auth:
        user_id = request.auth.get("user_id")
        tenant_id = request.auth.get("tenant_id")
        api_key_id = request.auth.get("api_key_id")

    return {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "api_key_id": api_key_id,
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
            "source_ip": request.META.get("REMOTE_ADDR"),
            "user_agent": request.META.get("HTTP_USER_AGENT"),
            "content_length": response.get("Content-Length"),
        }

        # Add API key specific information for enhanced audit logging
        if auth_info.get("api_key_id"):
            log_data.update(
                {
                    "api_key_id": auth_info["api_key_id"],
                    "api_key_name": auth_info.get("api_key_name"),
                    "authentication_method": "api_key",
                    "is_api_key_request": True,
                }
            )
        else:
            log_data.update(
                {
                    "authentication_method": "jwt"
                    if auth_info.get("user_id")
                    else "unauthenticated",
                    "is_api_key_request": False,
                }
            )

        # Log the request with comprehensive data
        message = f"API Request: {request.method} {request.path}"
        if auth_info.get("api_key_id"):
            message += f" [API Key: {auth_info.get('api_key_name', 'unnamed')}]"

        self.logger.info(message, extra=log_data)

        return response
