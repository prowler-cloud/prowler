import logging
import time

from django.db import close_old_connections

from config.custom_logging import BackendLogger


class CloseDBConnectionsMiddleware:
    """Release request-scoped DB connections at the request boundary.

    Under the native ASGI worker, sync views run on a thread-sensitive
    executor thread; the connections they open live in that thread's context.
    Django's request_finished -> close_old_connections fires in a different
    context and never frees them, so they pile up idle until Postgres runs out
    of slots. Closing here, on the same thread-sensitive context as the view,
    releases them. close_old_connections respects CONN_MAX_AGE, so it keeps
    working if persistent connections are enabled later.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            return self.get_response(request)
        finally:
            close_old_connections()


def extract_auth_info(request) -> dict:
    if getattr(request, "auth", None) is not None:
        tenant_id = request.auth.get("tenant_id", "N/A")
        user_id = request.auth.get("sub", "N/A")
        api_key_prefix = request.auth.get("api_key_prefix", "N/A")
    else:
        tenant_id, user_id, api_key_prefix = "N/A", "N/A", "N/A"
    return {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "api_key_prefix": api_key_prefix,
    }


class APILoggingMiddleware:
    """
    Middleware for logging API requests.

    This middleware logs details of API requests, including the typical request metadata among other useful information.

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
        self.logger.info(
            "",
            extra={
                "user_id": auth_info["user_id"],
                "tenant_id": auth_info["tenant_id"],
                "api_key_prefix": auth_info["api_key_prefix"],
                "method": request.method,
                "path": request.path,
                "query_params": request.GET.dict(),
                "status_code": response.status_code,
                "duration": duration,
            },
        )

        return response
