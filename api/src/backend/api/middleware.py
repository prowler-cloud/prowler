import logging
import time

from config.custom_logging import BackendLogger


def extract_auth_info(request) -> dict:
    if getattr(request, "auth", None) is not None:
        tenant_id = request.auth.get("tenant_id", "N/A")
        user_id = request.auth.get("sub", "N/A")
    else:
        tenant_id, user_id = "N/A", "N/A"
    return {"tenant_id": tenant_id, "user_id": user_id}


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
                "method": request.method,
                "path": request.path,
                "query_params": request.GET.dict(),
                "status_code": response.status_code,
                "duration": duration,
            },
        )

        return response
