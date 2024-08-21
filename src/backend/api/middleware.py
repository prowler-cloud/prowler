import logging
import time

from django.http import HttpRequest

from config.custom_logging import BackendLogger


def extract_tenant_id(request: HttpRequest) -> str | None:
    """
    Extract the tenant ID from the request headers.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        str: The tenant ID if present in the headers, otherwise None.
    """
    return request.headers.get("X-Tenant-ID")


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
        self.logger.info(
            "",
            extra={
                "method": request.method,
                "path": request.path,
                "query_params": request.GET.dict(),
                "status_code": response.status_code,
                "duration": duration,
                "tenant_id": extract_tenant_id(request),
            },
        )

        return response
