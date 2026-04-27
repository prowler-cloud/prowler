import logging
import time

from config.custom_logging import BackendLogger


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


class SAMLACSURLMiddleware:
    """
    Middleware to override the host used for SAML ACS URL generation.

    When Prowler runs behind a reverse proxy or load balancer, Django's
    request.build_absolute_uri() uses the internal container hostname
    (e.g., prowler-api:8080) instead of the external domain. This causes
    SAML ACS URLs to be incorrect, breaking SSO authentication.

    Set SAML_ACS_BASE_URL in your environment (e.g., https://prowler.example.com)
    to override the host for SAML-related endpoints.

    Fixes: https://github.com/prowler-cloud/prowler/issues/10533
    """

    SAML_PATH_PREFIX = "/accounts/saml/"

    def __init__(self, get_response):
        self.get_response = get_response
        self.saml_acs_base_url = None

        from config.env import env

        url = env("SAML_ACS_BASE_URL", default="")
        if url:
            # Parse the URL to extract scheme, host, and port
            from urllib.parse import urlparse

            parsed = urlparse(url.rstrip("/"))
            if parsed.scheme and parsed.hostname:
                self.saml_acs_base_url = parsed
                logging.getLogger("prowler").info(
                    f"SAML ACS URL override active: {url}"
                )

    def __call__(self, request):
        if (
            self.saml_acs_base_url
            and self.SAML_PATH_PREFIX in request.path
        ):
            parsed = self.saml_acs_base_url

            # Override the host so build_absolute_uri() uses the external URL
            host = parsed.hostname
            if parsed.port and parsed.port not in (80, 443):
                host = f"{host}:{parsed.port}"

            request.META["HTTP_HOST"] = host
            request.META["SERVER_NAME"] = parsed.hostname
            request.META["SERVER_PORT"] = str(parsed.port or (443 if parsed.scheme == "https" else 80))

            # Ensure the scheme is correct
            if parsed.scheme == "https":
                request.META["HTTP_X_FORWARDED_PROTO"] = "https"
                request.META["wsgi.url_scheme"] = "https"

        return self.get_response(request)
