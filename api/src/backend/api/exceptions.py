from django.core.exceptions import ValidationError as django_validation_error
from rest_framework import status
from rest_framework.exceptions import (
    APIException,
    AuthenticationFailed,
    NotAuthenticated,
)
from rest_framework_json_api.exceptions import exception_handler
from rest_framework_json_api.serializers import ValidationError
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


class ModelValidationError(ValidationError):
    def __init__(
        self,
        detail: str | None = None,
        code: str | None = None,
        pointer: str | None = None,
        status_code: int = 400,
    ):
        super().__init__(
            detail=[
                {
                    "detail": detail,
                    "status": str(status_code),
                    "source": {"pointer": pointer},
                    "code": code,
                }
            ]
        )


class InvitationTokenExpiredException(APIException):
    status_code = status.HTTP_410_GONE
    default_detail = "The invitation token has expired and is no longer valid."
    default_code = "token_expired"


# Task Management Exceptions (non-HTTP)
class TaskManagementError(Exception):
    """Base exception for task management errors."""

    def __init__(self, task=None):
        self.task = task
        super().__init__()


class TaskFailedException(TaskManagementError):
    """Raised when a task has failed."""


class TaskNotFoundException(TaskManagementError):
    """Raised when a task is not found."""


class TaskInProgressException(TaskManagementError):
    """Raised when a task is running but there's no related Task object to return."""

    def __init__(self, task_result=None):
        self.task_result = task_result
        super().__init__()


# Provider connection errors
class ProviderConnectionError(Exception):
    """Base exception for provider connection errors."""


class ProviderDeletedException(Exception):
    """Raised when a provider has been deleted during scan/task execution."""


def custom_exception_handler(exc, context):
    if isinstance(exc, django_validation_error):
        if hasattr(exc, "error_dict"):
            exc = ValidationError(exc.message_dict)
        else:
            exc = ValidationError(detail=exc.messages[0], code=exc.code)
    # Force 401 status for AuthenticationFailed exceptions regardless of the authentication backend
    elif isinstance(exc, (AuthenticationFailed, NotAuthenticated, TokenError)):
        exc.status_code = status.HTTP_401_UNAUTHORIZED
        if isinstance(exc, (TokenError, InvalidToken)):
            if (
                hasattr(exc, "detail")
                and isinstance(exc.detail, dict)
                and "messages" in exc.detail
            ):
                exc.detail["messages"] = [
                    message_item["message"] for message_item in exc.detail["messages"]
                ]
    return exception_handler(exc, context)


class ConflictException(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "A conflict occurred. The resource already exists."
    default_code = "conflict"

    def __init__(self, detail=None, code=None, pointer=None):
        error_detail = {
            "detail": detail or self.default_detail,
            "status": self.status_code,
            "code": self.default_code,
        }

        if pointer:
            error_detail["source"] = {"pointer": pointer}

        super().__init__(detail=[error_detail])


# Upstream Provider Errors (for external API calls like CloudTrail)
# These indicate issues with the provider, not with the user's API authentication


class UpstreamAuthenticationError(APIException):
    """Provider credentials are invalid or expired (502 Bad Gateway).

    Used when AWS/Azure/GCP credentials fail to authenticate with the upstream
    provider. This is NOT the user's API authentication failing.
    """

    status_code = status.HTTP_502_BAD_GATEWAY
    default_detail = (
        "Provider credentials are invalid or expired. Please reconnect the provider."
    )
    default_code = "upstream_auth_failed"

    def __init__(self, detail=None):
        super().__init__(
            detail=[
                {
                    "detail": detail or self.default_detail,
                    "status": str(self.status_code),
                    "code": self.default_code,
                }
            ]
        )


class UpstreamAccessDeniedError(APIException):
    """Provider credentials lack required permissions (502 Bad Gateway).

    Used when credentials are valid but don't have the IAM permissions
    needed for the requested operation (e.g., cloudtrail:LookupEvents).
    This is 502 (not 403) because it's an upstream/gateway error - the USER
    authenticated fine, but the PROVIDER's credentials are misconfigured.
    """

    status_code = status.HTTP_502_BAD_GATEWAY
    default_detail = (
        "Access denied. The provider credentials do not have the required permissions."
    )
    default_code = "upstream_access_denied"

    def __init__(self, detail=None):
        super().__init__(
            detail=[
                {
                    "detail": detail or self.default_detail,
                    "status": str(self.status_code),
                    "code": self.default_code,
                }
            ]
        )


class UpstreamServiceUnavailableError(APIException):
    """Provider service is unavailable (503 Service Unavailable).

    Used when the upstream provider API returns an error or is unreachable.
    """

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "Unable to communicate with the provider. Please try again later."
    default_code = "service_unavailable"

    def __init__(self, detail=None):
        super().__init__(
            detail=[
                {
                    "detail": detail or self.default_detail,
                    "status": str(self.status_code),
                    "code": self.default_code,
                }
            ]
        )


class UpstreamInternalError(APIException):
    """Unexpected error communicating with provider (500 Internal Server Error).

    Used as a catch-all for unexpected errors during provider communication.
    """

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = (
        "An unexpected error occurred while communicating with the provider."
    )
    default_code = "internal_error"

    def __init__(self, detail=None):
        super().__init__(
            detail=[
                {
                    "detail": detail or self.default_detail,
                    "status": str(self.status_code),
                    "code": self.default_code,
                }
            ]
        )
