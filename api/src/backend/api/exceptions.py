from django.core.exceptions import ValidationError as django_validation_error
from rest_framework import status
from rest_framework.exceptions import APIException
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


def custom_exception_handler(exc, context):
    if isinstance(exc, django_validation_error):
        if hasattr(exc, "error_dict"):
            exc = ValidationError(exc.message_dict)
        else:
            exc = ValidationError(detail=exc.messages[0], code=exc.code)
    elif isinstance(exc, (TokenError, InvalidToken)):
        if (
            hasattr(exc, "detail")
            and isinstance(exc.detail, dict)
            and "messages" in exc.detail
        ):
            exc.detail["messages"] = [
                message_item["message"] for message_item in exc.detail["messages"]
            ]
    return exception_handler(exc, context)
