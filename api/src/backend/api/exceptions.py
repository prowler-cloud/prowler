from django.core.exceptions import ValidationError as django_validation_error
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework_json_api.exceptions import exception_handler
from rest_framework_json_api.serializers import ValidationError
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken


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


def custom_exception_handler(exc, context):
    if isinstance(exc, django_validation_error):
        if hasattr(exc, "error_dict"):
            exc = ValidationError(exc.message_dict)
        else:
            exc = ValidationError(detail=exc.messages[0], code=exc.code)
    elif isinstance(exc, (TokenError, InvalidToken)):
        exc.detail["messages"] = [
            message_item["message"] for message_item in exc.detail["messages"]
        ]
    return exception_handler(exc, context)
