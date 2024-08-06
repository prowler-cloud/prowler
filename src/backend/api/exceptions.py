from django.core.exceptions import ValidationError as django_validation_error
from rest_framework_json_api.exceptions import exception_handler
from rest_framework_json_api.serializers import ValidationError


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


def custom_exception_handler(exc, context):
    if isinstance(exc, django_validation_error):
        if hasattr(exc, "error_dict"):
            exc = ValidationError(exc.message_dict)
        else:
            exc = ValidationError(detail=exc.messages[0], code=exc.code)
    return exception_handler(exc, context)
