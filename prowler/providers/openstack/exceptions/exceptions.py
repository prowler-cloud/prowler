from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 10000 to 10999 are reserved for OpenStack exceptions
class OpenStackBaseException(ProwlerException):
    """Base class for OpenStack Errors."""

    OPENSTACK_ERROR_CODES = {
        (10000, "OpenStackCredentialsError"): {
            "message": "OpenStack credentials not found or invalid",
            "remediation": "Check the OpenStack API credentials and ensure they are properly set.",
        },
        (10001, "OpenStackAuthenticationError"): {
            "message": "OpenStack authentication failed",
            "remediation": "Check the OpenStack API credentials and ensure they are valid.",
        },
        (10002, "OpenStackSessionError"): {
            "message": "OpenStack session setup failed",
            "remediation": "Check the session setup and ensure it is properly configured.",
        },
        (10003, "OpenStackIdentityError"): {
            "message": "OpenStack identity setup failed",
            "remediation": "Check credentials and ensure they are properly set up for OpenStack.",
        },
        (10004, "OpenStackAPIError"): {
            "message": "OpenStack API call failed",
            "remediation": "Check the API request and ensure it is properly formatted.",
        },
        (10005, "OpenStackRateLimitError"): {
            "message": "OpenStack API rate limit exceeded",
            "remediation": "Reduce the number of API requests or wait before making more requests.",
        },
        (10006, "OpenStackInvalidOrganizationIdError"): {
            "message": "The provided credentials do not have access to the organization with the provided ID",
            "remediation": "Check the organization ID and ensure it is a valid organization ID and that the credentials have access to it.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "OpenStack"
        error_info = self.OPENSTACK_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class OpenStackCredentialsError(OpenStackBaseException):
    """Exception for OpenStack credentials errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=10000,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackAuthenticationError(OpenStackBaseException):
    """Exception for OpenStack authentication errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=10001,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackSessionError(OpenStackBaseException):
    """Exception for OpenStack session setup errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=10002,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackIdentityError(OpenStackBaseException):
    """Exception for OpenStack identity setup errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=10003,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackAPIError(OpenStackBaseException):
    """Exception for OpenStack API errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=10004,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackRateLimitError(OpenStackBaseException):
    """Exception for OpenStack rate limit errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=10005,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackInvalidOrganizationIdError(OpenStackBaseException):
    """Exception for OpenStack invalid organization ID errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=10006,
            file=file,
            original_exception=original_exception,
            message=message,
        )
