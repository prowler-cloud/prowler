from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 14000 to 14999 are reserved for Okta exceptions
class OktaBaseException(ProwlerException):
    """Base class for Okta Errors."""

    OKTA_ERROR_CODES = {
        (14000, "OktaEnvironmentVariableError"): {
            "message": "Okta environment variable error",
            "remediation": "Check the Okta environment variables and ensure they are properly set.",
        },
        (14001, "OktaSetUpSessionError"): {
            "message": "Error setting up Okta session",
            "remediation": "Check the OAuth credentials (org URL, client ID, private key, scopes) and ensure they are properly configured.",
        },
        (14002, "OktaSetUpIdentityError"): {
            "message": "Okta identity setup error due to bad credentials",
            "remediation": "Check the OAuth credentials and confirm the service app has been granted the required read scopes.",
        },
        (14003, "OktaInvalidCredentialsError"): {
            "message": "Okta credentials are not valid",
            "remediation": "Check the client ID and private key for the Okta service app.",
        },
        (14004, "OktaInvalidOrgURLError"): {
            "message": "Okta organization URL is not valid",
            "remediation": "Provide an org URL in the form https://<org>.okta.com (no trailing slash).",
        },
        (14005, "OktaPrivateKeyFileError"): {
            "message": "Okta private key file could not be read",
            "remediation": "Check the file path and permissions, and ensure the file contains a PEM-encoded RSA key or a JWK JSON document.",
        },
        (14006, "OktaInsufficientPermissionsError"): {
            "message": "Okta service app is missing required scopes",
            "remediation": "Have a Super Admin grant the required *.read scopes to the service app and assign the Read-Only Administrator role.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Okta"
        error_info = self.OKTA_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class OktaCredentialsError(OktaBaseException):
    """Base class for Okta credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class OktaEnvironmentVariableError(OktaCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14000, file=file, original_exception=original_exception, message=message
        )


class OktaSetUpSessionError(OktaCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14001, file=file, original_exception=original_exception, message=message
        )


class OktaSetUpIdentityError(OktaCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14002, file=file, original_exception=original_exception, message=message
        )


class OktaInvalidCredentialsError(OktaCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14003, file=file, original_exception=original_exception, message=message
        )


class OktaInvalidOrgURLError(OktaCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14004, file=file, original_exception=original_exception, message=message
        )


class OktaPrivateKeyFileError(OktaCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14005, file=file, original_exception=original_exception, message=message
        )


class OktaInsufficientPermissionsError(OktaCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            14006, file=file, original_exception=original_exception, message=message
        )
