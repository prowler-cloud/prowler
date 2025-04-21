from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 5000 to 5999 are reserved for M365 exceptions
class M365BaseException(ProwlerException):
    """Base class for M365 Errors."""

    MICROSOFT365_ERROR_CODES = {
        (6000, "M365EnvironmentVariableError"): {
            "message": "Microsoft 365 environment variable error",
            "remediation": "Check the Microsoft 365 environment variables and ensure they are properly set.",
        },
        (6001, "M365ArgumentTypeValidationError"): {
            "message": "Microsoft 365 argument type validation error",
            "remediation": "Check the provided argument types specific to Microsoft 365 and ensure they meet the required format.",
        },
        (6002, "M365SetUpRegionConfigError"): {
            "message": "Microsoft 365 region configuration setup error",
            "remediation": "Check the Microsoft 365 region configuration and ensure it is properly set up.",
        },
        (6003, "M365HTTPResponseError"): {
            "message": "Error in HTTP response from Microsoft 365",
            "remediation": "",
        },
        (6004, "M365CredentialsUnavailableError"): {
            "message": "Error trying to configure Microsoft 365 credentials because they are unavailable",
            "remediation": "Check the dictionary and ensure it is properly set up for Microsoft 365 credentials. TENANT_ID, CLIENT_ID and CLIENT_SECRET are required.",
        },
        (6005, "M365GetTokenIdentityError"): {
            "message": "Error trying to get token from Microsoft 365 Identity",
            "remediation": "Check the Microsoft 365 Identity and ensure it is properly set up.",
        },
        (6006, "M365ClientAuthenticationError"): {
            "message": "Error in client authentication",
            "remediation": "Check the client authentication and ensure it is properly set up.",
        },
        (6007, "M365NotValidTenantIdError"): {
            "message": "The provided tenant ID is not valid",
            "remediation": "Check the tenant ID and ensure it is a valid ID.",
        },
        (6008, "M365NotValidClientIdError"): {
            "message": "The provided client ID is not valid",
            "remediation": "Check the client ID and ensure it is a valid ID.",
        },
        (6009, "M365NotValidClientSecretError"): {
            "message": "The provided client secret is not valid",
            "remediation": "Check the client secret and ensure it is a valid secret.",
        },
        (6010, "M365ConfigCredentialsError"): {
            "message": "Error in configuration of Microsoft 365 credentials",
            "remediation": "Check the configuration of Microsoft 365 credentials and ensure it is properly set up.",
        },
        (6011, "M365ClientIdAndClientSecretNotBelongingToTenantIdError"): {
            "message": "The provided client ID and client secret do not belong to the provided tenant ID",
            "remediation": "Check the client ID and client secret and ensure they belong to the provided tenant ID.",
        },
        (6012, "M365TenantIdAndClientSecretNotBelongingToClientIdError"): {
            "message": "The provided tenant ID and client secret do not belong to the provided client ID",
            "remediation": "Check the tenant ID and client secret and ensure they belong to the provided client ID.",
        },
        (6013, "M365TenantIdAndClientIdNotBelongingToClientSecretError"): {
            "message": "The provided tenant ID and client ID do not belong to the provided client secret",
            "remediation": "Check the tenant ID and client ID and ensure they belong to the provided client secret.",
        },
        (6014, "M365InvalidTenantDomainError"): {
            "message": "The provided tenant domain is not valid",
            "remediation": "Check the tenant domain and ensure it is a valid domain.",
        },
        (6015, "M365NoAuthenticationMethodError"): {
            "message": "No Microsoft 365 authentication method found",
            "remediation": "Check that any authentication method is properly set up for Microsoft 365.",
        },
        (6016, "M365SetUpSessionError"): {
            "message": "Error setting up session",
            "remediation": "Check the session setup and ensure it is properly set up.",
        },
        (6017, "M365DefaultAzureCredentialError"): {
            "message": "Error with DefaultAzureCredential",
            "remediation": "Ensure DefaultAzureCredential is correctly configured.",
        },
        (6018, "M365InteractiveBrowserCredentialError"): {
            "message": "Error with InteractiveBrowserCredential",
            "remediation": "Ensure InteractiveBrowserCredential is correctly configured.",
        },
        (6019, "M365BrowserAuthNoTenantIDError"): {
            "message": "Microsoft 365 Tenant ID (--tenant-id) is required for browser authentication mode",
            "remediation": "Check the Microsoft 365 Tenant ID and ensure it is properly set up.",
        },
        (6020, "M365BrowserAuthNoFlagError"): {
            "message": "Microsoft 365 tenant ID error: browser authentication flag (--browser-auth) not found",
            "remediation": "To use browser authentication, ensure the tenant ID is properly set.",
        },
        (6021, "M365NotTenantIdButClientIdAndClientSecretError"): {
            "message": "Tenant Id is required for Microsoft 365 static credentials. Make sure you are using the correct credentials.",
            "remediation": "Check the Microsoft 365 Tenant ID and ensure it is properly set up.",
        },
        (6022, "M365MissingEnvironmentCredentialsError"): {
            "message": "User and Password environment variables are needed to use Credentials authentication method.",
            "remediation": "Ensure your environment variables are properly set up.",
        },
        (6023, "M365EnvironmentUserCredentialsError"): {
            "message": "User or Password environment variables are not correct.",
            "remediation": "Ensure you are using the right credentials.",
        },
        (6024, "M365NotValidUserError"): {
            "message": "The provided M365 User is not valid.",
            "remediation": "Check the M365 User and ensure it is a valid user.",
        },
        (6025, "M365NotValidEncryptedPasswordError"): {
            "message": "The provided M365 Encrypted Password is not valid.",
            "remediation": "Check the M365 Encrypted Password and ensure it is a valid password.",
        },
        (6026, "M365UserNotBelongingToTenantError"): {
            "message": "The provided M365 User does not belong to the specified tenant.",
            "remediation": "Check the M365 User email domain and ensure it belongs to the specified tenant.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "M365"
        error_info = self.MICROSOFT365_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class M365CredentialsError(M365BaseException):
    """Base class for M365 credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class M365EnvironmentVariableError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6000, file=file, original_exception=original_exception, message=message
        )


class M365ArgumentTypeValidationError(M365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6001, file=file, original_exception=original_exception, message=message
        )


class M365SetUpRegionConfigError(M365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6002, file=file, original_exception=original_exception, message=message
        )


class M365HTTPResponseError(M365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6003, file=file, original_exception=original_exception, message=message
        )


class M365CredentialsUnavailableError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6004, file=file, original_exception=original_exception, message=message
        )


class M365GetTokenIdentityError(M365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6005, file=file, original_exception=original_exception, message=message
        )


class M365ClientAuthenticationError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6006, file=file, original_exception=original_exception, message=message
        )


class M365NotValidTenantIdError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6007, file=file, original_exception=original_exception, message=message
        )


class M365NotValidClientIdError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6008, file=file, original_exception=original_exception, message=message
        )


class M365NotValidClientSecretError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6009, file=file, original_exception=original_exception, message=message
        )


class M365ConfigCredentialsError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6010, file=file, original_exception=original_exception, message=message
        )


class M365ClientIdAndClientSecretNotBelongingToTenantIdError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6011, file=file, original_exception=original_exception, message=message
        )


class M365TenantIdAndClientSecretNotBelongingToClientIdError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6012, file=file, original_exception=original_exception, message=message
        )


class M365TenantIdAndClientIdNotBelongingToClientSecretError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6013, file=file, original_exception=original_exception, message=message
        )


class M365InvalidTenantDomainError(M365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6014, file=file, original_exception=original_exception, message=message
        )


class M365NoAuthenticationMethodError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6015, file=file, original_exception=original_exception, message=message
        )


class M365SetUpSessionError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6016, file=file, original_exception=original_exception, message=message
        )


class M365DefaultAzureCredentialError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6017, file=file, original_exception=original_exception, message=message
        )


class M365InteractiveBrowserCredentialError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6018, file=file, original_exception=original_exception, message=message
        )


class M365BrowserAuthNoTenantIDError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6019, file=file, original_exception=original_exception, message=message
        )


class M365BrowserAuthNoFlagError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6020, file=file, original_exception=original_exception, message=message
        )


class M365NotTenantIdButClientIdAndClientSecretError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6021, file=file, original_exception=original_exception, message=message
        )


class M365MissingEnvironmentCredentialsError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6022, file=file, original_exception=original_exception, message=message
        )


class M365EnvironmentUserCredentialsError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6023, file=file, original_exception=original_exception, message=message
        )


class M365NotValidUserError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6024, file=file, original_exception=original_exception, message=message
        )


class M365NotValidEncryptedPasswordError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6025, file=file, original_exception=original_exception, message=message
        )


class M365UserNotBelongingToTenantError(M365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6026, file=file, original_exception=original_exception, message=message
        )
