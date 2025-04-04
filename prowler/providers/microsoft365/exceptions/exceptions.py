from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 5000 to 5999 are reserved for Microsoft365 exceptions
class Microsoft365BaseException(ProwlerException):
    """Base class for Microsoft365 Errors."""

    MICROSOFT365_ERROR_CODES = {
        (6000, "Microsoft365EnvironmentVariableError"): {
            "message": "Microsoft365 environment variable error",
            "remediation": "Check the Microsoft365 environment variables and ensure they are properly set.",
        },
        (6001, "Microsoft365ArgumentTypeValidationError"): {
            "message": "Microsoft365 argument type validation error",
            "remediation": "Check the provided argument types specific to Microsoft365 and ensure they meet the required format.",
        },
        (6002, "Microsoft365SetUpRegionConfigError"): {
            "message": "Microsoft365 region configuration setup error",
            "remediation": "Check the Microsoft365 region configuration and ensure it is properly set up.",
        },
        (6003, "Microsoft365HTTPResponseError"): {
            "message": "Error in HTTP response from Microsoft365",
            "remediation": "",
        },
        (6004, "Microsoft365CredentialsUnavailableError"): {
            "message": "Error trying to configure Microsoft365 credentials because they are unavailable",
            "remediation": "Check the dictionary and ensure it is properly set up for Microsoft365 credentials. TENANT_ID, CLIENT_ID and CLIENT_SECRET are required.",
        },
        (6005, "Microsoft365GetTokenIdentityError"): {
            "message": "Error trying to get token from Microsoft365 Identity",
            "remediation": "Check the Microsoft365 Identity and ensure it is properly set up.",
        },
        (6006, "Microsoft365ClientAuthenticationError"): {
            "message": "Error in client authentication",
            "remediation": "Check the client authentication and ensure it is properly set up.",
        },
        (6007, "Microsoft365NotValidTenantIdError"): {
            "message": "The provided tenant ID is not valid",
            "remediation": "Check the tenant ID and ensure it is a valid ID.",
        },
        (6008, "Microsoft365NotValidClientIdError"): {
            "message": "The provided client ID is not valid",
            "remediation": "Check the client ID and ensure it is a valid ID.",
        },
        (6009, "Microsoft365NotValidClientSecretError"): {
            "message": "The provided client secret is not valid",
            "remediation": "Check the client secret and ensure it is a valid secret.",
        },
        (6010, "Microsoft365ConfigCredentialsError"): {
            "message": "Error in configuration of Microsoft365 credentials",
            "remediation": "Check the configuration of Microsoft365 credentials and ensure it is properly set up.",
        },
        (6011, "Microsoft365ClientIdAndClientSecretNotBelongingToTenantIdError"): {
            "message": "The provided client ID and client secret do not belong to the provided tenant ID",
            "remediation": "Check the client ID and client secret and ensure they belong to the provided tenant ID.",
        },
        (6012, "Microsoft365TenantIdAndClientSecretNotBelongingToClientIdError"): {
            "message": "The provided tenant ID and client secret do not belong to the provided client ID",
            "remediation": "Check the tenant ID and client secret and ensure they belong to the provided client ID.",
        },
        (6013, "Microsoft365TenantIdAndClientIdNotBelongingToClientSecretError"): {
            "message": "The provided tenant ID and client ID do not belong to the provided client secret",
            "remediation": "Check the tenant ID and client ID and ensure they belong to the provided client secret.",
        },
        (6014, "Microsoft365InvalidProviderIdError"): {
            "message": "The provided provider_id does not match with the available subscriptions",
            "remediation": "Check the provider_id and ensure it is a valid subscription for the given credentials.",
        },
        (6015, "Microsoft365NoAuthenticationMethodError"): {
            "message": "No Microsoft365 authentication method found",
            "remediation": "Check that any authentication method is properly set up for Microsoft365.",
        },
        (6016, "Microsoft365SetUpSessionError"): {
            "message": "Error setting up session",
            "remediation": "Check the session setup and ensure it is properly set up.",
        },
        (6017, "Microsoft365DefaultAzureCredentialError"): {
            "message": "Error with DefaultAzureCredential",
            "remediation": "Ensure DefaultAzureCredential is correctly configured.",
        },
        (6018, "Microsoft365InteractiveBrowserCredentialError"): {
            "message": "Error with InteractiveBrowserCredential",
            "remediation": "Ensure InteractiveBrowserCredential is correctly configured.",
        },
        (6019, "Microsoft365BrowserAuthNoTenantIDError"): {
            "message": "Microsoft365 Tenant ID (--tenant-id) is required for browser authentication mode",
            "remediation": "Check the Microsoft365 Tenant ID and ensure it is properly set up.",
        },
        (6020, "Microsoft365BrowserAuthNoFlagError"): {
            "message": "Microsoft365 tenant ID error: browser authentication flag (--browser-auth) not found",
            "remediation": "To use browser authentication, ensure the tenant ID is properly set.",
        },
        (6021, "Microsoft365NotTenantIdButClientIdAndClientSecretError"): {
            "message": "Tenant Id is required for Microsoft365 static credentials. Make sure you are using the correct credentials.",
            "remediation": "Check the Microsoft365 Tenant ID and ensure it is properly set up.",
        },
        (6022, "Microsoft365MissingEnvironmentUserCredentialsError"): {
            "message": "User and Password environment variables are needed to use Credentials authentication method.",
            "remediation": "Ensure your environment variables are properly set up.",
        },
        (6023, "Microsoft365EnvironmentUserCredentialsError"): {
            "message": "User or Password environment variables are not correct.",
            "remediation": "Ensure you are using the right credentials.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Microsoft365"
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


class Microsoft365CredentialsError(Microsoft365BaseException):
    """Base class for Microsoft365 credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class Microsoft365EnvironmentVariableError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6000, file=file, original_exception=original_exception, message=message
        )


class Microsoft365ArgumentTypeValidationError(Microsoft365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6001, file=file, original_exception=original_exception, message=message
        )


class Microsoft365SetUpRegionConfigError(Microsoft365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6002, file=file, original_exception=original_exception, message=message
        )


class Microsoft365HTTPResponseError(Microsoft365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6003, file=file, original_exception=original_exception, message=message
        )


class Microsoft365CredentialsUnavailableError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6004, file=file, original_exception=original_exception, message=message
        )


class Microsoft365GetTokenIdentityError(Microsoft365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6005, file=file, original_exception=original_exception, message=message
        )


class Microsoft365ClientAuthenticationError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6006, file=file, original_exception=original_exception, message=message
        )


class Microsoft365NotValidTenantIdError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6007, file=file, original_exception=original_exception, message=message
        )


class Microsoft365NotValidClientIdError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6008, file=file, original_exception=original_exception, message=message
        )


class Microsoft365NotValidClientSecretError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6009, file=file, original_exception=original_exception, message=message
        )


class Microsoft365ConfigCredentialsError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6010, file=file, original_exception=original_exception, message=message
        )


class Microsoft365ClientIdAndClientSecretNotBelongingToTenantIdError(
    Microsoft365CredentialsError
):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6011, file=file, original_exception=original_exception, message=message
        )


class Microsoft365TenantIdAndClientSecretNotBelongingToClientIdError(
    Microsoft365CredentialsError
):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6012, file=file, original_exception=original_exception, message=message
        )


class Microsoft365TenantIdAndClientIdNotBelongingToClientSecretError(
    Microsoft365CredentialsError
):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6013, file=file, original_exception=original_exception, message=message
        )


class Microsoft365InvalidProviderIdError(Microsoft365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6014, file=file, original_exception=original_exception, message=message
        )


class Microsoft365NoAuthenticationMethodError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6015, file=file, original_exception=original_exception, message=message
        )


class Microsoft365SetUpSessionError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6016, file=file, original_exception=original_exception, message=message
        )


class Microsoft365DefaultAzureCredentialError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6017, file=file, original_exception=original_exception, message=message
        )


class Microsoft365InteractiveBrowserCredentialError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6018, file=file, original_exception=original_exception, message=message
        )


class Microsoft365BrowserAuthNoTenantIDError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6019, file=file, original_exception=original_exception, message=message
        )


class Microsoft365BrowserAuthNoFlagError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6020, file=file, original_exception=original_exception, message=message
        )


class Microsoft365NotTenantIdButClientIdAndClientSecretError(
    Microsoft365CredentialsError
):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6021, file=file, original_exception=original_exception, message=message
        )


class Microsoft365MissingEnvironmentUserCredentialsError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6022, file=file, original_exception=original_exception, message=message
        )


class Microsoft365EnvironmentUserCredentialsError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            6023, file=file, original_exception=original_exception, message=message
        )
