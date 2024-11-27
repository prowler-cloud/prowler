from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 5000 to 5999 are reserved for Microsoft365 exceptions
class Microsoft365BaseException(ProwlerException):
    """Base class for Microsoft365 Errors."""

    MICROSOFT365_ERROR_CODES = {
        (6000, "Microsoft365EnvironmentVariableError"): {
            "message": "Microsoft365 environment variable error",
            "remediation": "Check the Microsoft365 environment variables and ensure they are properly set.",
        },
        (6001, "Microsoft365NoSubscriptionsError"): {
            "message": "No Microsoft365 subscriptions found",
            "remediation": "Check the Microsoft365 subscriptions and ensure they are properly set up.",
        },
        (6002, "Microsoft365SetUpIdentityError"): {
            "message": "Microsoft365 identity setup error related with credentials",
            "remediation": "Check credentials and ensure they are properly set up for Microsoft365 and the identity provider.",
        },
        (6003, "Microsoft365NoAuthenticationMethodError"): {
            "message": "No Microsoft365 authentication method found",
            "remediation": "Check that any authentication method is properly set up for Microsoft365.",
        },
        (6006, "Microsoft365ArgumentTypeValidationError"): {
            "message": "Microsoft365 argument type validation error",
            "remediation": "Check the provided argument types specific to Microsoft365 and ensure they meet the required format.",
        },
        (6007, "Microsoft365SetUpRegionConfigError"): {
            "message": "Microsoft365 region configuration setup error",
            "remediation": "Check the Microsoft365 region configuration and ensure it is properly set up.",
        },
        (6008, "Microsoft365DefaultMicrosoft365CredentialError"): {
            "message": "Error in DefaultMicrosoft365Credential",
            "remediation": "Check that all the attributes are properly set up for the DefaultMicrosoft365Credential.",
        },
        (6009, "Microsoft365InteractiveBrowserCredentialError"): {
            "message": "Error retrieving InteractiveBrowserCredential",
            "remediation": "Check your browser and ensure that the tenant ID and browser authentication are properly set.",
        },
        (6010, "Microsoft365HTTPResponseError"): {
            "message": "Error in HTTP response from Microsoft365",
            "remediation": "",
        },
        (6011, "Microsoft365CredentialsUnavailableError"): {
            "message": "Error trying to configure Microsoft365 credentials because they are unavailable",
            "remediation": "Check the dictionary and ensure it is properly set up for Microsoft365 credentials. TENANT_ID, CLIENT_ID and CLIENT_SECRET are required.",
        },
        (6012, "Microsoft365GetTokenIdentityError"): {
            "message": "Error trying to get token from Microsoft365 Identity",
            "remediation": "Check the Microsoft365 Identity and ensure it is properly set up.",
        },
        (6013, "Microsoft365NotTenantIdButClientIdAndClienSecretError"): {
            "message": "The provided credentials are not a tenant ID but a client ID and client secret",
            "remediation": "Tenant Id, Client Id and Client Secret are required for Microsoft365 credentials. Make sure you are using the correct credentials.",
        },
        (6014, "Microsoft365ClientAuthenticationError"): {
            "message": "Error in client authentication",
            "remediation": "Check the client authentication and ensure it is properly set up.",
        },
        (6015, "Microsoft365SetUpSessionError"): {
            "message": "Error setting up session",
            "remediation": "Check the session setup and ensure it is properly set up.",
        },
        (6016, "Microsoft365NotValidTenantIdError"): {
            "message": "The provided tenant ID is not valid",
            "remediation": "Check the tenant ID and ensure it is a valid ID.",
        },
        (6017, "Microsoft365NotValidClientIdError"): {
            "message": "The provided client ID is not valid",
            "remediation": "Check the client ID and ensure it is a valid ID.",
        },
        (6018, "Microsoft365NotValidClientSecretError"): {
            "message": "The provided client secret is not valid",
            "remediation": "Check the client secret and ensure it is a valid secret.",
        },
        (6019, "Microsoft365ConfigCredentialsError"): {
            "message": "Error in configuration of Microsoft365 credentials",
            "remediation": "Check the configuration of Microsoft365 credentials and ensure it is properly set up.",
        },
        (6020, "Microsoft365ClientIdAndClientSecretNotBelongingToTenantIdError"): {
            "message": "The provided client ID and client secret do not belong to the provided tenant ID",
            "remediation": "Check the client ID and client secret and ensure they belong to the provided tenant ID.",
        },
        (6021, "Microsoft365TenantIdAndClientSecretNotBelongingToClientIdError"): {
            "message": "The provided tenant ID and client secret do not belong to the provided client ID",
            "remediation": "Check the tenant ID and client secret and ensure they belong to the provided client ID.",
        },
        (6022, "Microsoft365TenantIdAndClientIdNotBelongingToClientSecretError"): {
            "message": "The provided tenant ID and client ID do not belong to the provided client secret",
            "remediation": "Check the tenant ID and client ID and ensure they belong to the provided client secret.",
        },
        (6023, "Microsoft365InvalidProviderIdError"): {
            "message": "The provided provider_id does not match with the available subscriptions",
            "remediation": "Check the provider_id and ensure it is a valid subscription for the given credentials.",
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
            2000, file=file, original_exception=original_exception, message=message
        )


class Microsoft365NoSubscriptionsError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2001, file=file, original_exception=original_exception, message=message
        )


class Microsoft365SetUpIdentityError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2002, file=file, original_exception=original_exception, message=message
        )


class Microsoft365NoAuthenticationMethodError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2003, file=file, original_exception=original_exception, message=message
        )


class Microsoft365BrowserAuthNoTenantIDError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2004, file=file, original_exception=original_exception, message=message
        )


class Microsoft365TenantIDNoBrowserAuthError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2005, file=file, original_exception=original_exception, message=message
        )


class Microsoft365ArgumentTypeValidationError(Microsoft365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2006, file=file, original_exception=original_exception, message=message
        )


class Microsoft365SetUpRegionConfigError(Microsoft365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2007, file=file, original_exception=original_exception, message=message
        )


class Microsoft365DefaultMicrosoft365CredentialError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2008, file=file, original_exception=original_exception, message=message
        )


class Microsoft365InteractiveBrowserCredentialError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2009, file=file, original_exception=original_exception, message=message
        )


class Microsoft365HTTPResponseError(Microsoft365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2010, file=file, original_exception=original_exception, message=message
        )


class Microsoft365CredentialsUnavailableError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2011, file=file, original_exception=original_exception, message=message
        )


class Microsoft365GetTokenIdentityError(Microsoft365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2012, file=file, original_exception=original_exception, message=message
        )


class Microsoft365NotTenantIdButClientIdAndClienSecretError(
    Microsoft365CredentialsError
):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2013, file=file, original_exception=original_exception, message=message
        )


class Microsoft365ClientAuthenticationError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2014, file=file, original_exception=original_exception, message=message
        )


class Microsoft365SetUpSessionError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2015, file=file, original_exception=original_exception, message=message
        )


class Microsoft365NotValidTenantIdError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2016, file=file, original_exception=original_exception, message=message
        )


class Microsoft365NotValidClientIdError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2017, file=file, original_exception=original_exception, message=message
        )


class Microsoft365NotValidClientSecretError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2018, file=file, original_exception=original_exception, message=message
        )


class Microsoft365ConfigCredentialsError(Microsoft365CredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2019, file=file, original_exception=original_exception, message=message
        )


class Microsoft365ClientIdAndClientSecretNotBelongingToTenantIdError(
    Microsoft365CredentialsError
):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2020, file=file, original_exception=original_exception, message=message
        )


class Microsoft365TenantIdAndClientSecretNotBelongingToClientIdError(
    Microsoft365CredentialsError
):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2021, file=file, original_exception=original_exception, message=message
        )


class Microsoft365TenantIdAndClientIdNotBelongingToClientSecretError(
    Microsoft365CredentialsError
):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2022, file=file, original_exception=original_exception, message=message
        )


class Microsoft365InvalidProviderIdError(Microsoft365BaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2023, file=file, original_exception=original_exception, message=message
        )
