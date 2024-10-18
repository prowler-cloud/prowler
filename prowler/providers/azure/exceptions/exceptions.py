from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 2000 to 2999 are reserved for Azure exceptions
class AzureBaseException(ProwlerException):
    """Base class for Azure Errors."""

    AZURE_ERROR_CODES = {
        (2000, "AzureEnvironmentVariableError"): {
            "message": "Azure environment variable error",
            "remediation": "Check the Azure environment variables and ensure they are properly set.",
        },
        (2001, "AzureNoSubscriptionsError"): {
            "message": "No Azure subscriptions found",
            "remediation": "Check the Azure subscriptions and ensure they are properly set up.",
        },
        (2002, "AzureSetUpIdentityError"): {
            "message": "Azure identity setup error related with credentials",
            "remediation": "Check credentials and ensure they are properly set up for Azure and the identity provider.",
        },
        (2003, "AzureNoAuthenticationMethodError"): {
            "message": "No Azure authentication method found",
            "remediation": "Check that any authentication method is properly set up for Azure.",
        },
        (2004, "AzureBrowserAuthNoTenantIDError"): {
            "message": "Azure browser authentication error: no tenant ID found",
            "remediation": "To use browser authentication, ensure the tenant ID is properly set.",
        },
        (2005, "AzureTenantIDNoBrowserAuthError"): {
            "message": "Azure tenant ID error: browser authentication not found",
            "remediation": "To use browser authentication, both the tenant ID and browser authentication must be properly set.",
        },
        (2006, "AzureArgumentTypeValidationError"): {
            "message": "Azure argument type validation error",
            "remediation": "Check the provided argument types specific to Azure and ensure they meet the required format.",
        },
        (2007, "AzureSetUpRegionConfigError"): {
            "message": "Azure region configuration setup error",
            "remediation": "Check the Azure region configuration and ensure it is properly set up.",
        },
        (2008, "AzureDefaultAzureCredentialError"): {
            "message": "Error in DefaultAzureCredential",
            "remediation": "Check that all the attributes are properly set up for the DefaultAzureCredential.",
        },
        (2009, "AzureInteractiveBrowserCredentialError"): {
            "message": "Error retrieving InteractiveBrowserCredential",
            "remediation": "Check your browser and ensure that the tenant ID and browser authentication are properly set.",
        },
        (2010, "AzureHTTPResponseError"): {
            "message": "Error in HTTP response from Azure",
            "remediation": "",
        },
        (2011, "AzureCredentialsUnavailableError"): {
            "message": "Error trying to configure Azure credentials because they are unavailable",
            "remediation": "Check the dictionary and ensure it is properly set up for Azure credentials. TENANT_ID, CLIENT_ID and CLIENT_SECRET are required.",
        },
        (2012, "AzureGetTokenIdentityError"): {
            "message": "Error trying to get token from Azure Identity",
            "remediation": "Check the Azure Identity and ensure it is properly set up.",
        },
        (2013, "AzureNotTenantIdButClientIdAndClienSecretError"): {
            "message": "The provided credentials are not a tenant ID but a client ID and client secret",
            "remediation": "Tenant Id, Client Id and Client Secret are required for Azure credentials. Make sure you are using the correct credentials.",
        },
        (2014, "AzureClientAuthenticationError"): {
            "message": "Error in client authentication",
            "remediation": "Check the client authentication and ensure it is properly set up.",
        },
        (2015, "AzureSetUpSessionError"): {
            "message": "Error setting up session",
            "remediation": "Check the session setup and ensure it is properly set up.",
        },
        (2016, "AzureNotValidTenantIdError"): {
            "message": "The provided tenant ID is not valid",
            "remediation": "Check the tenant ID and ensure it is a valid ID.",
        },
        (2017, "AzureNotValidClientIdError"): {
            "message": "The provided client ID is not valid",
            "remediation": "Check the client ID and ensure it is a valid ID.",
        },
        (2018, "AzureNotValidClientSecretError"): {
            "message": "The provided client secret is not valid",
            "remediation": "Check the client secret and ensure it is a valid secret.",
        },
        (2019, "AzureConfigCredentialsError"): {
            "message": "Error in configuration of Azure credentials",
            "remediation": "Check the configuration of Azure credentials and ensure it is properly set up.",
        },
        (2020, "AzureClientIdAndClientSecretNotBelongingToTenantIdError"): {
            "message": "The provided client ID and client secret do not belong to the provided tenant ID",
            "remediation": "Check the client ID and client secret and ensure they belong to the provided tenant ID.",
        },
        (2021, "AzureTenantIdAndClientSecretNotBelongingToClientIdError"): {
            "message": "The provided tenant ID and client secret do not belong to the provided client ID",
            "remediation": "Check the tenant ID and client secret and ensure they belong to the provided client ID.",
        },
        (2022, "AzureTenantIdAndClientIdNotBelongingToClientSecretError"): {
            "message": "The provided tenant ID and client ID do not belong to the provided client secret",
            "remediation": "Check the tenant ID and client ID and ensure they belong to the provided client secret.",
        },
        (2023, "AzureInvalidProviderIdError"): {
            "message": "The provided provider_id does not match with the available subscriptions",
            "remediation": "Check the provider_id and ensure it is a valid subscription for the given credentials.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Azure"
        error_info = self.AZURE_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class AzureCredentialsError(AzureBaseException):
    """Base class for Azure credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class AzureEnvironmentVariableError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2000, file=file, original_exception=original_exception, message=message
        )


class AzureNoSubscriptionsError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2001, file=file, original_exception=original_exception, message=message
        )


class AzureSetUpIdentityError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2002, file=file, original_exception=original_exception, message=message
        )


class AzureNoAuthenticationMethodError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2003, file=file, original_exception=original_exception, message=message
        )


class AzureBrowserAuthNoTenantIDError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2004, file=file, original_exception=original_exception, message=message
        )


class AzureTenantIDNoBrowserAuthError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2005, file=file, original_exception=original_exception, message=message
        )


class AzureArgumentTypeValidationError(AzureBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2006, file=file, original_exception=original_exception, message=message
        )


class AzureSetUpRegionConfigError(AzureBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2007, file=file, original_exception=original_exception, message=message
        )


class AzureDefaultAzureCredentialError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2008, file=file, original_exception=original_exception, message=message
        )


class AzureInteractiveBrowserCredentialError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2009, file=file, original_exception=original_exception, message=message
        )


class AzureHTTPResponseError(AzureBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2010, file=file, original_exception=original_exception, message=message
        )


class AzureCredentialsUnavailableError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2011, file=file, original_exception=original_exception, message=message
        )


class AzureGetTokenIdentityError(AzureBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2012, file=file, original_exception=original_exception, message=message
        )


class AzureNotTenantIdButClientIdAndClienSecretError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2013, file=file, original_exception=original_exception, message=message
        )


class AzureClientAuthenticationError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2014, file=file, original_exception=original_exception, message=message
        )


class AzureSetUpSessionError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2015, file=file, original_exception=original_exception, message=message
        )


class AzureNotValidTenantIdError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2016, file=file, original_exception=original_exception, message=message
        )


class AzureNotValidClientIdError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2017, file=file, original_exception=original_exception, message=message
        )


class AzureNotValidClientSecretError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2018, file=file, original_exception=original_exception, message=message
        )


class AzureConfigCredentialsError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2019, file=file, original_exception=original_exception, message=message
        )


class AzureClientIdAndClientSecretNotBelongingToTenantIdError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2020, file=file, original_exception=original_exception, message=message
        )


class AzureTenantIdAndClientSecretNotBelongingToClientIdError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2021, file=file, original_exception=original_exception, message=message
        )


class AzureTenantIdAndClientIdNotBelongingToClientSecretError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2022, file=file, original_exception=original_exception, message=message
        )


class AzureInvalidProviderIdError(AzureBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            2023, file=file, original_exception=original_exception, message=message
        )
