from prowler.exceptions.exceptions import ProwlerException


class AzureBaseException(ProwlerException):
    """Base class for Azure Errors."""

    AZURE_ERROR_CODES = {
        (1914, "AzureEnvironmentVariableError"): {
            "message": "Azure environment variable error",
            "remediation": "Check the Azure environment variables and ensure they are properly set.",
        },
        (1915, "AzureNoSubscriptionsError"): {
            "message": "No Azure subscriptions found",
            "remediation": "Check the Azure subscriptions and ensure they are properly set up.",
        },
        (1916, "AzureSetUpIdentityError"): {
            "message": "Azure identity setup error related with credentials",
            "remediation": "Check credentials and ensure they are properly set up for Azure and the identity provider.",
        },
        (1917, "AzureNoAuthenticationMethodError"): {
            "message": "No Azure authentication method found",
            "remediation": "Check that any authentication method is properly set up for Azure.",
        },
        (1918, "AzureBrowserAuthNoTenantIDError"): {
            "message": "Azure browser authentication error: no tenant ID found",
            "remediation": "To use browser authentication, ensure the tenant ID is properly set.",
        },
        (1919, "AzureTenantIDNoBrowserAuthError"): {
            "message": "Azure tenant ID error: browser authentication not found",
            "remediation": "To use browser authentication, both the tenant ID and browser authentication must be properly set.",
        },
        (1920, "AzureArgumentTypeValidationError"): {
            "message": "Azure argument type validation error",
            "remediation": "Check the provided argument types specific to Azure and ensure they meet the required format.",
        },
        (1921, "AzureSetUpRegionConfigError"): {
            "message": "Azure region configuration setup error",
            "remediation": "Check the Azure region configuration and ensure it is properly set up.",
        },
        (1922, "AzureDefaultAzureCredentialError"): {
            "message": "Error in DefaultAzureCredential",
            "remediation": "Check that all the attributes are properly set up for the DefaultAzureCredential.",
        },
        (1923, "AzureInteractiveBrowserCredentialError"): {
            "message": "Error retrieving InteractiveBrowserCredential",
            "remediation": "Check your browser and ensure that the tenant ID and browser authentication are properly set.",
        },
        (1924, "AzureHTTPResponseError"): {
            "message": "Error in HTTP response from Azure",
            "remediation": "",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Azure"
        error_info = self.AZURE_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            provider=provider,
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
            1914, file=file, original_exception=original_exception, message=message
        )


class AzureNoSubscriptionsError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1915, file=file, original_exception=original_exception, message=message
        )


class AzureSetUpIdentityError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1916, file=file, original_exception=original_exception, message=message
        )


class AzureNoAuthenticationMethodError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1917, file=file, original_exception=original_exception, message=message
        )


class AzureBrowserAuthNoTenantIDError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1918, file=file, original_exception=original_exception, message=message
        )


class AzureTenantIDNoBrowserAuthError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1919, file=file, original_exception=original_exception, message=message
        )


class AzureArgumentTypeValidationError(AzureBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1920, file=file, original_exception=original_exception, message=message
        )


class AzureSetUpRegionConfigError(AzureBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1921, file=file, original_exception=original_exception, message=message
        )


class AzureDefaultAzureCredentialError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1922, file=file, original_exception=original_exception, message=message
        )


class AzureInteractiveBrowserCredentialError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1923, file=file, original_exception=original_exception, message=message
        )


class AzureHTTPResponseError(AzureBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            1924, file=file, original_exception=original_exception, message=message
        )
