from prowler.exceptions.exceptions import ProwlerException


class AzureCredentialsError(ProwlerException):
    """Base class for Azure credentials errors."""

    def __init__(self, code, provider="Azure", file=None, original_exception=None):
        super().__init__(code, provider, file, original_exception)


class AzureEnvironmentVariableError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1918, provider="Azure", file=file, original_exception=original_exception
        )


class AzureNoSubscriptionsError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1919, provider="Azure", file=file, original_exception=original_exception
        )


class AzureSetUpIdentityError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1920, provider="Azure", file=file, original_exception=original_exception
        )


class AzureNoAuthenticationMethodError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1921, provider="Azure", file=file, original_exception=original_exception
        )


class AzureBrowserAuthNoTenantIDError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1922, provider="Azure", file=file, original_exception=original_exception
        )


class AzureTenantIDNoBrowserAuthError(AzureCredentialsError):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1923, provider="Azure", file=file, original_exception=original_exception
        )


class AzureArgumentTypeValidationError(ProwlerException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1924, provider="Azure", file=file, original_exception=original_exception
        )


class AzureSetUpRegionConfigError(ProwlerException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1925, provider="Azure", file=file, original_exception=original_exception
        )


class AzureDefaultAzureCredentialError(ProwlerException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1926, provider="Azure", file=file, original_exception=original_exception
        )


class AzureInteractiveBrowserCredentialError(ProwlerException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1927, provider="Azure", file=file, original_exception=original_exception
        )


class AzureHTTPResponseError(ProwlerException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1928, provider="Azure", file=file, original_exception=original_exception
        )
