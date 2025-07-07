"""
IONOS Provider Exceptions
"""


class IonosProviderError(Exception):
    """Common base class for all IONOS Provider exceptions."""


class IonosAuthenticationError(IonosProviderError):
    """Common base class for IONOS authentication exceptions."""


class IonosNoAuthMethodProvidedError(IonosAuthenticationError):
    """Exception raised when no authentication method is provided."""

    def __init__(self):
        super().__init__(
            "IONOS provider requires at least one authentication method: [--user-env-vars | --ionosctl | --user/--password]"
        )


class IonosIncompleteCredentialsError(IonosAuthenticationError):
    """Exception raised when credentials are incomplete."""

    def __init__(self):
        super().__init__(
            "Both --user and --password flags must be provided for credential authentication"
        )


class IonosEnvironmentCredentialsError(IonosAuthenticationError):
    """Exception raised when environment credentials are incomplete."""

    def __init__(self):
        super().__init__(
            "Could not find IONOS environment credentials. Please set IONOS_USERNAME and IONOS_PASSWORD environment variables"
        )


class IonosTokenLoadError(IonosAuthenticationError):
    """Exception raised when the IONOS token cannot be loaded."""

    def __init__(self):
        super().__init__(
            "Could not load IONOS token from ionosctl configuration"
        )
