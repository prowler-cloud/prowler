from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 17000 to 17999 are reserved for OpenStack exceptions
class OpenStackBaseException(ProwlerException):
    """Base class for OpenStack Errors."""

    OPENSTACK_ERROR_CODES = {
        (17000, "OpenStackCredentialsError"): {
            "message": "OpenStack credentials not found or invalid",
            "remediation": "Check the OpenStack API credentials and ensure they are properly set.",
        },
        (17001, "OpenStackAuthenticationError"): {
            "message": "OpenStack authentication failed",
            "remediation": "Check the OpenStack API credentials and ensure they are valid.",
        },
        (17002, "OpenStackSessionError"): {
            "message": "OpenStack session setup failed",
            "remediation": "Check the session setup and ensure it is properly configured.",
        },
        (17003, "OpenStackIdentityError"): {
            "message": "OpenStack identity setup failed",
            "remediation": "Check credentials and ensure they are properly set up for OpenStack.",
        },
        (17004, "OpenStackAPIError"): {
            "message": "OpenStack API call failed",
            "remediation": "Check the API request and ensure it is properly formatted.",
        },
        (17005, "OpenStackRateLimitError"): {
            "message": "OpenStack API rate limit exceeded",
            "remediation": "Reduce the number of API requests or wait before making more requests.",
        },
        (17006, "OpenStackConfigFileNotFoundError"): {
            "message": "OpenStack clouds.yaml configuration file not found",
            "remediation": "Check that the clouds.yaml file exists at the specified path or in standard locations (~/.config/openstack/clouds.yaml, /etc/openstack/clouds.yaml, ./clouds.yaml).",
        },
        (17007, "OpenStackCloudNotFoundError"): {
            "message": "Specified cloud not found in clouds.yaml configuration",
            "remediation": "Check that the cloud name exists in your clouds.yaml file and is properly configured.",
        },
        (17008, "OpenStackInvalidConfigError"): {
            "message": "Invalid or malformed clouds.yaml configuration file",
            "remediation": "Check that the clouds.yaml file is valid YAML and follows the OpenStack configuration format.",
        },
        (17009, "OpenStackInvalidProviderIdError"): {
            "message": "Provider ID does not match the project_id in clouds.yaml",
            "remediation": "Ensure the provider_id matches the project_id configured in your clouds.yaml file.",
        },
        (17010, "OpenStackNoRegionError"): {
            "message": "No region configuration found in clouds.yaml",
            "remediation": "Add either 'region_name' (single region) or 'regions' (list of regions) to your cloud configuration in clouds.yaml.",
        },
        (17011, "OpenStackAmbiguousRegionError"): {
            "message": "Ambiguous region configuration in clouds.yaml",
            "remediation": "Use either 'region_name' or 'regions' in your cloud configuration, not both.",
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
            code=17000,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackAuthenticationError(OpenStackBaseException):
    """Exception for OpenStack authentication errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=17001,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackSessionError(OpenStackBaseException):
    """Exception for OpenStack session setup errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=17002,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackIdentityError(OpenStackBaseException):
    """Exception for OpenStack identity setup errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=17003,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackAPIError(OpenStackBaseException):
    """Exception for OpenStack API errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=17004,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackRateLimitError(OpenStackBaseException):
    """Exception for OpenStack rate limit errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=17005,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackConfigFileNotFoundError(OpenStackBaseException):
    """Exception for clouds.yaml file not found errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=17006,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackCloudNotFoundError(OpenStackBaseException):
    """Exception for cloud not found in clouds.yaml errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=17007,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackInvalidConfigError(OpenStackBaseException):
    """Exception for invalid clouds.yaml configuration errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=17008,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackInvalidProviderIdError(OpenStackBaseException):
    """Exception for provider_id not matching project_id in clouds.yaml"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=17009,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackNoRegionError(OpenStackBaseException):
    """Exception for missing region configuration in clouds.yaml"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=17010,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class OpenStackAmbiguousRegionError(OpenStackBaseException):
    """Exception for ambiguous region configuration in clouds.yaml"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=17011,
            file=file,
            original_exception=original_exception,
            message=message,
        )
