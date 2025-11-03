from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 7000 to 7999 are reserved for OCI exceptions
class OCIBaseException(ProwlerException):
    """Base class for OCI errors."""

    OCI_ERROR_CODES = {
        (7000, "OCIClientError"): {
            "message": "OCI ClientError occurred",
            "remediation": "Check your OCI client configuration and permissions.",
        },
        (7001, "OCIConfigFileNotFoundError"): {
            "message": "OCI Config file not found",
            "remediation": "Ensure the OCI config file exists at the specified path, please visit https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm",
        },
        (7002, "OCIInvalidConfigError"): {
            "message": "Invalid OCI configuration",
            "remediation": "Verify that your OCI configuration is properly set up, please visit https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm",
        },
        (7003, "OCIProfileNotFoundError"): {
            "message": "OCI Profile not found",
            "remediation": "Ensure the OCI profile exists in your config file, please visit https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm",
        },
        (7004, "OCINoCredentialsError"): {
            "message": "No OCI credentials found",
            "remediation": "Verify that OCI credentials are properly set up, please visit https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm",
        },
        (7005, "OCIAuthenticationError"): {
            "message": "OCI authentication failed",
            "remediation": "Check your OCI credentials and ensure they are valid.",
        },
        (7006, "OCISetUpSessionError"): {
            "message": "OCI session setup error",
            "remediation": "Check the OCI session setup and ensure it is properly configured.",
        },
        (7007, "OCIInvalidRegionError"): {
            "message": "Invalid OCI region",
            "remediation": "Check the OCI region name and ensure it is valid, please visit https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm",
        },
        (7008, "OCIInvalidCompartmentError"): {
            "message": "Invalid OCI compartment",
            "remediation": "Check the OCI compartment OCID and ensure it exists and is accessible.",
        },
        (7009, "OCIInvalidTenancyError"): {
            "message": "Invalid OCI tenancy",
            "remediation": "Check the OCI tenancy OCID and ensure it is valid.",
        },
        (7010, "OCIServiceError"): {
            "message": "OCI service error occurred",
            "remediation": "Check the OCI service error details and ensure proper permissions.",
        },
        (7011, "OCIInstancePrincipalError"): {
            "message": "OCI instance principal authentication failed",
            "remediation": "Ensure the instance has proper instance principal configuration and dynamic group policies.",
        },
        (7012, "OCIInvalidOCIDError"): {
            "message": "Invalid OCI OCID format",
            "remediation": "Check the OCID format and ensure it matches the pattern: ocid1.<resource_type>.<realm>.<region>.<unique_id>",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        error_info = self.OCI_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code,
            source="OCI",
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class OCICredentialsError(OCIBaseException):
    """Base class for OCI credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class OCIClientError(OCICredentialsError):
    """Exception raised when OCI client error occurs."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7000, file=file, original_exception=original_exception, message=message
        )


class OCIConfigFileNotFoundError(OCICredentialsError):
    """Exception raised when OCI config file is not found."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7001, file=file, original_exception=original_exception, message=message
        )


class OCIInvalidConfigError(OCICredentialsError):
    """Exception raised when OCI configuration is invalid."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7002, file=file, original_exception=original_exception, message=message
        )


class OCIProfileNotFoundError(OCICredentialsError):
    """Exception raised when OCI profile is not found."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7003, file=file, original_exception=original_exception, message=message
        )


class OCINoCredentialsError(OCICredentialsError):
    """Exception raised when no OCI credentials are found."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7004, file=file, original_exception=original_exception, message=message
        )


class OCIAuthenticationError(OCICredentialsError):
    """Exception raised when OCI authentication fails."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7005, file=file, original_exception=original_exception, message=message
        )


class OCISetUpSessionError(OCIBaseException):
    """Exception raised when OCI session setup fails."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7006, file=file, original_exception=original_exception, message=message
        )


class OCIInvalidRegionError(OCIBaseException):
    """Exception raised when OCI region is invalid."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7007, file=file, original_exception=original_exception, message=message
        )


class OCIInvalidCompartmentError(OCIBaseException):
    """Exception raised when OCI compartment is invalid."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7008, file=file, original_exception=original_exception, message=message
        )


class OCIInvalidTenancyError(OCIBaseException):
    """Exception raised when OCI tenancy is invalid."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7009, file=file, original_exception=original_exception, message=message
        )


class OCIServiceError(OCIBaseException):
    """Exception raised when OCI service error occurs."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7010, file=file, original_exception=original_exception, message=message
        )


class OCIInstancePrincipalError(OCIBaseException):
    """Exception raised when OCI instance principal authentication fails."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7011, file=file, original_exception=original_exception, message=message
        )


class OCIInvalidOCIDError(OCIBaseException):
    """Exception raised when OCI OCID format is invalid."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            7012, file=file, original_exception=original_exception, message=message
        )
