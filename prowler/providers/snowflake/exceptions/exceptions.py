from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 22000 to 22999 are reserved for Snowflake exceptions
class SnowflakeBaseException(ProwlerException):
    """Base class for Snowflake errors."""

    SNOWFLAKE_ERROR_CODES = {
        (22000, "SnowflakeCredentialsError"): {
            "message": "Snowflake credentials not found or incomplete",
            "remediation": "Provide the account identifier, user and RSA private key via SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER and SNOWFLAKE_PRIVATE_KEY_PATH.",
        },
        (22001, "SnowflakeAuthenticationError"): {
            "message": "Snowflake authentication failed",
            "remediation": "Confirm the public key is registered on the user with ALTER USER <user> SET RSA_PUBLIC_KEY, and that the fingerprint matches RSA_PUBLIC_KEY_FP in DESCRIBE USER.",
        },
        (22002, "SnowflakePrivateKeyError"): {
            "message": "The Snowflake private key could not be loaded",
            "remediation": "Supply an unencrypted PKCS#8 RSA private key, or an encrypted one together with SNOWFLAKE_PRIVATE_KEY_PASSPHRASE.",
        },
        (22003, "SnowflakeSessionError"): {
            "message": "Snowflake session setup failed",
            "remediation": "Verify the account identifier resolves to a reachable <account>.snowflakecomputing.com host and that outbound HTTPS is permitted.",
        },
        (22004, "SnowflakeIdentityError"): {
            "message": "Unable to retrieve Snowflake identity information",
            "remediation": "Ensure the role granted to the user can run SELECT CURRENT_ACCOUNT(), and that a warehouse is available to it.",
        },
        (22005, "SnowflakeMissingPermissionError"): {
            "message": "The Snowflake role cannot read the ACCOUNT_USAGE schema",
            "remediation": "Grant the role access with GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE <role>.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "Snowflake"
        error_info = self.SNOWFLAKE_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown Snowflake error",
                "remediation": "Check the Snowflake documentation for more details.",
            }
        elif message:
            error_info = error_info.copy()
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class SnowflakeCredentialsError(SnowflakeBaseException):
    """Exception for missing or incomplete Snowflake credentials."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22000, file=file, original_exception=original_exception, message=message
        )


class SnowflakeAuthenticationError(SnowflakeBaseException):
    """Exception for Snowflake authentication errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22001, file=file, original_exception=original_exception, message=message
        )


class SnowflakePrivateKeyError(SnowflakeBaseException):
    """Exception for unusable Snowflake private key material."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22002, file=file, original_exception=original_exception, message=message
        )


class SnowflakeSessionError(SnowflakeBaseException):
    """Exception for Snowflake session setup errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22003, file=file, original_exception=original_exception, message=message
        )


class SnowflakeIdentityError(SnowflakeBaseException):
    """Exception for Snowflake identity errors."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22004, file=file, original_exception=original_exception, message=message
        )


class SnowflakeMissingPermissionError(SnowflakeBaseException):
    """Exception for a role that cannot read ACCOUNT_USAGE."""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            22005, file=file, original_exception=original_exception, message=message
        )
