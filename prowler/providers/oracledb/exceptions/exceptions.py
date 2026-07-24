from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 20000 to 20999 are reserved for Oracle Database exceptions
class OracledbBaseException(ProwlerException):
    """Base class for Oracle Database Errors."""

    ORACLEDB_ERROR_CODES = {
        (20000, "OracledbEnvironmentVariableError"): {
            "message": "Oracle Database environment variable error",
            "remediation": "Check the Oracle Database environment variables and ensure they are properly set.",
        },
        (20001, "OracledbSetUpSessionError"): {
            "message": "Error setting up Oracle Database session",
            "remediation": "Check the connection credentials (user, password, DSN) and ensure the database is reachable.",
        },
        (20002, "OracledbSetUpIdentityError"): {
            "message": "Oracle Database identity setup error due to bad credentials",
            "remediation": "Check the connection credentials and confirm the user can query the database dictionary views.",
        },
        (20003, "OracledbInvalidCredentialsError"): {
            "message": "Oracle Database credentials are not valid",
            "remediation": "Check the user and password for the Oracle Database connection.",
        },
        (20004, "OracledbConnectionError"): {
            "message": "Could not connect to the Oracle Database",
            "remediation": "Check the DSN (host:port/service_name), network connectivity and listener status.",
        },
        (20005, "OracledbInvalidProviderIdError"): {
            "message": "The provided provider_id does not match the connected database",
            "remediation": "Check the provider_id (Oracle Database global name) and ensure it matches the database the credentials connect to.",
        },
        (20006, "OracledbInsufficientPrivilegesError"): {
            "message": "Oracle Database user is missing required privileges",
            "remediation": "Grant the SELECT ANY DICTIONARY system privilege (or the SELECT_CATALOG_ROLE role) to the assessment user.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "OracleDB"
        error_info = self.ORACLEDB_ERROR_CODES.get((code, self.__class__.__name__))
        if error_info is None:
            error_info = {
                "message": message or "Unknown Oracle Database error.",
                "remediation": "Check the Oracle Database documentation for more details.",
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


class OracledbCredentialsError(OracledbBaseException):
    """Base class for Oracle Database credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class OracledbEnvironmentVariableError(OracledbCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            20000, file=file, original_exception=original_exception, message=message
        )


class OracledbSetUpSessionError(OracledbCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            20001, file=file, original_exception=original_exception, message=message
        )


class OracledbSetUpIdentityError(OracledbCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            20002, file=file, original_exception=original_exception, message=message
        )


class OracledbInvalidCredentialsError(OracledbCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            20003, file=file, original_exception=original_exception, message=message
        )


class OracledbConnectionError(OracledbCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            20004, file=file, original_exception=original_exception, message=message
        )


class OracledbInvalidProviderIdError(OracledbCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            20005, file=file, original_exception=original_exception, message=message
        )


class OracledbInsufficientPrivilegesError(OracledbCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            20006, file=file, original_exception=original_exception, message=message
        )
