import pytest

from prowler.providers.oracledb.exceptions.exceptions import (
    OracledbBaseException,
    OracledbConnectionError,
    OracledbEnvironmentVariableError,
    OracledbInsufficientPrivilegesError,
    OracledbInvalidCredentialsError,
    OracledbInvalidProviderIdError,
    OracledbSetUpIdentityError,
    OracledbSetUpSessionError,
)


class TestOracledbExceptions:
    @pytest.mark.parametrize(
        "exception_class,code",
        [
            (OracledbEnvironmentVariableError, 20000),
            (OracledbSetUpSessionError, 20001),
            (OracledbSetUpIdentityError, 20002),
            (OracledbInvalidCredentialsError, 20003),
            (OracledbConnectionError, 20004),
            (OracledbInvalidProviderIdError, 20005),
            (OracledbInsufficientPrivilegesError, 20006),
        ],
    )
    def test_exception_code_and_source(self, exception_class, code):
        exception = exception_class(file="test_file")

        assert isinstance(exception, OracledbBaseException)
        assert exception.code == code
        assert f"[{code}]" in str(exception)

    def test_custom_message_overrides_default(self):
        exception = OracledbConnectionError(message="custom connection failure")

        assert "custom connection failure" in str(exception)

    def test_default_message_when_none_given(self):
        exception = OracledbInvalidCredentialsError()

        assert "credentials are not valid" in str(exception)
