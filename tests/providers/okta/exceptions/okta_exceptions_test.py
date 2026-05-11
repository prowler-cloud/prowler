import pytest

from prowler.providers.okta.exceptions.exceptions import (
    OktaBaseException,
    OktaCredentialsError,
    OktaEnvironmentVariableError,
    OktaInsufficientPermissionsError,
    OktaInvalidCredentialsError,
    OktaInvalidOrgURLError,
    OktaPrivateKeyFileError,
    OktaSetUpIdentityError,
    OktaSetUpSessionError,
)

EXPECTED_CODES = {
    OktaEnvironmentVariableError: 14000,
    OktaSetUpSessionError: 14001,
    OktaSetUpIdentityError: 14002,
    OktaInvalidCredentialsError: 14003,
    OktaInvalidOrgURLError: 14004,
    OktaPrivateKeyFileError: 14005,
    OktaInsufficientPermissionsError: 14006,
}


class Test_OktaExceptions:
    def test_all_codes_in_reserved_range(self):
        codes = [c for c, _ in OktaBaseException.OKTA_ERROR_CODES.keys()]
        assert all(14000 <= c <= 14999 for c in codes)
        assert len(codes) == len(set(codes))  # unique

    def test_all_subclasses_inherit_from_credentials_error(self):
        for exc_cls in EXPECTED_CODES:
            assert issubclass(exc_cls, OktaCredentialsError)
            assert issubclass(exc_cls, OktaBaseException)

    @pytest.mark.parametrize("exc_cls,code", list(EXPECTED_CODES.items()))
    def test_each_exception_carries_its_code(self, exc_cls, code):
        exc = exc_cls()
        assert exc.code == code
        assert exc.source == "Okta"
        assert exc.message  # populated from OKTA_ERROR_CODES
        assert exc.remediation  # populated from OKTA_ERROR_CODES

    @pytest.mark.parametrize("exc_cls", list(EXPECTED_CODES.keys()))
    def test_custom_message_overrides_default(self, exc_cls):
        custom = "specific error context"
        exc = exc_cls(message=custom)
        assert exc.message == custom

    def test_str_format_includes_class_code_and_message(self):
        exc = OktaInvalidOrgURLError(message="bad url")
        rendered = str(exc)
        assert "OktaInvalidOrgURLError" in rendered
        assert "[14004]" in rendered
        assert "bad url" in rendered

    def test_original_exception_appended_to_str(self):
        original = ValueError("network down")
        exc = OktaSetUpIdentityError(original_exception=original)
        rendered = str(exc)
        assert "network down" in rendered

    def test_can_be_raised_and_caught(self):
        with pytest.raises(OktaInvalidCredentialsError) as info:
            raise OktaInvalidCredentialsError(message="bad token")
        assert info.value.code == 14003
        assert "bad token" in str(info.value)

    def test_caught_as_credentials_error_base(self):
        with pytest.raises(OktaCredentialsError):
            raise OktaPrivateKeyFileError(message="empty")

    def test_caught_as_okta_base_exception(self):
        with pytest.raises(OktaBaseException):
            raise OktaEnvironmentVariableError(message="missing org url")
