import os
from unittest import mock

import pytest

from prowler.providers.huaweicloud.exceptions.exceptions import (
    HuaweiCloudAuthenticationError,
    HuaweiCloudBaseException,
    HuaweiCloudCredentialsError,
    HuaweiCloudIdentityError,
    HuaweiCloudInvalidProviderIdError,
    HuaweiCloudInvalidRegionError,
    HuaweiCloudServiceError,
    HuaweiCloudSetUpSessionError,
)
from prowler.providers.huaweicloud.huaweicloud_provider import HuaweicloudProvider
from prowler.providers.huaweicloud.models import (
    HuaweiCloudCallerIdentity,
    HuaweiCloudSession,
)

ACCESS_KEY = "AKIAmockaccesskey"
SECRET_KEY = "mocksecretkey"


class TestHuaweiCloudProviderSetupSession:
    def test_missing_credentials_raises(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with pytest.raises(HuaweiCloudCredentialsError):
                HuaweicloudProvider.setup_session()

    def test_returns_session_with_explicit_credentials(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            session = HuaweicloudProvider.setup_session(
                access_key_id=ACCESS_KEY,
                secret_access_key=SECRET_KEY,
                project_id="pid",
            )
            assert isinstance(session, HuaweiCloudSession)
            assert session.get_credentials().ak == ACCESS_KEY
            assert not session.is_mock

    def test_reads_credentials_from_env(self):
        env = {
            "HUAWEICLOUD_ACCESS_KEY_ID": ACCESS_KEY,
            "HUAWEICLOUD_SECRET_ACCESS_KEY": SECRET_KEY,
        }
        with mock.patch.dict(os.environ, env, clear=True):
            session = HuaweicloudProvider.setup_session()
            assert session.get_credentials().ak == ACCESS_KEY

    def test_mock_auth_returns_mock_session(self):
        with mock.patch.dict(os.environ, {"HUAWEICLOUD_MOCK_AUTH": "true"}, clear=True):
            session = HuaweicloudProvider.setup_session()
            assert session.is_mock


class TestHuaweiCloudProviderValidateCredentials:
    def test_mock_session_returns_caller_identity(self):
        with mock.patch.dict(os.environ, {"HUAWEICLOUD_MOCK_AUTH": "true"}, clear=True):
            session = HuaweicloudProvider.setup_session()
            identity = HuaweicloudProvider.validate_credentials(session=session)
            assert isinstance(identity, HuaweiCloudCallerIdentity)
            assert identity.account_id == "123456789012"


class TestHuaweiCloudProviderGetRegionsToAudit:
    @staticmethod
    def _provider():
        # Bare instance is enough: get_regions_to_audit only reads the module-level
        # HUAWEICLOUD_REGIONS and guards access to self._identity with hasattr.
        return HuaweicloudProvider.__new__(HuaweicloudProvider)

    def test_valid_regions(self):
        regions = self._provider().get_regions_to_audit(["cn-north-4"])
        assert [r.region_id for r in regions] == ["cn-north-4"]

    def test_no_regions_returns_all(self):
        from prowler.providers.huaweicloud.config import HUAWEICLOUD_REGIONS

        regions = self._provider().get_regions_to_audit(None)
        assert len(regions) == len(HUAWEICLOUD_REGIONS)

    def test_all_invalid_regions_raises(self):
        with pytest.raises(HuaweiCloudInvalidRegionError):
            self._provider().get_regions_to_audit(["not-a-region"])

    def test_partial_invalid_regions_keeps_valid(self):
        regions = self._provider().get_regions_to_audit(["cn-north-4", "not-a-region"])
        assert [r.region_id for r in regions] == ["cn-north-4"]


class TestHuaweiCloudProviderTestConnection:
    def test_mock_auth_connected(self):
        with mock.patch.dict(os.environ, {"HUAWEICLOUD_MOCK_AUTH": "true"}, clear=True):
            connection = HuaweicloudProvider.test_connection()
            assert connection.is_connected
            assert connection.error is None

    def test_provider_id_mismatch_raises(self):
        fake_identity = HuaweiCloudCallerIdentity(
            domain_id="d",
            user_id="u",
            user_name="n",
            account_id="111111111111",
            account_name="acct",
            type="user",
        )
        with mock.patch.dict(os.environ, {}, clear=True):
            with (
                mock.patch.object(
                    HuaweicloudProvider,
                    "setup_session",
                    return_value=mock.MagicMock(),
                ),
                mock.patch.object(
                    HuaweicloudProvider,
                    "validate_credentials",
                    return_value=fake_identity,
                ),
            ):
                with pytest.raises(HuaweiCloudInvalidProviderIdError):
                    HuaweicloudProvider.test_connection(
                        access_key_id=ACCESS_KEY,
                        secret_access_key=SECRET_KEY,
                        provider_id="999999999999",
                        raise_on_exception=True,
                    )

    def test_missing_credentials_returns_error_when_not_raising(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            connection = HuaweicloudProvider.test_connection(raise_on_exception=False)
            assert connection.is_connected is not True
            assert connection.error is not None


class TestHuaweiCloudExceptions:
    def test_error_codes_are_unique_and_in_reserved_range(self):
        classes = [
            HuaweiCloudCredentialsError,
            HuaweiCloudAuthenticationError,
            HuaweiCloudSetUpSessionError,
            HuaweiCloudIdentityError,
            HuaweiCloudInvalidRegionError,
            HuaweiCloudInvalidProviderIdError,
            HuaweiCloudServiceError,
        ]
        codes = set()
        for cls in classes:
            error = cls(file="huaweicloud_provider.py")
            assert isinstance(error, HuaweiCloudBaseException)
            assert 19000 <= error.code <= 19099
            assert error.message
            assert error.remediation
            codes.add(error.code)
        assert len(codes) == len(classes)

    def test_custom_message_override(self):
        error = HuaweiCloudServiceError(message="custom service failure")
        assert error.message == "custom service failure"
        assert error.code == 19006
