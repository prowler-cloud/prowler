import os
from unittest.mock import MagicMock, call, patch

import pytest
from alibabacloud_tea_openapi.exceptions import ClientException
from darabonba.core import DaraCore
from darabonba.exceptions import RetryError, UnretryableException
from Tea.exceptions import UnretryableException as TeaUnretryableException
from Tea.response import TeaResponse

from prowler.providers.alibabacloud.alibabacloud_provider import AlibabacloudProvider
from prowler.providers.alibabacloud.exceptions.exceptions import (
    AlibabaCloudConnectionError,
    AlibabaCloudInvalidCredentialsError,
    AlibabaCloudSetUpSessionError,
)
from prowler.providers.alibabacloud.models import AlibabaCloudCallerIdentity
from prowler.providers.common.models import Connection


def test_validate_credentials_non_authentication_api_error_is_not_invalid_credentials():
    """Test non-authentication STS API errors are not relabeled as credentials."""
    session = MagicMock()
    session.get_credentials.return_value = MagicMock(
        access_key_id="LTAI1234567890",
        access_key_secret="test-secret-key",
        security_token=None,
    )
    api_error = ClientException(
        code="Forbidden",
        message="The caller is not authorized",
        status_code=403,
    )
    wrapped_api_error = TeaUnretryableException(request=None, ex=api_error)

    with (
        patch.object(DaraCore, "do_action", side_effect=wrapped_api_error),
        patch.object(DaraCore, "sleep") as sleep,
    ):
        with pytest.raises(UnretryableException) as exception:
            AlibabacloudProvider.validate_credentials(session)

    assert not isinstance(exception.value, AlibabaCloudInvalidCredentialsError)
    assert exception.value.inner_exception is wrapped_api_error
    assert exception.value.inner_exception.inner_exception is api_error
    sleep.assert_not_called()


def test_validate_credentials_retries_transport_failure_then_succeeds():
    """Test STS caller identity retries a transient transport failure."""
    session = MagicMock()
    session.get_credentials.return_value = MagicMock(
        access_key_id="LTAI1234567890",
        access_key_secret="test-secret-key",
        security_token=None,
    )
    response = TeaResponse()
    response.status_code = 200
    response.headers = {"content-type": "application/json"}
    response.body = (
        b'{"AccountId":"1234567890","PrincipalId":"123456",'
        b'"Arn":"acs:ram::1234567890:user/test-user",'
        b'"IdentityType":"RamUser"}'
    )

    with (
        patch.object(
            DaraCore,
            "do_action",
            side_effect=[RetryError("connection reset"), response],
        ) as do_action,
        patch.object(DaraCore, "sleep") as sleep,
    ):
        caller_identity = AlibabacloudProvider.validate_credentials(session)

    assert caller_identity.account_id == "1234567890"
    assert do_action.call_count == 2
    sleep.assert_called_once_with(1000)


def test_validate_credentials_connection_failure_is_not_invalid_credentials():
    """Test exhausted STS transport retries raise a connection-specific error."""
    session = MagicMock()
    session.get_credentials.return_value = MagicMock(
        access_key_id="LTAI1234567890",
        access_key_secret="test-secret-key",
        security_token=None,
    )
    retry_errors = []
    for _ in range(3):
        connection_reset = ConnectionResetError(104, "Connection reset by peer")
        retry_error = RetryError(str(connection_reset))
        retry_error.__cause__ = connection_reset
        retry_errors.append(retry_error)

    with (
        patch.object(DaraCore, "do_action", side_effect=retry_errors) as do_action,
        patch.object(DaraCore, "sleep") as sleep,
    ):
        with pytest.raises(AlibabaCloudConnectionError) as exception:
            AlibabacloudProvider.validate_credentials(session)

    assert not isinstance(exception.value, AlibabaCloudInvalidCredentialsError)
    assert do_action.call_count == 3
    assert sleep.call_args_list == [call(1000), call(1000)]
    assert isinstance(exception.value.original_exception, UnretryableException)
    assert exception.value.original_exception.inner_exception is retry_errors[-1]
    assert exception.value.__cause__ is exception.value.original_exception


def test_validate_credentials_genuine_invalid_credentials():
    """Test an explicit STS authentication failure remains a credentials error."""
    session = MagicMock()
    session.get_credentials.return_value = MagicMock(
        access_key_id="LTAI-invalid",
        access_key_secret="invalid-secret",
        security_token=None,
    )
    authentication_error = ClientException(
        code="InvalidAccessKeyId.NotFound",
        message="The AccessKey ID does not exist",
        status_code=400,
    )
    wrapped_authentication_error = TeaUnretryableException(
        request=None, ex=authentication_error
    )

    with (
        patch.object(DaraCore, "do_action", side_effect=wrapped_authentication_error),
        patch.object(DaraCore, "sleep") as sleep,
    ):
        with pytest.raises(AlibabaCloudInvalidCredentialsError) as exception:
            AlibabacloudProvider.validate_credentials(session)

    assert isinstance(exception.value.original_exception, UnretryableException)
    assert (
        exception.value.original_exception.inner_exception
        is wrapped_authentication_error
    )
    assert (
        exception.value.original_exception.inner_exception.inner_exception
        is authentication_error
    )
    assert exception.value.__cause__ is exception.value.original_exception
    sleep.assert_not_called()


def test_validate_credentials_authentication_error_wins_over_transport_error():
    """Test a definitive nested authentication error takes precedence over transport."""
    session = MagicMock()
    session.get_credentials.return_value = MagicMock(
        access_key_id="LTAI-invalid",
        access_key_secret="invalid-secret",
        security_token=None,
    )
    authentication_error = ClientException(
        code="InvalidAccessKeyId.NotFound",
        message="The AccessKey ID does not exist",
        status_code=400,
    )
    retry_errors = []
    for _ in range(3):
        retry_error = RetryError("connection reset")
        retry_error.__cause__ = authentication_error
        retry_errors.append(retry_error)

    with (
        patch.object(DaraCore, "do_action", side_effect=retry_errors),
        patch.object(DaraCore, "sleep") as sleep,
    ):
        with pytest.raises(AlibabaCloudInvalidCredentialsError) as exception:
            AlibabacloudProvider.validate_credentials(session)

    assert isinstance(exception.value.original_exception, UnretryableException)
    assert exception.value.original_exception.inner_exception is retry_errors[-1]
    assert exception.value.__cause__ is exception.value.original_exception
    assert sleep.call_args_list == [call(1000), call(1000)]


class TestAlibabacloudProviderTestConnection:
    """Tests for the AlibabacloudProvider.test_connection method."""

    def test_test_connection_connection_error_no_raise(self):
        """Test connection failures are returned with their dedicated type."""
        mock_session = MagicMock()
        connection_error = AlibabaCloudConnectionError(
            file="test_file",
            original_exception=RetryError("connection reset"),
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ),
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                side_effect=connection_error,
            ),
            patch(
                "prowler.providers.alibabacloud.alibabacloud_provider.logger.error"
            ) as logger_error,
            patch(
                "prowler.providers.alibabacloud.alibabacloud_provider.logger.critical"
            ) as logger_critical,
        ):
            result = AlibabacloudProvider.test_connection(
                access_key_id="LTAI1234567890",
                access_key_secret="test-secret-key",
                raise_on_exception=False,
            )

        assert result.is_connected is False
        assert result.error is connection_error
        assert result.error.code == 10008
        logger_error.assert_called_once()
        logger_critical.assert_not_called()

    def test_test_connection_connection_error_raises(self):
        """Test connection failures retain raise-on-exception behavior."""
        mock_session = MagicMock()
        connection_error = AlibabaCloudConnectionError(
            file="test_file",
            original_exception=RetryError("connection reset"),
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ),
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                side_effect=connection_error,
            ),
            patch(
                "prowler.providers.alibabacloud.alibabacloud_provider.logger.error"
            ) as logger_error,
            patch(
                "prowler.providers.alibabacloud.alibabacloud_provider.logger.critical"
            ) as logger_critical,
        ):
            with pytest.raises(AlibabaCloudConnectionError) as exception:
                AlibabacloudProvider.test_connection(
                    access_key_id="LTAI1234567890",
                    access_key_secret="test-secret-key",
                    raise_on_exception=True,
                )

        assert exception.value is connection_error
        logger_error.assert_called_once()
        logger_critical.assert_not_called()

    def test_test_connection_with_static_credentials_success(self):
        """Test successful connection with static access key credentials."""
        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:user/test-user",
            identity_type="RamUser",
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                return_value=mock_caller_identity,
            ) as mock_validate_credentials,
        ):
            result = AlibabacloudProvider.test_connection(
                access_key_id="LTAI1234567890",
                access_key_secret="test-secret-key",
                raise_on_exception=False,
            )

            assert isinstance(result, Connection)
            assert result.is_connected is True
            assert result.error is None
            mock_setup_session.assert_called_once()
            mock_validate_credentials.assert_called_once()

    def test_test_connection_with_sts_token_success(self):
        """Test successful connection with STS temporary credentials."""
        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:user/test-user",
            identity_type="RamUser",
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ),
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                return_value=mock_caller_identity,
            ),
        ):
            result = AlibabacloudProvider.test_connection(
                access_key_id="STS.LTAI1234567890",
                access_key_secret="test-secret-key",
                security_token="test-security-token",
                raise_on_exception=False,
            )

            assert isinstance(result, Connection)
            assert result.is_connected is True
            assert result.error is None

    def test_test_connection_with_role_arn_success(self):
        """Test successful connection with RAM role assumption."""
        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:role/ProwlerRole",
            identity_type="AssumedRoleUser",
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                return_value=mock_caller_identity,
            ),
        ):
            result = AlibabacloudProvider.test_connection(
                role_arn="acs:ram::1234567890:role/ProwlerRole",
                role_session_name="prowler-session",
                raise_on_exception=False,
            )

            assert isinstance(result, Connection)
            assert result.is_connected is True
            assert result.error is None
            mock_setup_session.assert_called_once_with(
                role_arn="acs:ram::1234567890:role/ProwlerRole",
                role_session_name="prowler-session",
                ecs_ram_role=None,
                oidc_role_arn=None,
                credentials_uri=None,
                access_key_id=None,
                access_key_secret=None,
                security_token=None,
            )

    def test_test_connection_with_provider_id_validation_success(self):
        """Test successful connection with provider_id validation."""
        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:user/test-user",
            identity_type="RamUser",
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ),
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                return_value=mock_caller_identity,
            ),
        ):
            result = AlibabacloudProvider.test_connection(
                access_key_id="LTAI1234567890",
                access_key_secret="test-secret-key",
                provider_id="1234567890",
                raise_on_exception=False,
            )

            assert isinstance(result, Connection)
            assert result.is_connected is True
            assert result.error is None

    def test_test_connection_with_provider_id_mismatch_raises_exception(self):
        """Test connection with provider_id mismatch raises exception."""
        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:user/test-user",
            identity_type="RamUser",
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ),
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                return_value=mock_caller_identity,
            ),
        ):
            with pytest.raises(AlibabaCloudInvalidCredentialsError) as exception:
                AlibabacloudProvider.test_connection(
                    access_key_id="LTAI1234567890",
                    access_key_secret="test-secret-key",
                    provider_id="different-account-id",
                    raise_on_exception=True,
                )

            assert "Provider ID mismatch" in str(exception.value)
            assert "expected 'different-account-id'" in str(exception.value)
            assert "got '1234567890'" in str(exception.value)

    def test_test_connection_with_provider_id_mismatch_no_raise(self):
        """Test connection with provider_id mismatch returns error without raising."""
        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:user/test-user",
            identity_type="RamUser",
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ),
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                return_value=mock_caller_identity,
            ),
        ):
            result = AlibabacloudProvider.test_connection(
                access_key_id="LTAI1234567890",
                access_key_secret="test-secret-key",
                provider_id="different-account-id",
                raise_on_exception=False,
            )

            assert isinstance(result, Connection)
            assert result.is_connected is False
            assert result.error is not None
            assert isinstance(result.error, AlibabaCloudInvalidCredentialsError)

    def test_test_connection_setup_session_error_raises_exception(self):
        """Test connection when setup_session raises an exception."""
        with patch.object(
            AlibabacloudProvider,
            "setup_session",
            side_effect=AlibabaCloudSetUpSessionError(
                file="test_file",
                original_exception=Exception("Simulated setup error"),
            ),
        ):
            with pytest.raises(AlibabaCloudSetUpSessionError) as exception:
                AlibabacloudProvider.test_connection(
                    access_key_id="LTAI1234567890",
                    access_key_secret="test-secret-key",
                    raise_on_exception=True,
                )

            assert exception.type == AlibabaCloudSetUpSessionError

    def test_test_connection_setup_session_error_no_raise(self):
        """Test connection when setup_session raises an exception without raising."""
        setup_error = AlibabaCloudSetUpSessionError(
            file="test_file",
            original_exception=Exception("Simulated setup error"),
        )

        with patch.object(
            AlibabacloudProvider,
            "setup_session",
            side_effect=setup_error,
        ):
            result = AlibabacloudProvider.test_connection(
                access_key_id="LTAI1234567890",
                access_key_secret="test-secret-key",
                raise_on_exception=False,
            )

            assert isinstance(result, Connection)
            assert result.is_connected is False
            assert result.error is setup_error

    def test_test_connection_invalid_credentials_raises_exception(self):
        """Test connection when validate_credentials raises an exception."""
        mock_session = MagicMock()

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ),
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                side_effect=AlibabaCloudInvalidCredentialsError(
                    file="test_file",
                    original_exception=Exception("Invalid credentials"),
                ),
            ),
        ):
            with pytest.raises(AlibabaCloudInvalidCredentialsError) as exception:
                AlibabacloudProvider.test_connection(
                    access_key_id="LTAI-invalid",
                    access_key_secret="invalid-secret",
                    raise_on_exception=True,
                )

            assert exception.type == AlibabaCloudInvalidCredentialsError

    def test_test_connection_invalid_credentials_no_raise(self):
        """Test connection when validate_credentials raises an exception without raising."""
        mock_session = MagicMock()
        auth_error = AlibabaCloudInvalidCredentialsError(
            file="test_file",
            original_exception=Exception("Invalid credentials"),
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ),
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                side_effect=auth_error,
            ),
        ):
            result = AlibabacloudProvider.test_connection(
                access_key_id="LTAI-invalid",
                access_key_secret="invalid-secret",
                raise_on_exception=False,
            )

            assert isinstance(result, Connection)
            assert result.is_connected is False
            assert result.error is auth_error

    def test_test_connection_generic_exception_raises(self):
        """Test connection when a generic exception occurs."""
        mock_session = MagicMock()

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ),
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                side_effect=Exception("Unexpected error"),
            ),
        ):
            with pytest.raises(Exception) as exception:
                AlibabacloudProvider.test_connection(
                    access_key_id="LTAI1234567890",
                    access_key_secret="test-secret-key",
                    raise_on_exception=True,
                )

            assert str(exception.value) == "Unexpected error"

    def test_test_connection_generic_exception_no_raise(self):
        """Test connection when a generic exception occurs without raising."""
        mock_session = MagicMock()
        generic_error = Exception("Unexpected error")

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ),
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                side_effect=generic_error,
            ),
        ):
            result = AlibabacloudProvider.test_connection(
                access_key_id="LTAI1234567890",
                access_key_secret="test-secret-key",
                raise_on_exception=False,
            )

            assert isinstance(result, Connection)
            assert result.is_connected is False
            assert result.error is generic_error

    def test_test_connection_passes_credentials_to_setup_session(self):
        """Test that credentials are passed directly to setup_session."""
        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:user/test-user",
            identity_type="RamUser",
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                return_value=mock_caller_identity,
            ),
        ):
            result = AlibabacloudProvider.test_connection(
                access_key_id="LTAI1234567890",
                access_key_secret="test-secret-key",
                security_token="test-token",
                raise_on_exception=False,
            )

            assert result.is_connected is True

            # Verify credentials are passed directly to setup_session
            mock_setup_session.assert_called_once_with(
                role_arn=None,
                role_session_name=None,
                ecs_ram_role=None,
                oidc_role_arn=None,
                credentials_uri=None,
                access_key_id="LTAI1234567890",
                access_key_secret="test-secret-key",
                security_token="test-token",
            )

    def test_test_connection_does_not_set_environment_variables(self):
        """Test that test_connection does not set environment variables."""
        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:user/test-user",
            identity_type="RamUser",
        )

        # Ensure env vars don't exist before the test
        for var in [
            "ALIBABA_CLOUD_ACCESS_KEY_ID",
            "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
            "ALIBABA_CLOUD_SECURITY_TOKEN",
        ]:
            if var in os.environ:
                del os.environ[var]

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ),
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                return_value=mock_caller_identity,
            ),
        ):
            result = AlibabacloudProvider.test_connection(
                access_key_id="LTAI1234567890",
                access_key_secret="test-secret-key",
                security_token="test-token",
                raise_on_exception=False,
            )

            assert result.is_connected is True

            # Verify environment variables are not set
            assert "ALIBABA_CLOUD_ACCESS_KEY_ID" not in os.environ
            assert "ALIBABA_CLOUD_ACCESS_KEY_SECRET" not in os.environ
            assert "ALIBABA_CLOUD_SECURITY_TOKEN" not in os.environ

    def test_test_connection_with_ecs_ram_role(self):
        """Test successful connection with ECS RAM role."""
        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:role/ECS-Prowler-Role",
            identity_type="AssumedRoleUser",
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                return_value=mock_caller_identity,
            ),
        ):
            result = AlibabacloudProvider.test_connection(
                ecs_ram_role="ECS-Prowler-Role",
                raise_on_exception=False,
            )

            assert isinstance(result, Connection)
            assert result.is_connected is True
            assert result.error is None
            mock_setup_session.assert_called_once_with(
                role_arn=None,
                role_session_name=None,
                ecs_ram_role="ECS-Prowler-Role",
                oidc_role_arn=None,
                credentials_uri=None,
                access_key_id=None,
                access_key_secret=None,
                security_token=None,
            )

    def test_test_connection_with_oidc_role_arn(self):
        """Test successful connection with OIDC role ARN."""
        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:role/OIDCRole",
            identity_type="AssumedRoleUser",
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                return_value=mock_caller_identity,
            ),
        ):
            result = AlibabacloudProvider.test_connection(
                oidc_role_arn="acs:ram::1234567890:role/OIDCRole",
                raise_on_exception=False,
            )

            assert isinstance(result, Connection)
            assert result.is_connected is True
            assert result.error is None
            mock_setup_session.assert_called_once_with(
                role_arn=None,
                role_session_name=None,
                ecs_ram_role=None,
                oidc_role_arn="acs:ram::1234567890:role/OIDCRole",
                credentials_uri=None,
                access_key_id=None,
                access_key_secret=None,
                security_token=None,
            )

    def test_test_connection_with_credentials_uri(self):
        """Test successful connection with credentials URI."""
        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:user/test-user",
            identity_type="RamUser",
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                return_value=mock_caller_identity,
            ),
        ):
            result = AlibabacloudProvider.test_connection(
                credentials_uri="http://localhost:8080/credentials",
                raise_on_exception=False,
            )

            assert isinstance(result, Connection)
            assert result.is_connected is True
            assert result.error is None
            mock_setup_session.assert_called_once_with(
                role_arn=None,
                role_session_name=None,
                ecs_ram_role=None,
                oidc_role_arn=None,
                credentials_uri="http://localhost:8080/credentials",
                access_key_id=None,
                access_key_secret=None,
                security_token=None,
            )

    def test_test_connection_without_any_credentials(self):
        """Test connection without any credentials uses default credential chain."""
        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:user/test-user",
            identity_type="RamUser",
        )

        with (
            patch.object(
                AlibabacloudProvider,
                "setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch.object(
                AlibabacloudProvider,
                "validate_credentials",
                return_value=mock_caller_identity,
            ),
        ):
            result = AlibabacloudProvider.test_connection(
                raise_on_exception=False,
            )

            assert isinstance(result, Connection)
            assert result.is_connected is True
            assert result.error is None
            # Should call setup_session with all None values
            mock_setup_session.assert_called_once_with(
                role_arn=None,
                role_session_name=None,
                ecs_ram_role=None,
                oidc_role_arn=None,
                credentials_uri=None,
                access_key_id=None,
                access_key_secret=None,
                security_token=None,
            )

    def test_test_connection_preserves_existing_env_vars(self):
        """Test that existing environment variables are not affected by test_connection."""
        # Set up existing env vars
        original_key = "original-key-id"
        os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"] = original_key

        mock_session = MagicMock()
        mock_caller_identity = AlibabaCloudCallerIdentity(
            account_id="1234567890",
            principal_id="123456",
            arn="acs:ram::1234567890:user/test-user",
            identity_type="RamUser",
        )

        try:
            with (
                patch.object(
                    AlibabacloudProvider,
                    "setup_session",
                    return_value=mock_session,
                ),
                patch.object(
                    AlibabacloudProvider,
                    "validate_credentials",
                    return_value=mock_caller_identity,
                ),
            ):
                result = AlibabacloudProvider.test_connection(
                    access_key_id="LTAI1234567890",
                    access_key_secret="test-secret-key",
                    raise_on_exception=False,
                )

                assert result.is_connected is True
                # Verify test_connection does not modify existing env vars
                # (credentials are passed directly to setup_session, not via env vars)
                assert os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID") == original_key
        finally:
            # Clean up
            if "ALIBABA_CLOUD_ACCESS_KEY_ID" in os.environ:
                del os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"]
