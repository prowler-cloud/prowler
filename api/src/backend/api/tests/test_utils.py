from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
from rest_framework.exceptions import ValidationError, NotFound

from api.db_router import MainRouter
from api.exceptions import InvitationTokenExpiredException
from api.models import Invitation
from api.models import Provider
from api.utils import (
    merge_dicts,
    return_prowler_provider,
    initialize_prowler_provider,
    prowler_provider_connection_test,
    get_prowler_provider_kwargs,
)
from api.utils import validate_invitation


class TestMergeDicts:
    def test_simple_merge(self):
        default_dict = {"key1": "value1", "key2": "value2"}
        replacement_dict = {"key2": "new_value2", "key3": "value3"}
        expected_result = {"key1": "value1", "key2": "new_value2", "key3": "value3"}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_nested_merge(self):
        default_dict = {
            "key1": "value1",
            "key2": {"nested_key1": "nested_value1", "nested_key2": "nested_value2"},
        }
        replacement_dict = {
            "key2": {
                "nested_key2": "new_nested_value2",
                "nested_key3": "nested_value3",
            },
            "key3": "value3",
        }
        expected_result = {
            "key1": "value1",
            "key2": {
                "nested_key1": "nested_value1",
                "nested_key2": "new_nested_value2",
                "nested_key3": "nested_value3",
            },
            "key3": "value3",
        }

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_no_overlap(self):
        default_dict = {"key1": "value1"}
        replacement_dict = {"key2": "value2"}
        expected_result = {"key1": "value1", "key2": "value2"}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_replacement_dict_empty(self):
        default_dict = {"key1": "value1", "key2": "value2"}
        replacement_dict = {}
        expected_result = {"key1": "value1", "key2": "value2"}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_default_dict_empty(self):
        default_dict = {}
        replacement_dict = {"key1": "value1", "key2": "value2"}
        expected_result = {"key1": "value1", "key2": "value2"}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_nested_empty_in_replacement_dict(self):
        default_dict = {"key1": {"nested_key1": "nested_value1"}}
        replacement_dict = {"key1": {}}
        expected_result = {"key1": {}}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_deep_nested_merge(self):
        default_dict = {"key1": {"nested_key1": {"deep_key1": "deep_value1"}}}
        replacement_dict = {"key1": {"nested_key1": {"deep_key1": "new_deep_value1"}}}
        expected_result = {"key1": {"nested_key1": {"deep_key1": "new_deep_value1"}}}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result


class TestReturnProwlerProvider:
    @pytest.mark.parametrize(
        "provider_type, expected_provider",
        [
            (Provider.ProviderChoices.AWS.value, AwsProvider),
            (Provider.ProviderChoices.GCP.value, GcpProvider),
            (Provider.ProviderChoices.AZURE.value, AzureProvider),
            (Provider.ProviderChoices.KUBERNETES.value, KubernetesProvider),
        ],
    )
    def test_return_prowler_provider(self, provider_type, expected_provider):
        provider = MagicMock()
        provider.provider = provider_type
        prowler_provider = return_prowler_provider(provider)
        assert prowler_provider == expected_provider

    def test_return_prowler_provider_unsupported_provider(self):
        provider = MagicMock()
        provider.provider = "UNSUPPORTED_PROVIDER"
        with pytest.raises(ValueError):
            return return_prowler_provider(provider)


class TestInitializeProwlerProvider:
    @patch("api.utils.return_prowler_provider")
    def test_initialize_prowler_provider(self, mock_return_prowler_provider):
        provider = MagicMock()
        provider.secret.secret = {"key": "value"}
        mock_return_prowler_provider.return_value = MagicMock()

        initialize_prowler_provider(provider)
        mock_return_prowler_provider.return_value.assert_called_once_with(key="value")


class TestProwlerProviderConnectionTest:
    @patch("api.utils.return_prowler_provider")
    def test_prowler_provider_connection_test(self, mock_return_prowler_provider):
        provider = MagicMock()
        provider.uid = "1234567890"
        provider.secret.secret = {"key": "value"}
        mock_return_prowler_provider.return_value = MagicMock()

        prowler_provider_connection_test(provider)
        mock_return_prowler_provider.return_value.test_connection.assert_called_once_with(
            key="value", provider_id="1234567890", raise_on_exception=False
        )


class TestGetProwlerProviderKwargs:
    @pytest.mark.parametrize(
        "provider_type, expected_extra_kwargs",
        [
            (
                Provider.ProviderChoices.AWS.value,
                {},
            ),
            (
                Provider.ProviderChoices.AZURE.value,
                {"subscription_ids": ["provider_uid"]},
            ),
            (
                Provider.ProviderChoices.GCP.value,
                {"project_ids": ["provider_uid"]},
            ),
            (
                Provider.ProviderChoices.KUBERNETES.value,
                {"context": "provider_uid"},
            ),
        ],
    )
    def test_get_prowler_provider_kwargs(self, provider_type, expected_extra_kwargs):
        provider_uid = "provider_uid"
        secret_dict = {"key": "value"}
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        provider = MagicMock()
        provider.provider = provider_type
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider)

        expected_result = {**secret_dict, **expected_extra_kwargs}
        assert result == expected_result

    def test_get_prowler_provider_kwargs_unsupported_provider(self):
        # Setup
        provider_uid = "provider_uid"
        secret_dict = {"key": "value"}
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        provider = MagicMock()
        provider.provider = "UNSUPPORTED_PROVIDER"
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider)

        expected_result = secret_dict.copy()
        assert result == expected_result

    def test_get_prowler_provider_kwargs_no_secret(self):
        # Setup
        provider_uid = "provider_uid"
        secret_mock = MagicMock()
        secret_mock.secret = {}

        provider = MagicMock()
        provider.provider = Provider.ProviderChoices.AWS.value
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider)

        expected_result = {}
        assert result == expected_result


class TestValidateInvitation:
    @pytest.fixture
    def invitation(self):
        invitation = MagicMock(spec=Invitation)
        invitation.token = "VALID_TOKEN"
        invitation.email = "user@example.com"
        invitation.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        invitation.state = Invitation.State.PENDING
        invitation.tenant = MagicMock()
        return invitation

    def test_valid_invitation(self, invitation):
        with patch("api.utils.Invitation.objects.using") as mock_using:
            mock_db = mock_using.return_value
            mock_db.get.return_value = invitation

            result = validate_invitation("VALID_TOKEN", "user@example.com")

            assert result == invitation
            mock_db.get.assert_called_once_with(
                token="VALID_TOKEN", email="user@example.com"
            )

    def test_invitation_not_found_raises_validation_error(self):
        with patch("api.utils.Invitation.objects.using") as mock_using:
            mock_db = mock_using.return_value
            mock_db.get.side_effect = Invitation.DoesNotExist

            with pytest.raises(ValidationError) as exc_info:
                validate_invitation("INVALID_TOKEN", "user@example.com")

            assert exc_info.value.detail == {
                "invitation_token": "Invalid invitation code."
            }
            mock_db.get.assert_called_once_with(
                token="INVALID_TOKEN", email="user@example.com"
            )

    def test_invitation_not_found_raises_not_found(self):
        with patch("api.utils.Invitation.objects.using") as mock_using:
            mock_db = mock_using.return_value
            mock_db.get.side_effect = Invitation.DoesNotExist

            with pytest.raises(NotFound) as exc_info:
                validate_invitation(
                    "INVALID_TOKEN", "user@example.com", raise_not_found=True
                )

            assert exc_info.value.detail == "Invitation is not valid."
            mock_db.get.assert_called_once_with(
                token="INVALID_TOKEN", email="user@example.com"
            )

    def test_invitation_expired(self, invitation):
        expired_time = datetime.now(timezone.utc) - timedelta(days=1)
        invitation.expires_at = expired_time

        with patch("api.utils.Invitation.objects.using") as mock_using, patch(
            "api.utils.datetime"
        ) as mock_datetime:
            mock_db = mock_using.return_value
            mock_db.get.return_value = invitation
            mock_datetime.now.return_value = datetime.now(timezone.utc)

            with pytest.raises(InvitationTokenExpiredException):
                validate_invitation("VALID_TOKEN", "user@example.com")

            # Ensure the invitation state was updated to EXPIRED
            assert invitation.state == Invitation.State.EXPIRED
            invitation.save.assert_called_once_with(using=MainRouter.admin_db)

    def test_invitation_not_pending(self, invitation):
        invitation.state = Invitation.State.ACCEPTED

        with patch("api.utils.Invitation.objects.using") as mock_using:
            mock_db = mock_using.return_value
            mock_db.get.return_value = invitation

            with pytest.raises(ValidationError) as exc_info:
                validate_invitation("VALID_TOKEN", "user@example.com")

            assert exc_info.value.detail == {
                "invitation_token": "This invitation is no longer valid."
            }

    def test_invitation_with_different_email(self):
        with patch("api.utils.Invitation.objects.using") as mock_using:
            mock_db = mock_using.return_value
            mock_db.get.side_effect = Invitation.DoesNotExist

            with pytest.raises(ValidationError) as exc_info:
                validate_invitation("VALID_TOKEN", "different@example.com")

            assert exc_info.value.detail == {
                "invitation_token": "Invalid invitation code."
            }
            mock_db.get.assert_called_once_with(
                token="VALID_TOKEN", email="different@example.com"
            )
