from unittest.mock import MagicMock, patch

import pytest
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider

from api.models import Provider
from api.utils import (
    merge_dicts,
    return_prowler_provider,
    initialize_prowler_provider,
    prowler_provider_connection_test,
)


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
