from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.azure.lib.service.service import AzureService
from prowler.providers.azure.models import AzureIdentityInfo, AzureRegionConfig

REGION_CASES = [
    (
        "AzureCloud",
        "https://graph.microsoft.com/.default",
        "https://api.loganalytics.io",
    ),
    (
        "AzureChinaCloud",
        "https://microsoftgraph.chinacloudapi.cn/.default",
        "https://api.loganalytics.azure.cn",
    ),
    (
        "AzureUSGovernment",
        "https://graph.microsoft.us/.default",
        "https://api.loganalytics.us",
    ),
]


def _provider_mock(region_config: AzureRegionConfig):
    provider = MagicMock()
    provider.identity = AzureIdentityInfo(
        tenant_domain="tenant.onmicrosoft.com",
        subscriptions={"sub-1": "Subscription 1"},
    )
    provider.session = MagicMock()
    provider.audit_config = {}
    provider.fixer_config = {}
    provider.locations = {}
    provider.region_config = region_config
    return provider


class TestAzureServiceSovereignClouds:
    """Cover __set_clients__ kwargs for the Graph and Logs clients across the
    three sovereign clouds — these are the two service slots in service.py
    that historically defaulted to public-cloud endpoints."""

    @pytest.mark.parametrize(
        "_region,graph_scope,_logs_endpoint",
        REGION_CASES,
    )
    def test_set_clients_graph_passes_per_cloud_scope(
        self, _region, graph_scope, _logs_endpoint
    ):
        graph_service = MagicMock()
        graph_service.__str__ = MagicMock(return_value="GraphServiceClient")
        region_config = AzureRegionConfig(
            graph_scope=graph_scope,
            logs_endpoint=_logs_endpoint,
        )

        with patch.object(AzureService, "__init__", return_value=None):
            service = AzureService.__new__(AzureService)

        service.__set_clients__(
            _provider_mock(region_config).identity,
            _provider_mock(region_config).session,
            graph_service,
            region_config,
        )

        graph_service.assert_called_once()
        _, kwargs = graph_service.call_args
        assert kwargs["scopes"] == [graph_scope]

    @pytest.mark.parametrize(
        "_region,_graph_scope,logs_endpoint",
        REGION_CASES,
    )
    def test_set_clients_logs_passes_per_cloud_endpoint(
        self, _region, _graph_scope, logs_endpoint
    ):
        logs_service = MagicMock()
        logs_service.__str__ = MagicMock(return_value="LogsQueryClient")
        region_config = AzureRegionConfig(
            graph_scope=_graph_scope,
            logs_endpoint=logs_endpoint,
        )

        with patch.object(AzureService, "__init__", return_value=None):
            service = AzureService.__new__(AzureService)

        service.__set_clients__(
            _provider_mock(region_config).identity,
            _provider_mock(region_config).session,
            logs_service,
            region_config,
        )

        logs_service.assert_called_once()
        _, kwargs = logs_service.call_args
        assert kwargs["endpoint"] == logs_endpoint
