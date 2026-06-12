from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.azure.lib.service.service import AzureService
from prowler.providers.azure.models import AzureIdentityInfo, AzureRegionConfig

REGION_CASES = [
    (
        "AzureCloud",
        "https://graph.microsoft.com",
        "https://graph.microsoft.com/.default",
        "https://api.loganalytics.io",
    ),
    (
        "AzureChinaCloud",
        "https://microsoftgraph.chinacloudapi.cn",
        "https://microsoftgraph.chinacloudapi.cn/.default",
        "https://api.loganalytics.azure.cn",
    ),
    (
        "AzureUSGovernment",
        "https://graph.microsoft.us",
        "https://graph.microsoft.us/.default",
        "https://api.loganalytics.us",
    ),
]


def _identity_and_session():
    identity = AzureIdentityInfo(
        tenant_domain="tenant.onmicrosoft.com",
        subscriptions={"sub-1": "Subscription 1"},
    )
    session = MagicMock()
    return identity, session


class TestAzureServiceSovereignClouds:
    """Cover __set_clients__ kwargs for the Graph and Logs clients across the
    three sovereign clouds — these are the two service slots in service.py
    that historically defaulted to public-cloud endpoints."""

    @pytest.mark.parametrize(
        "_region,graph_host,graph_scope,_logs_endpoint",
        REGION_CASES,
    )
    def test_set_clients_graph_uses_per_cloud_host_scope_and_adapter(
        self, _region, graph_host, graph_scope, _logs_endpoint
    ):
        graph_service = MagicMock()
        graph_service.__str__ = MagicMock(return_value="GraphServiceClient")
        region_config = AzureRegionConfig(
            graph_host=graph_host,
            graph_scope=graph_scope,
            logs_endpoint=_logs_endpoint,
        )
        identity, session = _identity_and_session()

        with (
            patch.object(AzureService, "__init__", return_value=None),
            patch(
                "prowler.providers.azure.lib.service.service.AzureIdentityAuthenticationProvider"
            ) as mock_auth_provider_cls,
            patch(
                "prowler.providers.azure.lib.service.service.GraphClientFactory"
            ) as mock_factory,
            patch(
                "prowler.providers.azure.lib.service.service.GraphRequestAdapter"
            ) as mock_adapter_cls,
        ):
            service = AzureService.__new__(AzureService)
            service.__set_clients__(identity, session, graph_service, region_config)

        mock_auth_provider_cls.assert_called_once_with(session, scopes=[graph_scope])
        mock_factory.create_with_default_middleware.assert_called_once_with(
            host=graph_host
        )
        mock_adapter_cls.assert_called_once_with(
            mock_auth_provider_cls.return_value,
            client=mock_factory.create_with_default_middleware.return_value,
        )
        graph_service.assert_called_once_with(
            request_adapter=mock_adapter_cls.return_value
        )

    @pytest.mark.parametrize(
        "_region,_graph_host,_graph_scope,logs_endpoint",
        REGION_CASES,
    )
    def test_set_clients_logs_passes_per_cloud_endpoint(
        self, _region, _graph_host, _graph_scope, logs_endpoint
    ):
        logs_service = MagicMock()
        logs_service.__str__ = MagicMock(return_value="LogsQueryClient")
        region_config = AzureRegionConfig(
            graph_host=_graph_host,
            graph_scope=_graph_scope,
            logs_endpoint=logs_endpoint,
        )
        identity, session = _identity_and_session()

        with patch.object(AzureService, "__init__", return_value=None):
            service = AzureService.__new__(AzureService)

        service.__set_clients__(identity, session, logs_service, region_config)

        logs_service.assert_called_once_with(credential=session, endpoint=logs_endpoint)
