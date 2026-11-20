from unittest.mock import patch

from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


class Test_M365Service:
    def test_client_targets_the_region_graph_host(self):
        region_config = M365Provider.setup_region_config("M365USGovernment")
        provider = set_mocked_m365_provider(azure_region_config=region_config)

        with patch(
            "prowler.providers.m365.lib.service.service.M365PowerShell"
        ) as powershell:
            service = M365Service(provider)

        powershell.assert_called_once_with(
            provider.credentials, provider.identity, region_config
        )
        assert service.region_config == region_config
        assert (
            service.client.request_adapter.base_url
            == "https://graph.microsoft.us/v1.0/"
        )
