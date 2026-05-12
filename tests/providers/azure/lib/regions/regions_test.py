from azure.identity import AzureAuthorityHosts

from prowler.providers.azure.lib.regions.regions import (
    AZURE_CHINA_CLOUD,
    AZURE_CHINA_GRAPH_SCOPE,
    AZURE_CHINA_LOGS_ENDPOINT,
    AZURE_GENERIC_CLOUD,
    AZURE_GENERIC_GRAPH_SCOPE,
    AZURE_GENERIC_LOGS_ENDPOINT,
    AZURE_US_GOV_CLOUD,
    AZURE_US_GOV_GRAPH_SCOPE,
    AZURE_US_GOV_LOGS_ENDPOINT,
    get_regions_config,
)


class Test_azure_regions:
    def test_get_regions_config(self):
        allowed_regions = [
            "AzureCloud",
            "AzureChinaCloud",
            "AzureUSGovernment",
        ]
        expected_output = {
            "AzureCloud": {
                "authority": None,
                "base_url": AZURE_GENERIC_CLOUD,
                "credential_scopes": [AZURE_GENERIC_CLOUD + "/.default"],
                "graph_scope": AZURE_GENERIC_GRAPH_SCOPE,
                "logs_endpoint": AZURE_GENERIC_LOGS_ENDPOINT,
            },
            "AzureChinaCloud": {
                "authority": AzureAuthorityHosts.AZURE_CHINA,
                "base_url": AZURE_CHINA_CLOUD,
                "credential_scopes": [AZURE_CHINA_CLOUD + "/.default"],
                "graph_scope": AZURE_CHINA_GRAPH_SCOPE,
                "logs_endpoint": AZURE_CHINA_LOGS_ENDPOINT,
            },
            "AzureUSGovernment": {
                "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
                "base_url": AZURE_US_GOV_CLOUD,
                "credential_scopes": [AZURE_US_GOV_CLOUD + "/.default"],
                "graph_scope": AZURE_US_GOV_GRAPH_SCOPE,
                "logs_endpoint": AZURE_US_GOV_LOGS_ENDPOINT,
            },
        }

        for region in allowed_regions:
            region_config = get_regions_config(region)
            assert region_config == expected_output[region]
