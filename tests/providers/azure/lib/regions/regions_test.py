from azure.identity import AzureAuthorityHosts

from prowler.providers.azure.lib.regions.regions import (
    AZURE_CHINA_CLOUD,
    AZURE_GENERIC_CLOUD,
    AZURE_GRAPH_CHINA,
    AZURE_GRAPH_GLOBAL,
    AZURE_GRAPH_GOV_US_L4,
    AZURE_GRAPH_GOV_US_L5,
    AZURE_US_GOV_CLOUD,
    get_regions_config,
)


class Test_azure_regions:
    def test_get_regions_config(self):
        allowed_regions = [
            "AzureCloud",
            "AzureChinaCloud",
            "AzureUSGovernmentL4",
            "AzureUSGovernmentL5",
        ]
        expected_output = {
            "AzureCloud": {
                "authority": None,
                "base_url": AZURE_GENERIC_CLOUD,
                "credential_scopes": [AZURE_GENERIC_CLOUD + "/.default"],
                "graph_credential_scopes": [AZURE_GRAPH_GLOBAL],
            },
            "AzureChinaCloud": {
                "authority": AzureAuthorityHosts.AZURE_CHINA,
                "base_url": AZURE_CHINA_CLOUD,
                "credential_scopes": [AZURE_CHINA_CLOUD + "/.default"],
                "graph_credential_scopes": [AZURE_GRAPH_CHINA],
            },
            "AzureUSGovernmentL4": {
                "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
                "base_url": AZURE_US_GOV_CLOUD,
                "credential_scopes": [AZURE_US_GOV_CLOUD + "/.default"],
                "graph_credential_scopes": [AZURE_GRAPH_GOV_US_L4],
            },
            "AzureUSGovernmentL5": {
                "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
                "base_url": AZURE_US_GOV_CLOUD,
                "credential_scopes": [AZURE_US_GOV_CLOUD + "/.default"],
                "graph_credential_scopes": [AZURE_GRAPH_GOV_US_L5],
            },
        }

        for region in allowed_regions:
            region_config = get_regions_config(region)
            assert region_config == expected_output[region]
