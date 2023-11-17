from azure.identity import AzureAuthorityHosts
from msrestazure.azure_cloud import (
    AZURE_CHINA_CLOUD,
    AZURE_GERMAN_CLOUD,
    AZURE_US_GOV_CLOUD,
)

from prowler.providers.azure.lib.regions.regions import get_regions_config


class Test_azure_regions:
    def test_get_regions_config(self):
        allowed_regions = [
            "AzureCloud",
            "AzureChinaCloud",
            "AzureUSGovernment",
            "AzureGermanCloud",
        ]
        expected_output = {
            "AzureCloud": {
                "authority": None,
                "base_url": "https://management.azure.com",
                "credential_scopes": ["https://management.azure.com/.default"],
            },
            "AzureChinaCloud": {
                "authority": AzureAuthorityHosts.AZURE_CHINA,
                "base_url": AZURE_CHINA_CLOUD.endpoints.resource_manager,
                "credential_scopes": [
                    AZURE_CHINA_CLOUD.endpoints.resource_manager + "/.default"
                ],
            },
            "AzureUSGovernment": {
                "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
                "base_url": AZURE_US_GOV_CLOUD.endpoints.resource_manager,
                "credential_scopes": [
                    AZURE_US_GOV_CLOUD.endpoints.resource_manager + "/.default"
                ],
            },
            "AzureGermanCloud": {
                "authority": AzureAuthorityHosts.AZURE_GERMANY,
                "base_url": AZURE_GERMAN_CLOUD.endpoints.resource_manager,
                "credential_scopes": [
                    AZURE_GERMAN_CLOUD.endpoints.resource_manager + "/.default"
                ],
            },
        }

        for region in allowed_regions:
            region_config = get_regions_config(region)
            assert region_config == expected_output[region]
