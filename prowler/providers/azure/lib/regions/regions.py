from azure.identity import AzureAuthorityHosts
from msrestazure.azure_cloud import (
    AZURE_CHINA_CLOUD,
    AZURE_GERMAN_CLOUD,
    AZURE_US_GOV_CLOUD,
)


def get_regions_config(region):
    allowed_regions = {
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
    return allowed_regions[region]
