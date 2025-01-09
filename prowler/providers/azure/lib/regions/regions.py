from azure.identity import AzureAuthorityHosts

AZURE_CHINA_CLOUD = "https://management.chinacloudapi.cn"
AZURE_US_GOV_CLOUD = "https://management.usgovcloudapi.net"
AZURE_GENERIC_CLOUD = "https://management.azure.com"


def get_regions_config(region):
    allowed_regions = {
        "AzureCloud": {
            "authority": None,
            "base_url": AZURE_GENERIC_CLOUD,
            "credential_scopes": [AZURE_GENERIC_CLOUD + "/.default"],
        },
        "AzureChinaCloud": {
            "authority": AzureAuthorityHosts.AZURE_CHINA,
            "base_url": AZURE_CHINA_CLOUD,
            "credential_scopes": [AZURE_CHINA_CLOUD + "/.default"],
        },
        "AzureUSGovernment": {
            "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
            "base_url": AZURE_US_GOV_CLOUD,
            "credential_scopes": [AZURE_US_GOV_CLOUD + "/.default"],
        },
    }
    return allowed_regions[region]
