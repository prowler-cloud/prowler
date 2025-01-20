from azure.identity import AzureAuthorityHosts

MICROSOFT365_CHINA_CLOUD = "https://microsoftgraph.chinacloudapi.cn"
MICROSOFT365_US_GOV_CLOUD = "https://graph.microsoft.us"
MICROSOFT365_US_DOD_CLOUD = "https://graph.microsoftmil.us"
MICROSOFT365_GENERIC_CLOUD = "https://graph.microsoft.com"


def get_regions_config(region):
    allowed_regions = {
        "Microsoft365Global": {
            "authority": None,
            "base_url": MICROSOFT365_GENERIC_CLOUD,
            "credential_scopes": [MICROSOFT365_GENERIC_CLOUD + "/.default"],
        },
        "Microsoft365China": {
            "authority": AzureAuthorityHosts.AZURE_CHINA,
            "base_url": MICROSOFT365_CHINA_CLOUD,
            "credential_scopes": [MICROSOFT365_CHINA_CLOUD + "/.default"],
        },
        "Microsoft365USGovernment": {
            "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
            "base_url": MICROSOFT365_US_GOV_CLOUD,
            "credential_scopes": [MICROSOFT365_US_GOV_CLOUD + "/.default"],
        },
    }
    return allowed_regions[region]
