from azure.identity import AzureAuthorityHosts

MICROSOFT365_CHINA_CLOUD = "https://microsoftgraph.chinacloudapi.cn"
MICROSOFT365_US_GOV_CLOUD = "https://graph.microsoft.us"
MICROSOFT365_US_DOD_CLOUD = "https://graph.microsoftmil.us"
MICROSOFT365_GENERIC_CLOUD = "https://graph.microsoft.com"

# PowerShell values per cloud
POWERSHELL_GENERIC_CLOUD = {
    "exchange_environment": None,
    "exchange_scope": "https://outlook.office365.com/.default",
    "teams_environment": None,
}
POWERSHELL_CHINA_CLOUD = {
    "exchange_environment": "O365China",
    "exchange_scope": "https://partner.outlook.cn/.default",
    "teams_environment": "TeamsChina",
}
# M365USGovernment is GCC High (graph.microsoft.us), not DoD
POWERSHELL_US_GOV_CLOUD = {
    "exchange_environment": "O365USGovGCCHigh",
    "exchange_scope": "https://outlook.office365.us/.default",
    "teams_environment": "TeamsGCCH",
}


def get_regions_config(region):
    allowed_regions = {
        "M365Global": {
            "authority": None,
            "base_url": MICROSOFT365_GENERIC_CLOUD,
            "credential_scopes": [MICROSOFT365_GENERIC_CLOUD + "/.default"],
            "powershell": POWERSHELL_GENERIC_CLOUD,
        },
        "M365China": {
            "authority": AzureAuthorityHosts.AZURE_CHINA,
            "base_url": MICROSOFT365_CHINA_CLOUD,
            "credential_scopes": [MICROSOFT365_CHINA_CLOUD + "/.default"],
            "powershell": POWERSHELL_CHINA_CLOUD,
        },
        "M365USGovernment": {
            "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
            "base_url": MICROSOFT365_US_GOV_CLOUD,
            "credential_scopes": [MICROSOFT365_US_GOV_CLOUD + "/.default"],
            "powershell": POWERSHELL_US_GOV_CLOUD,
        },
    }
    return allowed_regions[region]
