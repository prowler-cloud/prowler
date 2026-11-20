import re

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


def get_regions_config(region: str, region_endpoints: dict | None = None) -> dict:
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
    if region == "M365Custom":
        return get_custom_region_config(region_endpoints)
    return allowed_regions[region]


def get_custom_region_config(region_endpoints: dict | None) -> dict:
    """Build the M365Custom region configuration from the operator-supplied endpoints.

    Each endpoint is a host or an https:// URL, with an optional port and trailing slash.
    """
    hosts = {}
    for key in ("authority_host", "graph"):
        value = (region_endpoints or {}).get(key)
        if not value:
            continue
        host = value.strip()
        if host.lower().startswith("https://"):
            host = host[len("https://") :]
        host = host.removesuffix("/")
        if not re.fullmatch(r"[A-Za-z0-9.-]+(:[0-9]+)?", host):
            raise ValueError(
                f"Region M365Custom endpoint {key} must be a host or an https:// URL: {value}"
            )
        hosts[key] = host
    missing_endpoints = [key for key in ("authority_host", "graph") if key not in hosts]
    if missing_endpoints:
        raise ValueError(
            f"Region M365Custom requires these endpoints: {', '.join(missing_endpoints)}"
        )
    base_url = f"https://{hosts['graph']}"
    return {
        # azure-identity takes the authority as a bare host, like AzureAuthorityHosts
        "authority": hosts["authority_host"],
        "base_url": base_url,
        "credential_scopes": [base_url + "/.default"],
    }
