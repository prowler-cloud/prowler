from azure.identity import AzureAuthorityHosts

AZURE_GENERIC_CLOUD = "https://management.azure.com"
AZURE_GRAPH_GLOBAL = "https://graph.microsoft.com"

AZURE_US_GOV_CLOUD = "https://management.usgovcloudapi.net"
AZURE_GRAPH_GOV_US_L4 = "https://graph.microsoft.us"
AZURE_GRAPH_GOV_US_L5 = "https://dod-graph.microsoft.us"

AZURE_CHINA_CLOUD = "https://management.chinacloudapi.cn"
AZURE_GRAPH_CHINA = "https://microsoftgraph.chinacloudapi.cn"


def get_regions_config(region):
    allowed_regions = {
        "AzureCloud": {
            "authority": AzureAuthorityHosts.AZURE_PUBLIC_CLOUD,
            "base_url": AZURE_GENERIC_CLOUD,
            "credential_scopes": [AZURE_GENERIC_CLOUD + "/.default"],
            "graph_credential_scopes": [AZURE_GRAPH_GLOBAL + "/.default"],
            "graph_base_url": AZURE_GRAPH_GLOBAL,
        },
        "AzureChinaCloud": {
            "authority": AzureAuthorityHosts.AZURE_CHINA,
            "base_url": AZURE_CHINA_CLOUD,
            "credential_scopes": [AZURE_CHINA_CLOUD + "/.default"],
            "graph_credential_scopes": [AZURE_GRAPH_CHINA + "/.default"],
            "graph_base_url": AZURE_GRAPH_CHINA,
        },
        "AzureUSGovernmentL4": {
            "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
            "base_url": AZURE_US_GOV_CLOUD,
            "credential_scopes": [AZURE_US_GOV_CLOUD + "/.default"],
            "graph_credential_scopes": [AZURE_GRAPH_GOV_US_L4 + "/.default"],
            "graph_base_url": AZURE_GRAPH_GOV_US_L4,
        },
        "AzureUSGovernmentL5": {
            "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
            "base_url": AZURE_US_GOV_CLOUD,
            "credential_scopes": [AZURE_US_GOV_CLOUD + "/.default"],
            "graph_credential_scopes": [AZURE_GRAPH_GOV_US_L5 + "/.default"],
            "graph_base_url": AZURE_GRAPH_GOV_US_L5,
        },
    }
    return allowed_regions[region]
