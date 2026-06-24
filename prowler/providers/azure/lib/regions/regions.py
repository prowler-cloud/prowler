from azure.identity import AzureAuthorityHosts

AZURE_CHINA_CLOUD = "https://management.chinacloudapi.cn"
AZURE_US_GOV_CLOUD = "https://management.usgovcloudapi.net"
AZURE_GENERIC_CLOUD = "https://management.azure.com"

AZURE_GENERIC_GRAPH_HOST = "https://graph.microsoft.com"
AZURE_CHINA_GRAPH_HOST = "https://microsoftgraph.chinacloudapi.cn"
AZURE_US_GOV_GRAPH_HOST = "https://graph.microsoft.us"

AZURE_GENERIC_GRAPH_SCOPE = f"{AZURE_GENERIC_GRAPH_HOST}/.default"
AZURE_CHINA_GRAPH_SCOPE = f"{AZURE_CHINA_GRAPH_HOST}/.default"
AZURE_US_GOV_GRAPH_SCOPE = f"{AZURE_US_GOV_GRAPH_HOST}/.default"

AZURE_GENERIC_LOGS_ENDPOINT = "https://api.loganalytics.io"
AZURE_CHINA_LOGS_ENDPOINT = "https://api.loganalytics.azure.cn"
AZURE_US_GOV_LOGS_ENDPOINT = "https://api.loganalytics.us"


def get_regions_config(region):
    allowed_regions = {
        "AzureCloud": {
            "authority": None,
            "base_url": AZURE_GENERIC_CLOUD,
            "credential_scopes": [AZURE_GENERIC_CLOUD + "/.default"],
            "graph_host": AZURE_GENERIC_GRAPH_HOST,
            "graph_scope": AZURE_GENERIC_GRAPH_SCOPE,
            "logs_endpoint": AZURE_GENERIC_LOGS_ENDPOINT,
        },
        "AzureChinaCloud": {
            "authority": AzureAuthorityHosts.AZURE_CHINA,
            "base_url": AZURE_CHINA_CLOUD,
            "credential_scopes": [AZURE_CHINA_CLOUD + "/.default"],
            "graph_host": AZURE_CHINA_GRAPH_HOST,
            "graph_scope": AZURE_CHINA_GRAPH_SCOPE,
            "logs_endpoint": AZURE_CHINA_LOGS_ENDPOINT,
        },
        "AzureUSGovernment": {
            "authority": AzureAuthorityHosts.AZURE_GOVERNMENT,
            "base_url": AZURE_US_GOV_CLOUD,
            "credential_scopes": [AZURE_US_GOV_CLOUD + "/.default"],
            "graph_host": AZURE_US_GOV_GRAPH_HOST,
            "graph_scope": AZURE_US_GOV_GRAPH_SCOPE,
            "logs_endpoint": AZURE_US_GOV_LOGS_ENDPOINT,
        },
    }
    return allowed_regions[region]
