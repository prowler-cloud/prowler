from azure.identity import AzureAuthorityHosts

# Temp fix until azure-identity python sdk has built-in AuthorityHost value for Bleu FR Sov Cloud
AZURE_BLEU_FRSOV_AUTHORITY_HOST = "login.sovcloud-identity.fr"

AZURE_CHINA_CLOUD = "https://management.chinacloudapi.cn"
AZURE_US_GOV_CLOUD = "https://management.usgovcloudapi.net"
AZURE_BLEU_FRSOV_CLOUD = "https://management.sovcloud-api.fr"
AZURE_GENERIC_CLOUD = "https://management.azure.com"

AZURE_GENERIC_GRAPH_HOST = "https://graph.microsoft.com"
AZURE_CHINA_GRAPH_HOST = "https://microsoftgraph.chinacloudapi.cn"
AZURE_US_GOV_GRAPH_HOST = "https://graph.microsoft.us"
AZURE_BLEU_FRSOV_GRAPH_HOST = "https://graph.svc.sovcloud.fr"

AZURE_GENERIC_GRAPH_SCOPE = f"{AZURE_GENERIC_GRAPH_HOST}/.default"
AZURE_CHINA_GRAPH_SCOPE = f"{AZURE_CHINA_GRAPH_HOST}/.default"
AZURE_US_GOV_GRAPH_SCOPE = f"{AZURE_US_GOV_GRAPH_HOST}/.default"
AZURE_BLEU_FRSOV_GRAPH_SCOPE = f"{AZURE_BLEU_FRSOV_GRAPH_HOST}/.default"

AZURE_GENERIC_LOGS_ENDPOINT = "https://api.loganalytics.io"
AZURE_CHINA_LOGS_ENDPOINT = "https://api.loganalytics.azure.cn"
AZURE_US_GOV_LOGS_ENDPOINT = "https://api.loganalytics.us"
AZURE_BLEU_FRSOV_LOGS_ENDPOINT = "https://api.loganalytics.sovcloud-api.fr"


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
        "AzureBleuCloud": {
            # Bleu, French sovereign Azure cloud. More details https://bleucloud.fr
            "authority": AZURE_BLEU_FRSOV_AUTHORITY_HOST,
            "base_url": AZURE_BLEU_FRSOV_CLOUD,
            "credential_scopes": [AZURE_BLEU_FRSOV_CLOUD + "/.default"],
            "graph_host": AZURE_BLEU_FRSOV_GRAPH_HOST,
            "graph_scope": AZURE_BLEU_FRSOV_GRAPH_SCOPE,
            "logs_endpoint": AZURE_BLEU_FRSOV_LOGS_ENDPOINT,
        },
    }
    return allowed_regions[region]
