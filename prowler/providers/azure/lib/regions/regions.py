import re

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

AZURE_CUSTOM_CLOUD = "AzureCustom"


def get_custom_region_config(region_endpoints: dict) -> dict:
    """Build the region configuration of a cloud Prowler has no built-in entry for.

    Args:
        region_endpoints (dict): Endpoints of the cloud, as shown by
            `az cloud show`. `authority_host`, `resource_manager` and `graph`
            are required and `logs` is optional. Each value is a host or an
            `https://` URL, with an optional port and trailing slash.

    Returns:
        dict: The same keys `get_regions_config` returns for a built-in cloud.
            `logs_endpoint` is None when `logs` is not given.

    Raises:
        ValueError: If a required endpoint is missing or an endpoint is not a
            host or an `https://` URL.
    """
    hosts = {}
    for name in ("authority_host", "resource_manager", "graph", "logs"):
        value = (region_endpoints or {}).get(name) or ""
        host = value.strip()
        if host[:8].lower() == "https://":
            host = host[8:]
        host = host.removesuffix("/")
        if host and not re.fullmatch(r"[A-Za-z0-9.-]+(:[0-9]+)?", host):
            raise ValueError(
                f"Region {AZURE_CUSTOM_CLOUD} endpoint {name} must be a host or an https:// URL: {value}"
            )
        hosts[name] = host
    missing = [
        name
        for name in ("authority_host", "resource_manager", "graph")
        if not hosts[name]
    ]
    if missing:
        raise ValueError(
            f"Region {AZURE_CUSTOM_CLOUD} requires these endpoints: {', '.join(missing)}"
        )

    resource_manager = f"https://{hosts['resource_manager']}"
    graph = f"https://{hosts['graph']}"
    return {
        # azure-identity takes the authority as a bare host, like AzureAuthorityHosts
        "authority": hosts["authority_host"],
        "base_url": resource_manager,
        "credential_scopes": [f"{resource_manager}/.default"],
        "graph_host": graph,
        "graph_scope": f"{graph}/.default",
        "logs_endpoint": f"https://{hosts['logs']}" if hosts["logs"] else None,
    }


def get_regions_config(region, region_endpoints: dict = None):
    if region == AZURE_CUSTOM_CLOUD:
        return get_custom_region_config(region_endpoints)
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
