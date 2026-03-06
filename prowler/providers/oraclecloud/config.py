"""OCI Provider Configuration Constants"""

# Default OCI Configuration
OCI_DEFAULT_CONFIG_FILE = "~/.oci/config"
OCI_DEFAULT_PROFILE = "DEFAULT"

# OCI Session Configuration
OCI_MAX_RETRIES = 3
OCI_TIMEOUT = 60

# OCI User Agent
OCI_USER_AGENT = "Prowler"

# OCI Regions - Commercial Regions
OCI_COMMERCIAL_REGIONS = {
    "af-casablanca-1": "af-casablanca-1",
    "af-johannesburg-1": "af-johannesburg-1",
    "ap-batam-1": "ap-batam-1",
    "ap-chuncheon-1": "ap-chuncheon-1",
    "ap-hyderabad-1": "ap-hyderabad-1",
    "ap-kulai-2": "ap-kulai-2",
    "ap-melbourne-1": "ap-melbourne-1",
    "ap-mumbai-1": "ap-mumbai-1",
    "ap-osaka-1": "ap-osaka-1",
    "ap-seoul-1": "ap-seoul-1",
    "ap-singapore-1": "ap-singapore-1",
    "ap-singapore-2": "ap-singapore-2",
    "ap-sydney-1": "ap-sydney-1",
    "ap-tokyo-1": "ap-tokyo-1",
    "ca-montreal-1": "ca-montreal-1",
    "ca-toronto-1": "ca-toronto-1",
    "eu-amsterdam-1": "eu-amsterdam-1",
    "eu-frankfurt-1": "eu-frankfurt-1",
    "eu-madrid-1": "eu-madrid-1",
    "eu-madrid-3": "eu-madrid-3",
    "eu-marseille-1": "eu-marseille-1",
    "eu-milan-1": "eu-milan-1",
    "eu-paris-1": "eu-paris-1",
    "eu-stockholm-1": "eu-stockholm-1",
    "eu-turin-1": "eu-turin-1",
    "eu-zurich-1": "eu-zurich-1",
    "il-jerusalem-1": "il-jerusalem-1",
    "me-abudhabi-1": "me-abudhabi-1",
    "me-dubai-1": "me-dubai-1",
    "me-jeddah-1": "me-jeddah-1",
    "me-riyadh-1": "me-riyadh-1",
    "mx-monterrey-1": "mx-monterrey-1",
    "mx-queretaro-1": "mx-queretaro-1",
    "sa-bogota-1": "sa-bogota-1",
    "sa-santiago-1": "sa-santiago-1",
    "sa-saopaulo-1": "sa-saopaulo-1",
    "sa-valparaiso-1": "sa-valparaiso-1",
    "sa-vinhedo-1": "sa-vinhedo-1",
    "uk-cardiff-1": "uk-cardiff-1",
    "uk-london-1": "uk-london-1",
    "us-ashburn-1": "us-ashburn-1",
    "us-chicago-1": "us-chicago-1",
    "us-phoenix-1": "us-phoenix-1",
    "us-sanjose-1": "us-sanjose-1",
}

# OCI Government Regions
OCI_GOVERNMENT_REGIONS = {
    "us-langley-1": "US Gov West",
    "us-luke-1": "US Gov East",
}

# All OCI Regions
OCI_REGIONS = {**OCI_COMMERCIAL_REGIONS, **OCI_GOVERNMENT_REGIONS}
