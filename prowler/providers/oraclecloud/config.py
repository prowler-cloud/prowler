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
    "ap-chuncheon-1": "South Korea Central (Chuncheon)",
    "ap-hyderabad-1": "India West (Hyderabad)",
    "ap-melbourne-1": "Australia Southeast (Melbourne)",
    "ap-mumbai-1": "India West (Mumbai)",
    "ap-osaka-1": "Japan Central (Osaka)",
    "ap-seoul-1": "South Korea North (Seoul)",
    "ap-singapore-1": "Singapore (Singapore)",
    "ap-sydney-1": "Australia East (Sydney)",
    "ap-tokyo-1": "Japan East (Tokyo)",
    "ca-montreal-1": "Canada Southeast (Montreal)",
    "ca-toronto-1": "Canada Southeast (Toronto)",
    "eu-amsterdam-1": "Netherlands Northwest (Amsterdam)",
    "eu-frankfurt-1": "Germany Central (Frankfurt)",
    "eu-madrid-1": "Spain Central (Madrid)",
    "eu-marseille-1": "France South (Marseille)",
    "eu-milan-1": "Italy Northwest (Milan)",
    "eu-paris-1": "France Central (Paris)",
    "eu-stockholm-1": "Sweden Central (Stockholm)",
    "eu-zurich-1": "Switzerland North (Zurich)",
    "il-jerusalem-1": "Israel Central (Jerusalem)",
    "me-abudhabi-1": "UAE East (Abu Dhabi)",
    "me-dubai-1": "UAE East (Dubai)",
    "me-jeddah-1": "Saudi Arabia West (Jeddah)",
    "mx-monterrey-1": "Mexico Northeast (Monterrey)",
    "mx-queretaro-1": "Mexico Central (Queretaro)",
    "sa-bogota-1": "Colombia (Bogota)",
    "sa-santiago-1": "Chile (Santiago)",
    "sa-saopaulo-1": "Brazil East (Sao Paulo)",
    "sa-valparaiso-1": "Chile West (Valparaiso)",
    "sa-vinhedo-1": "Brazil Southeast (Vinhedo)",
    "uk-cardiff-1": "UK West (Cardiff)",
    "uk-london-1": "UK South (London)",
    "us-ashburn-1": "US East (Ashburn)",
    "us-chicago-1": "US East (Chicago)",
    "us-phoenix-1": "US West (Phoenix)",
    "us-sanjose-1": "US West (San Jose)",
}

# OCI Government Regions
OCI_GOVERNMENT_REGIONS = {
    "us-langley-1": "US Gov West",
    "us-luke-1": "US Gov East",
}

# All OCI Regions
OCI_REGIONS = {**OCI_COMMERCIAL_REGIONS, **OCI_GOVERNMENT_REGIONS}
