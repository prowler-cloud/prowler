from prowler.lib.logger import logger

# MongoDB Atlas Provider Configuration

# Default API version
ATLAS_API_VERSION = "2025-01-01"

# Default base URL
ATLAS_BASE_URL = "https://cloud.mongodb.com/api/atlas/v2"

# Default timeout for API requests (in seconds)
ATLAS_REQUEST_TIMEOUT = 30

# Default pagination settings
ATLAS_DEFAULT_PAGE_SIZE = 100
ATLAS_MAX_PAGES = 50

# Rate limiting settings
ATLAS_MAX_RETRIES = 3
ATLAS_RETRY_DELAY = 1

# Supported cluster types for encryption checks
ATLAS_CLUSTER_TYPES = ["REPLICASET", "SHARDED", "GEOSHARDED"]

# Supported encryption providers
ATLAS_ENCRYPTION_PROVIDERS = ["AWS", "AZURE", "GCP", "NONE"]

# Network access configuration
ATLAS_OPEN_WORLD_CIDRS = ["0.0.0.0/0", "::/0"]

logger.info("MongoDB Atlas Provider configuration loaded")
