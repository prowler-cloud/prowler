from prowler.lib.logger import logger

# MongoDB Atlas Provider Configuration

# Supported encryption providers
ATLAS_ENCRYPTION_PROVIDERS = ["AWS", "AZURE", "GCP", "NONE"]

# Network access configuration
ATLAS_OPEN_WORLD_CIDRS = ["0.0.0.0/0", "::/0"]

logger.info("MongoDB Atlas Provider configuration loaded")
