import math
from config.env import env

# Partitioning
PSQLEXTRA_PARTITIONING_MANAGER = "api.partitions.manager"

# Set the months for each partition. Setting the partition months to 1 will create partitions with a size of 1 natural month.
FINDINGS_TABLE_PARTITION_MONTHS = env.int("FINDINGS_TABLE_PARTITION_MONTHS", 1)

# Set the number of partitions to create
FINDINGS_TABLE_PARTITION_COUNT = env.int("FINDINGS_TABLE_PARTITION_COUNT", 7)

# Set the number of months to keep partitions before deleting them
# Setting this to None will keep partitions indefinitely
FINDINGS_TABLE_PARTITION_MAX_AGE_MONTHS = env.int(
    "FINDINGS_TABLE_PARTITION_MAX_AGE_MONTHS", None
)

# API Key Activity Partitioning Settings
# Set the months for each partition. Setting the partition months to 1 will create partitions with a size of 1 natural month.
API_KEY_ACTIVITY_TABLE_PARTITION_MONTHS = env.int("API_KEY_ACTIVITY_TABLE_PARTITION_MONTHS", 1)

# Set the number of partitions to create
API_KEY_ACTIVITY_TABLE_PARTITION_COUNT = env.int("API_KEY_ACTIVITY_TABLE_PARTITION_COUNT", 13)

# Set the number of months to keep partitions before deleting them (default: 12 months for audit compliance)
# Setting this to None will keep partitions indefinitely
API_KEY_ACTIVITY_TABLE_PARTITION_MAX_AGE_MONTHS = env.int(
    "API_KEY_ACTIVITY_TABLE_PARTITION_MAX_AGE_MONTHS", 12
)

# Backwards compatibility: API key activity retention in days (converted to months for partitioning)
# This allows using the documented API_KEY_ACTIVITY_RETENTION_DAYS environment variable
API_KEY_ACTIVITY_RETENTION_DAYS = env.int("API_KEY_ACTIVITY_RETENTION_DAYS", 365)

# Convert days to months for partitioning (if the days setting overrides the months setting)
if API_KEY_ACTIVITY_RETENTION_DAYS != 365:  # Only override if explicitly set to non-default
    API_KEY_ACTIVITY_TABLE_PARTITION_MAX_AGE_MONTHS = math.ceil(API_KEY_ACTIVITY_RETENTION_DAYS / 30.44)  # Average days per month
