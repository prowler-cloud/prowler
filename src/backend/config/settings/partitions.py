from config.env import env

# Partitioning
PSQLEXTRA_PARTITIONING_MANAGER = "api.partitions.manager"

# Set the days for each partition. Setting the partition days to 30 will create partitions with a size of 1 month.
FINDINGS_TABLE_PARTITION_DAYS = env.int("FINDINGS_TABLE_PARTITION_DAYS", 30)

# Set the number of partitions to create
FINDINGS_TABLE_PARTITION_COUNT = env.int("FINDINGS_TABLE_PARTITION_COUNT", 7)

# Set the number of days to keep partitions before deleting them
# Setting this to None will keep partitions indefinitely
FINDINGS_TABLE_PARTITION_MAX_AGE_DAYS = env.int(
    "FINDINGS_TABLE_PARTITION_MAX_AGE_DAYS", None
)
