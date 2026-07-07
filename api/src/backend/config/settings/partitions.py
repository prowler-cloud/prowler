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

# Compliance requirement overviews partitioning (RANGE by UUIDv7 id).
# Mirrors the findings settings; kept separate so the ingest-heavy compliance
# table can be tuned (and aged out) independently from findings.
COMPLIANCE_REQ_OVERVIEW_PARTITION_MONTHS = env.int(
    "COMPLIANCE_REQ_OVERVIEW_PARTITION_MONTHS", 1
)
COMPLIANCE_REQ_OVERVIEW_PARTITION_COUNT = env.int(
    "COMPLIANCE_REQ_OVERVIEW_PARTITION_COUNT", 7
)
# Setting this to None keeps partitions indefinitely (matches findings default).
COMPLIANCE_REQ_OVERVIEW_PARTITION_MAX_AGE_MONTHS = env.int(
    "COMPLIANCE_REQ_OVERVIEW_PARTITION_MAX_AGE_MONTHS", None
)
