# Partitions

## Overview

Partitions are used to split the data in a table into smaller chunks, allowing for more efficient querying and storage.

The Prowler API uses partitions to store findings. The partitions are created based on the UUIDv7 `id` field.

You can use the Prowler API without ever creating additional partitions. This documentation is only relevant if you want to manage partitions to gain additional query performance.

### Required Postgres Configuration

There are 3 configuration options that need to be set in the `postgres.conf` file to get the most performance out of the partitioning:

- `enable_partition_pruning = on` (default is on)
- `enable_partitionwise_join = on` (default is off)
- `enable_partitionwise_aggregate = on` (default is off)

For more information on these options, see the [Postgres documentation](https://www.postgresql.org/docs/current/runtime-config-query.html).

## Partitioning Strategy

The partitioning strategy is defined in the `api.partitions` module. The strategy is responsible for creating and deleting partitions based on the provided configuration.

## Managing Partitions

The application will run without any extra work on your part. If you want to add or delete partitions, you can use the following commands:

To manage the partitions, run `python manage.py pgpartition --using admin`

This command will generate a list of partitions to create and delete based on the provided configuration.

By default, the command will prompt you to accept the changes before applying them.

```shell
Finding:
  + 2024_oct_18
     name: 2024_oct_18
     from_values: 01929cec-8800-7988-a49d-54cbb64b2d3f
     to_values: 0193376b-4c18-7ff7-99d5-95b8479ce39f
     size_unit: days
     size_value: 30
  + 2024_nov_17
     name: 2024_nov_17
     from_values: 0193376b-5000-7414-bbae-b1da382332f9
     to_values: 0193d1ea-1418-7b00-93fa-c4e06bf36bbe
     size_unit: days
     size_value: 30

0 partitions will be deleted
2 partitions will be created
```

If you choose to apply the partitions, tables will be generated with the following format: `<table_name>_<year>_<month>_<day>`. The date in the table name shows the first date of the partition.

For more info on the partitioning manager, see https://github.com/SectorLabs/django-postgres-extra

### Changing the Partitioning Parameters

There are 3 environment variables that can be used to change the partitioning parameters:

- `FINDINGS_TABLE_PARTITION_DAYS`: Set the days for each partition. Setting the partition days to 30 will create partitions with a size of 1 month.
- `FINDINGS_TABLE_PARTITION_COUNT`: Set the number of partitions to create
- `FINDINGS_TABLE_PARTITION_MAX_AGE_DAYS`: Set the number of days to keep partitions before deleting them. Setting this to `None` will keep partitions indefinitely.
