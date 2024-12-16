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
   + 2024_nov
      name: 2024_nov
      from_values: 0192e505-9000-72c8-a47c-cce719d8fb93
      to_values: 01937f84-5418-7eb8-b2a6-e3be749e839d
      size_unit: months
      size_value: 1
   + 2024_dec
      name: 2024_dec
      from_values: 01937f84-5800-7b55-879c-9cdb46f023f6
      to_values: 01941f29-7818-7f9f-b4be-20b05bb2f574
      size_unit: months
      size_value: 1

0 partitions will be deleted
2 partitions will be created
```

If you choose to apply the partitions, tables will be generated with the following format: `<table_name>_<year>_<month>`.

For more info on the partitioning manager, see https://github.com/SectorLabs/django-postgres-extra

### Changing the Partitioning Parameters

There are 4 environment variables that can be used to change the partitioning parameters:

- `DJANGO_MANAGE_DB_PARTITIONS`: Allow Django to manage database partitons. By default is set to `False`.
- `FINDINGS_TABLE_PARTITION_MONTHS`: Set the months for each partition. Setting the partition monts to 1 will create partitions with a size of 1 natural month.
- `FINDINGS_TABLE_PARTITION_COUNT`: Set the number of partitions to create
- `FINDINGS_TABLE_PARTITION_MAX_AGE_MONTHS`: Set the number of months to keep partitions before deleting them. Setting this to `None` will keep partitions indefinitely.
