from datetime import datetime, timezone
from typing import Generator, Optional

from dateutil.relativedelta import relativedelta
from django.conf import settings
from psqlextra.partitioning import (
    PostgresPartitioningManager,
    PostgresRangePartition,
    PostgresRangePartitioningStrategy,
    PostgresTimePartitionSize,
    PostgresPartitioningError,
)
from psqlextra.partitioning.config import PostgresPartitioningConfig
from uuid6 import UUID

from api.models import Finding, ResourceFindingMapping
from api.rls import RowLevelSecurityConstraint
from api.uuid_utils import datetime_to_uuid7


class PostgresUUIDv7RangePartition(PostgresRangePartition):
    def __init__(
        self,
        from_values: UUID,
        to_values: UUID,
        size: PostgresTimePartitionSize,
        name_format: Optional[str] = None,
        **kwargs,
    ) -> None:
        self.from_values = from_values
        self.to_values = to_values
        self.size = size
        self.name_format = name_format

        self.rls_statements = None
        if "rls_statements" in kwargs:
            self.rls_statements = kwargs["rls_statements"]

        start_timestamp_ms = self.from_values.time

        self.start_datetime = datetime.fromtimestamp(
            start_timestamp_ms / 1000, timezone.utc
        )

    def name(self) -> str:
        if not self.name_format:
            raise PostgresPartitioningError("Unknown size/unit")

        return self.start_datetime.strftime(self.name_format).lower()

    def deconstruct(self) -> dict:
        return {
            **super().deconstruct(),
            "size_unit": self.size.unit.value,
            "size_value": self.size.value,
        }

    def create(
        self,
        model,
        schema_editor,
        comment,
    ) -> None:
        super().create(model, schema_editor, comment)

        # if this model has RLS statements, add them to the partition
        if isinstance(self.rls_statements, list):
            schema_editor.add_constraint(
                model,
                constraint=RowLevelSecurityConstraint(
                    "tenant_id",
                    name=f"rls_on_{self.name()}",
                    partition_name=self.name(),
                    statements=self.rls_statements,
                ),
            )


class PostgresUUIDv7PartitioningStrategy(PostgresRangePartitioningStrategy):
    def __init__(
        self,
        size: PostgresTimePartitionSize,
        count: int,
        start_date: datetime = None,
        max_age: Optional[relativedelta] = None,
        name_format: Optional[str] = None,
        **kwargs,
    ) -> None:
        self.start_date = start_date.replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        self.size = size
        self.count = count
        self.max_age = max_age
        self.name_format = name_format

        self.rls_statements = None
        if "rls_statements" in kwargs:
            self.rls_statements = kwargs["rls_statements"]

    def to_create(self) -> Generator[PostgresUUIDv7RangePartition, None, None]:
        current_datetime = (
            self.start_date if self.start_date else self.get_start_datetime()
        )

        for _ in range(self.count):
            end_datetime = (
                current_datetime + self.size.as_delta() - relativedelta(microseconds=1)
            )
            start_uuid7 = datetime_to_uuid7(current_datetime)
            end_uuid7 = datetime_to_uuid7(end_datetime)

            yield PostgresUUIDv7RangePartition(
                from_values=start_uuid7,
                to_values=end_uuid7,
                size=self.size,
                name_format=self.name_format,
                rls_statements=self.rls_statements,
            )

            current_datetime += self.size.as_delta()

    def to_delete(self) -> Generator[PostgresUUIDv7RangePartition, None, None]:
        if not self.max_age:
            return

        current_datetime = self.get_start_datetime() - self.max_age

        while True:
            end_datetime = current_datetime + self.size.as_delta()
            start_uuid7 = datetime_to_uuid7(current_datetime)
            end_uuid7 = datetime_to_uuid7(end_datetime)

            # dropping table will delete indexes and policies
            yield PostgresUUIDv7RangePartition(
                from_values=start_uuid7,
                to_values=end_uuid7,
                size=self.size,
                name_format=self.name_format,
            )

            current_datetime -= self.size.as_delta()

    def get_start_datetime(self) -> datetime:
        """
        Gets the start of the current month in UTC timezone.

        This function returns a `datetime` object set to the first day of the current
        month, at midnight (00:00:00), in UTC.

        Returns:
            datetime: A `datetime` object representing the start of the current month in UTC.
        """
        return datetime.now(timezone.utc).replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )


def relative_days_or_none(value):
    if value is None:
        return None
    return relativedelta(days=value)


#
# To manage the partitions, run `python manage.py pgpartition --using admin`
#
# For more info on the partitioning manager, see https://github.com/SectorLabs/django-postgres-extra
manager = PostgresPartitioningManager(
    [
        PostgresPartitioningConfig(
            model=Finding,
            strategy=PostgresUUIDv7PartitioningStrategy(
                start_date=datetime.now(timezone.utc),
                size=PostgresTimePartitionSize(
                    months=settings.FINDINGS_TABLE_PARTITION_MONTHS
                ),
                count=settings.FINDINGS_TABLE_PARTITION_COUNT,
                max_age=relative_days_or_none(
                    settings.FINDINGS_TABLE_PARTITION_MAX_AGE_MONTHS
                ),
                name_format="%Y_%b",
                rls_statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        # ResourceFindingMapping should always follow the Finding partitioning
        PostgresPartitioningConfig(
            model=ResourceFindingMapping,
            strategy=PostgresUUIDv7PartitioningStrategy(
                start_date=datetime.now(timezone.utc),
                size=PostgresTimePartitionSize(
                    months=settings.FINDINGS_TABLE_PARTITION_MONTHS
                ),
                count=settings.FINDINGS_TABLE_PARTITION_COUNT,
                max_age=relative_days_or_none(
                    settings.FINDINGS_TABLE_PARTITION_MAX_AGE_MONTHS
                ),
                name_format="%Y_%b",
                rls_statements=["SELECT"],
            ),
        ),
    ]
)
