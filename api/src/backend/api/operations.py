import re
from datetime import datetime, timezone

from django.db import connection
from django.db.migrations.operations.base import Operation


class CreatePartitionedIndex(Operation):
    reversible = True

    def __init__(
        self,
        parent_table: str,
        index_name: str,
        columns: str,
        method: str = "BTREE",
        where: str = "",
        all_partitions: bool = False,
        create_parent_index: bool = True,
    ):
        self.parent_table = parent_table
        self.index_name = index_name
        self.columns = columns
        self.method = method
        self.where = where
        self.all_partitions = all_partitions
        self.create_parent_index = create_parent_index

    def state_forwards(self, app_label, state):  # noqa: F841
        pass  # No state change

    def database_forwards(self, app_label, schema_editor, from_state, to_state):  # noqa: F841
        parent_index_name = f"{self.index_name}"
        where_sql = f" WHERE {self.where}" if self.where else ""

        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT inhrelid::regclass::text
                FROM pg_inherits
                WHERE inhparent = %s::regclass
                """,
                [self.parent_table],
            )
            partitions = [row[0] for row in cursor.fetchall()]

        if self.create_parent_index:
            sql = (
                f"CREATE INDEX IF NOT EXISTS {parent_index_name} "
                f"ON ONLY {self.parent_table} USING {self.method} ({self.columns})"
                f"{where_sql};"
            )
            schema_editor.execute(sql)

        for partition in partitions:
            if self._should_create_index_on_partition(partition, self.all_partitions):
                child_index_name = f"{partition.replace('.', '_')}_{self.index_name}"
                create_sql = (
                    f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {child_index_name} "
                    f"ON {partition} USING {self.method} ({self.columns})"
                    f"{where_sql};"
                )
                schema_editor.execute(create_sql)

                if self.create_parent_index:
                    attach_sql = (
                        f"ALTER INDEX {parent_index_name} "
                        f"ATTACH PARTITION {child_index_name};"
                    )
                    try:
                        schema_editor.execute(attach_sql)
                    except Exception as e:
                        print(
                            f"Warning: Could not attach index {child_index_name}: {e}"
                        )

    def database_backwards(self, app_label, schema_editor, from_state, to_state):  # noqa: F841
        if self.create_parent_index:
            parent_index_name = self.index_name
            drop_parent_sql = f"DROP INDEX IF EXISTS {parent_index_name};"
            schema_editor.execute(drop_parent_sql)

        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT inhrelid::regclass::text
                FROM pg_inherits
                WHERE inhparent = %s::regclass
                """,
                [self.parent_table],
            )
            partitions = [row[0] for row in cursor.fetchall()]

        for partition in partitions:
            idx_name = f"{partition.replace('.', '_')}_{self.index_name}"
            drop_sql = f"DROP INDEX CONCURRENTLY IF EXISTS {idx_name};"
            schema_editor.execute(drop_sql)

    def describe(self):
        return f"Create partitioned index {self.index_name} on {self.parent_table}"

    def _should_create_index_on_partition(
        self, partition_name: str, all_partitions: bool
    ) -> bool:
        if all_partitions:
            return True

        date_pattern = r"(\d{4})_([a-z]{3})$"
        match = re.search(date_pattern, partition_name)
        if not match:
            return True

        try:
            year_str, month_abbr = match.groups()
            year = int(year_str)
            month_map = {
                "jan": 1,
                "feb": 2,
                "mar": 3,
                "apr": 4,
                "may": 5,
                "jun": 6,
                "jul": 7,
                "aug": 8,
                "sep": 9,
                "oct": 10,
                "nov": 11,
                "dec": 12,
            }
            month = month_map.get(month_abbr.lower())
            if month is None:
                return True

            partition_date = datetime(year, month, 1, tzinfo=timezone.utc)
            current_month_start = datetime.now(timezone.utc).replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            )
            return partition_date >= current_month_start
        except Exception:
            return True
