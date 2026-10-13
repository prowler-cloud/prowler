from datetime import UTC, datetime
from itertools import islice

import pytest
from api.partitions import (
    PostgresUUIDv7PartitioningStrategy,
    relative_months_or_none,
)
from dateutil.relativedelta import relativedelta
from django.core.exceptions import ImproperlyConfigured
from psqlextra.partitioning import PostgresTimePartitionSize


def build_strategy(max_age):
    return PostgresUUIDv7PartitioningStrategy(
        size=PostgresTimePartitionSize(months=1),
        count=1,
        start_date=datetime.now(UTC),
        max_age=max_age,
        name_format="%Y_%b",
    )


class TestRelativeMonthsOrNone:
    @pytest.mark.parametrize("value", [None, 0])
    def test_unset_or_zero_keeps_partitions_indefinitely(self, value):
        assert relative_months_or_none(value) is None

    @pytest.mark.parametrize("months", [1, 3, 12])
    def test_value_is_interpreted_as_months(self, months):
        assert relative_months_or_none(months) == relativedelta(months=months)

    def test_value_is_not_interpreted_as_days(self):
        assert relative_months_or_none(12) != relativedelta(days=12)

    def test_negative_is_rejected(self):
        with pytest.raises(ImproperlyConfigured):
            relative_months_or_none(-12)


class TestToDelete:
    @pytest.mark.parametrize("max_age", [None, relative_months_or_none(0)])
    def test_nothing_is_deleted_without_max_age(self, max_age):
        strategy = build_strategy(max_age)

        assert list(islice(strategy.to_delete(), 5)) == []

    def test_first_deleted_partition_is_max_age_old(self):
        months = 3
        strategy = build_strategy(relative_months_or_none(months))

        first = next(strategy.to_delete())

        expected = strategy.get_start_datetime() - relativedelta(months=months)
        assert first.name() == expected.strftime("%Y_%b").lower()

    def test_deleted_partitions_go_further_back_in_time(self):
        strategy = build_strategy(relative_months_or_none(3))

        names = [p.name() for p in islice(strategy.to_delete(), 3)]
        starts = [datetime.strptime(n, "%Y_%b") for n in names]

        assert starts == sorted(starts, reverse=True)
