from datetime import UTC, datetime, timedelta
from itertools import islice

import pytest
from api.partitions import (
    PostgresUUIDv7PartitioningStrategy,
    relative_months_or_none,
)
from api.uuid_utils import uuid7_range_bound
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


class TestToCreate:
    def test_consecutive_partitions_meet_exactly(self):
        # PostgreSQL's upper bound is exclusive, so windows tile only when one
        # partition's to_values is the next one's from_values. Anything less
        # leaves ids in between with no partition to go to.
        strategy = PostgresUUIDv7PartitioningStrategy(
            size=PostgresTimePartitionSize(months=1),
            count=4,
            start_date=datetime(2026, 1, 1, tzinfo=UTC),
            max_age=None,
            name_format="%Y_%b",
        )

        partitions = list(strategy.to_create())

        for earlier, later in zip(partitions, partitions[1:]):
            assert earlier.to_values == later.from_values

    def test_bounds_do_not_depend_on_when_they_were_derived(self):
        # A bound that is regenerated has to come out identical, or a partition's
        # declared range cannot be reconciled against the one it was created with.
        moment = datetime(2026, 5, 17, 9, 30, tzinfo=UTC)

        assert uuid7_range_bound(moment) == uuid7_range_bound(moment)

    def test_bound_holds_its_millisecond_far_into_the_future(self):
        # A float second stops resolving milliseconds in 2249, so
        # int(dt.timestamp() * 1000) rounds the last microsecond of a millisecond
        # up into the next one and the bound excludes the ids it exists to cover.
        moment = datetime(2262, 5, 17, 9, 30, 0, 999, tzinfo=UTC)
        epoch = datetime(1970, 1, 1, tzinfo=UTC)

        bound = uuid7_range_bound(moment)

        assert bound.int >> 80 == (moment - epoch) // timedelta(milliseconds=1)

    def test_bound_is_the_lowest_uuid7_of_its_millisecond(self):
        moment = datetime(2026, 5, 17, 9, 30, tzinfo=UTC)

        bound = uuid7_range_bound(moment)

        assert bound.version == 7
        # Timestamp preserved, every field below it zero.
        assert bound.int >> 80 == int(moment.timestamp() * 1000)
        assert bound.int & ((1 << 76) - 1) == (0x2 << 62)
