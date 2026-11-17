from datetime import UTC, datetime, timedelta
from itertools import islice

import pytest
from api.models import Finding, ResourceFindingMapping
from api.partitions import (
    PostgresUUIDv7PartitioningStrategy,
    relative_months_or_none,
)
from api.uuid_utils import datetime_to_uuid7, uuid7_range_bound
from dateutil.relativedelta import relativedelta
from django.core.exceptions import ImproperlyConfigured
from django.db import connection
from prowler.lib.check.models import Severity
from prowler.lib.outputs.finding import Status
from psqlextra.partitioning import (
    PostgresPartitioningManager,
    PostgresTimePartitionSize,
)
from psqlextra.partitioning.config import PostgresPartitioningConfig


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


def build_manager(start_date, count, max_age):
    def config(model, rls_statements):
        return PostgresPartitioningConfig(
            model=model,
            strategy=PostgresUUIDv7PartitioningStrategy(
                size=PostgresTimePartitionSize(months=1),
                count=count,
                start_date=start_date,
                max_age=max_age,
                name_format="%Y_%b",
                rls_statements=rls_statements,
            ),
        )

    return PostgresPartitioningManager(
        [
            config(Finding, ["SELECT", "INSERT", "UPDATE", "DELETE"]),
            config(ResourceFindingMapping, ["SELECT"]),
        ]
    )


def table_exists(name):
    with connection.cursor() as cursor:
        cursor.execute("SELECT to_regclass(%s) IS NOT NULL", [name])
        return cursor.fetchone()[0]


def create_finding(scan, resource, finding_id, uid):
    finding = Finding.objects.create(
        id=finding_id,
        tenant_id=scan.tenant_id,
        uid=uid,
        scan=scan,
        status=Status.FAIL,
        status_extended="status extended",
        impact=Severity.low,
        impact_extended="impact extended",
        severity=Severity.low,
        raw_result={},
        check_id="test_check_id",
        check_metadata={"CheckId": "test_check_id"},
    )
    finding.add_resources([resource])
    return finding


@pytest.mark.django_db
class TestDeletePartitions:
    @pytest.fixture
    def expired_month(self):
        now = datetime.now(UTC).replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
        return now - relativedelta(months=3)

    @pytest.fixture
    def expired_partitions(self, expired_month):
        build_manager(expired_month, 1, None).plan(skip_delete=True).apply()
        name = expired_month.strftime("%Y_%b").lower()
        assert table_exists(f"findings_{name}")
        assert table_exists(f"resource_finding_mappings_{name}")
        return name

    def delete_expired(self):
        # The test's own inserts leave deferred foreign key checks pending in
        # the test transaction, which PostgreSQL refuses to drop a table under.
        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
            cursor.execute("SET CONSTRAINTS ALL DEFERRED")
        now = datetime.now(UTC)
        manager = build_manager(now, 1, relativedelta(months=3))
        manager.plan(skip_create=True).apply()

    def test_expired_findings_partition_is_dropped_with_its_mappings(
        self, scans_fixture, resources_fixture, expired_month, expired_partitions
    ):
        scan, *_ = scans_fixture
        resource, *_ = resources_fixture
        create_finding(
            scan, resource, datetime_to_uuid7(expired_month + timedelta(days=3)), "old"
        )
        kept = create_finding(
            scan, resource, datetime_to_uuid7(datetime.now(UTC)), "new"
        )

        self.delete_expired()

        assert not table_exists(f"findings_{expired_partitions}")
        assert not table_exists(f"resource_finding_mappings_{expired_partitions}")
        assert Finding.objects.filter(id=kept.id).exists()
        assert ResourceFindingMapping.objects.filter(finding_id=kept.id).exists()
        assert not Finding.objects.filter(uid="old").exists()

    def test_mappings_can_still_be_added_after_a_drop(
        self, scans_fixture, resources_fixture, expired_partitions
    ):
        scan, *_ = scans_fixture
        resource, *_ = resources_fixture

        self.delete_expired()

        finding = create_finding(
            scan, resource, datetime_to_uuid7(datetime.now(UTC)), "after"
        )
        assert ResourceFindingMapping.objects.filter(finding_id=finding.id).exists()

    def test_nothing_is_dropped_when_no_partition_is_expired(
        self, scans_fixture, resources_fixture
    ):
        scan, *_ = scans_fixture
        resource, *_ = resources_fixture
        finding = create_finding(
            scan, resource, datetime_to_uuid7(datetime.now(UTC)), "current"
        )

        self.delete_expired()

        assert Finding.objects.filter(id=finding.id).exists()
