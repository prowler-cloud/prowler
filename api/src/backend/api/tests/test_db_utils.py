from datetime import datetime, timezone
from enum import Enum
from unittest.mock import patch

import pytest
from django.conf import settings
from freezegun import freeze_time

from api.db_utils import (
    _should_create_index_on_partition,
    batch_delete,
    create_objects_in_batches,
    enum_to_choices,
    generate_random_token,
    one_week_from_now,
)
from api.models import Provider


class TestEnumToChoices:
    def test_enum_to_choices_simple(self):
        class Color(Enum):
            RED = 1
            GREEN = 2
            BLUE = 3

        expected_result = [
            (1, "Red"),
            (2, "Green"),
            (3, "Blue"),
        ]

        result = enum_to_choices(Color)
        assert result == expected_result

    def test_enum_to_choices_with_underscores(self):
        class Status(Enum):
            PENDING_APPROVAL = "pending"
            IN_PROGRESS = "in_progress"
            COMPLETED_SUCCESSFULLY = "completed"

        expected_result = [
            ("pending", "Pending Approval"),
            ("in_progress", "In Progress"),
            ("completed", "Completed Successfully"),
        ]

        result = enum_to_choices(Status)
        assert result == expected_result

    def test_enum_to_choices_empty_enum(self):
        class EmptyEnum(Enum):
            pass

        expected_result = []

        result = enum_to_choices(EmptyEnum)
        assert result == expected_result

    def test_enum_to_choices_numeric_values(self):
        class Numbers(Enum):
            ONE = 1
            TWO = 2
            THREE = 3

        expected_result = [
            (1, "One"),
            (2, "Two"),
            (3, "Three"),
        ]

        result = enum_to_choices(Numbers)
        assert result == expected_result


class TestOneWeekFromNow:
    def test_one_week_from_now(self):
        with patch("api.db_utils.datetime") as mock_datetime:
            mock_datetime.now.return_value = datetime(2023, 1, 1, tzinfo=timezone.utc)
            expected_result = datetime(2023, 1, 8, tzinfo=timezone.utc)

            result = one_week_from_now()
            assert result == expected_result

    def test_one_week_from_now_with_timezone(self):
        with patch("api.db_utils.datetime") as mock_datetime:
            mock_datetime.now.return_value = datetime(
                2023, 6, 15, 12, 0, tzinfo=timezone.utc
            )
            expected_result = datetime(2023, 6, 22, 12, 0, tzinfo=timezone.utc)

            result = one_week_from_now()
            assert result == expected_result


class TestGenerateRandomToken:
    def test_generate_random_token_default_length(self):
        token = generate_random_token()
        assert len(token) == 14

    def test_generate_random_token_custom_length(self):
        length = 20
        token = generate_random_token(length=length)
        assert len(token) == length

    def test_generate_random_token_with_symbols(self):
        symbols = "ABC123"
        token = generate_random_token(length=10, symbols=symbols)
        assert len(token) == 10
        assert all(char in symbols for char in token)

    def test_generate_random_token_unique(self):
        tokens = {generate_random_token() for _ in range(1000)}
        # Assuming that generating 1000 tokens should result in unique values
        assert len(tokens) == 1000

    def test_generate_random_token_no_symbols_provided(self):
        token = generate_random_token(length=5, symbols="")
        # Default symbols
        assert len(token) == 5


class TestBatchDelete:
    @pytest.fixture
    def create_test_providers(self, tenants_fixture):
        tenant = tenants_fixture[0]
        provider_id = 123456789012
        provider_count = 10
        for i in range(provider_count):
            Provider.objects.create(
                tenant=tenant,
                uid=f"{provider_id + i}",
                provider=Provider.ProviderChoices.AWS,
            )
        return provider_count

    @pytest.mark.django_db
    def test_batch_delete(self, tenants_fixture, create_test_providers):
        tenant_id = str(tenants_fixture[0].id)
        _, summary = batch_delete(
            tenant_id, Provider.objects.all(), batch_size=create_test_providers // 2
        )
        assert Provider.objects.all().count() == 0
        assert summary == {"api.Provider": create_test_providers}


class TestShouldCreateIndexOnPartition:
    @freeze_time("2025-05-15 00:00:00Z")
    @pytest.mark.parametrize(
        "partition_name, all_partitions, expected",
        [
            ("any_name", True, True),
            ("findings_default", True, True),
            ("findings_2022_jan", True, True),
            ("foo_bar", False, True),
            ("findings_2025_MAY", False, True),
            ("findings_2025_may", False, True),
            ("findings_2025_jun", False, True),
            ("findings_2025_apr", False, False),
            ("findings_2025_xyz", False, True),
        ],
    )
    def test_partition_inclusion_logic(self, partition_name, all_partitions, expected):
        assert (
            _should_create_index_on_partition(partition_name, all_partitions)
            is expected
        )

    @freeze_time("2025-05-15 00:00:00Z")
    def test_invalid_date_components(self):
        # even if regex matches but int conversion fails, we fallback True
        # (e.g. year too big, month number parse error)
        bad_name = "findings_99999_jan"
        assert _should_create_index_on_partition(bad_name, False) is True

        bad_name2 = "findings_2025_abc"
        # abc not in month_map → fallback True
        assert _should_create_index_on_partition(bad_name2, False) is True


@pytest.mark.django_db
class TestCreateObjectsInBatches:
    @pytest.fixture
    def tenant(self, tenants_fixture):
        return tenants_fixture[0]

    def make_provider_instances(self, tenant, count):
        """
        Return a list of `count` unsaved Provider instances for the given tenant.
        """
        base_uid = 1000
        return [
            Provider(
                tenant=tenant,
                uid=str(base_uid + i),
                provider=Provider.ProviderChoices.AWS,
            )
            for i in range(count)
        ]

    def test_exact_multiple_of_batch(self, tenant):
        total = 6
        batch_size = 3
        objs = self.make_provider_instances(tenant, total)

        create_objects_in_batches(str(tenant.id), Provider, objs, batch_size=batch_size)

        qs = Provider.objects.filter(tenant=tenant)
        assert qs.count() == total

    def test_non_multiple_of_batch(self, tenant):
        total = 7
        batch_size = 3
        objs = self.make_provider_instances(tenant, total)

        create_objects_in_batches(str(tenant.id), Provider, objs, batch_size=batch_size)

        qs = Provider.objects.filter(tenant=tenant)
        assert qs.count() == total

    def test_batch_size_default(self, tenant):
        default_size = settings.DJANGO_DELETION_BATCH_SIZE
        total = default_size + 2
        objs = self.make_provider_instances(tenant, total)

        create_objects_in_batches(str(tenant.id), Provider, objs)

        qs = Provider.objects.filter(tenant=tenant)
        assert qs.count() == total
