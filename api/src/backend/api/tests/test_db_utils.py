from datetime import datetime, timezone
from enum import Enum
from unittest.mock import patch

import pytest

from api.db_utils import (
    batch_delete,
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
    def test_batch_delete(self, create_test_providers):
        _, summary = batch_delete(
            Provider.objects.all(), batch_size=create_test_providers // 2
        )
        assert Provider.objects.all().count() == 0
        assert summary == {"api.Provider": create_test_providers}
