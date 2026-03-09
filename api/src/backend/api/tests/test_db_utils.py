from datetime import datetime, timezone
from enum import Enum
from unittest.mock import MagicMock, patch

import pytest
from django.conf import settings
from django.db import DEFAULT_DB_ALIAS, OperationalError
from freezegun import freeze_time
from rest_framework_json_api.serializers import ValidationError

from api.db_utils import (
    POSTGRES_TENANT_VAR,
    _should_create_index_on_partition,
    batch_delete,
    create_objects_in_batches,
    enum_to_choices,
    generate_api_key_prefix,
    generate_random_token,
    one_week_from_now,
    rls_transaction,
    update_objects_in_batches,
)
from api.models import Provider


@pytest.fixture
def enable_read_replica():
    """
    Fixture to enable READ_REPLICA_ALIAS for tests that need replica functionality.
    This avoids polluting the global test configuration.
    """
    with patch("api.db_utils.READ_REPLICA_ALIAS", "replica"):
        yield "replica"


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


@pytest.mark.django_db
class TestUpdateObjectsInBatches:
    @pytest.fixture
    def tenant(self, tenants_fixture):
        return tenants_fixture[0]

    def make_provider_instances(self, tenant, count):
        """
        Return a list of `count` unsaved Provider instances for the given tenant.
        """
        base_uid = 2000
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

        # Fetch them back, mutate the `uid` field, then update in batches
        providers = list(Provider.objects.filter(tenant=tenant))
        for p in providers:
            p.uid = f"{p.uid}_upd"

        update_objects_in_batches(
            tenant_id=str(tenant.id),
            model=Provider,
            objects=providers,
            fields=["uid"],
            batch_size=batch_size,
        )

        qs = Provider.objects.filter(tenant=tenant, uid__endswith="_upd")
        assert qs.count() == total

    def test_non_multiple_of_batch(self, tenant):
        total = 7
        batch_size = 3
        objs = self.make_provider_instances(tenant, total)
        create_objects_in_batches(str(tenant.id), Provider, objs, batch_size=batch_size)

        providers = list(Provider.objects.filter(tenant=tenant))
        for p in providers:
            p.uid = f"{p.uid}_upd"

        update_objects_in_batches(
            tenant_id=str(tenant.id),
            model=Provider,
            objects=providers,
            fields=["uid"],
            batch_size=batch_size,
        )

        qs = Provider.objects.filter(tenant=tenant, uid__endswith="_upd")
        assert qs.count() == total

    def test_batch_size_default(self, tenant):
        default_size = settings.DJANGO_DELETION_BATCH_SIZE
        total = default_size + 2
        objs = self.make_provider_instances(tenant, total)
        create_objects_in_batches(str(tenant.id), Provider, objs)

        providers = list(Provider.objects.filter(tenant=tenant))
        for p in providers:
            p.uid = f"{p.uid}_upd"

        # Update without specifying batch_size (uses default)
        update_objects_in_batches(
            tenant_id=str(tenant.id),
            model=Provider,
            objects=providers,
            fields=["uid"],
        )

        qs = Provider.objects.filter(tenant=tenant, uid__endswith="_upd")
        assert qs.count() == total


class TestGenerateApiKeyPrefix:
    def test_prefix_format(self):
        """Test that generated prefix starts with 'pk_'."""
        prefix = generate_api_key_prefix()
        assert prefix.startswith("pk_")

    def test_prefix_length(self):
        """Test that prefix has correct length (pk_ + 8 random chars = 11)."""
        prefix = generate_api_key_prefix()
        assert len(prefix) == 11

    def test_prefix_uniqueness(self):
        """Test that multiple generations produce unique prefixes."""
        prefixes = {generate_api_key_prefix() for _ in range(100)}
        assert len(prefixes) == 100

    def test_prefix_character_set(self):
        """Test that random part uses only allowed characters."""
        allowed_chars = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
        for _ in range(50):
            prefix = generate_api_key_prefix()
            random_part = prefix[3:]  # Strip 'pk_'
            assert all(char in allowed_chars for char in random_part)


@pytest.mark.django_db
class TestRlsTransaction:
    def test_rls_transaction_valid_uuid_string(self, tenants_fixture):
        """Test rls_transaction with valid UUID string."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with rls_transaction(tenant_id) as cursor:
            assert cursor is not None
            cursor.execute("SELECT current_setting(%s)", [POSTGRES_TENANT_VAR])
            result = cursor.fetchone()
            assert result[0] == tenant_id

    def test_rls_transaction_valid_uuid_object(self, tenants_fixture):
        """Test rls_transaction with UUID object."""
        tenant = tenants_fixture[0]

        with rls_transaction(tenant.id) as cursor:
            assert cursor is not None
            cursor.execute("SELECT current_setting(%s)", [POSTGRES_TENANT_VAR])
            result = cursor.fetchone()
            assert result[0] == str(tenant.id)

    def test_rls_transaction_invalid_uuid_raises_validation_error(self):
        """Test rls_transaction raises ValidationError for invalid UUID."""
        invalid_uuid = "not-a-valid-uuid"

        with pytest.raises(ValidationError, match="Must be a valid UUID"):
            with rls_transaction(invalid_uuid):
                pass

    def test_rls_transaction_uses_default_database_when_no_alias(self, tenants_fixture):
        """Test rls_transaction uses DEFAULT_DB_ALIAS when no alias specified."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=None):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                with patch("api.db_utils.transaction.atomic"):
                    with rls_transaction(tenant_id):
                        pass

                mock_connections.__getitem__.assert_called_with(DEFAULT_DB_ALIAS)

    def test_rls_transaction_uses_specified_alias(self, tenants_fixture):
        """Test rls_transaction uses specified database alias via using parameter."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)
        custom_alias = "custom_db"

        with patch("api.db_utils.connections") as mock_connections:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
            mock_connections.__getitem__.return_value = mock_conn
            mock_connections.__contains__.return_value = True

            with patch("api.db_utils.transaction.atomic"):
                with patch("api.db_utils.set_read_db_alias") as mock_set_alias:
                    with patch("api.db_utils.reset_read_db_alias") as mock_reset_alias:
                        mock_set_alias.return_value = "test_token"
                        with rls_transaction(tenant_id, using=custom_alias):
                            pass

                        mock_connections.__getitem__.assert_called_with(custom_alias)
                        mock_set_alias.assert_called_once_with(custom_alias)
                        mock_reset_alias.assert_called_once_with("test_token")

    def test_rls_transaction_uses_read_replica_from_router(
        self, tenants_fixture, enable_read_replica
    ):
        """Test rls_transaction uses read replica alias from router."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=enable_read_replica):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                with patch("api.db_utils.transaction.atomic"):
                    with patch("api.db_utils.set_read_db_alias") as mock_set_alias:
                        with patch(
                            "api.db_utils.reset_read_db_alias"
                        ) as mock_reset_alias:
                            mock_set_alias.return_value = "test_token"
                            with rls_transaction(tenant_id):
                                pass

                            mock_connections.__getitem__.assert_called()
                            mock_set_alias.assert_called_once()
                            mock_reset_alias.assert_called_once()

    def test_rls_transaction_fallback_to_default_when_alias_not_in_connections(
        self, tenants_fixture
    ):
        """Test rls_transaction falls back to DEFAULT_DB_ALIAS when alias not in connections."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)
        invalid_alias = "nonexistent_db"

        with patch("api.db_utils.get_read_db_alias", return_value=invalid_alias):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

                def contains_check(alias):
                    return alias == DEFAULT_DB_ALIAS

                mock_connections.__contains__.side_effect = contains_check
                mock_connections.__getitem__.return_value = mock_conn

                with patch("api.db_utils.transaction.atomic"):
                    with rls_transaction(tenant_id):
                        pass

                    mock_connections.__getitem__.assert_called_with(DEFAULT_DB_ALIAS)

    def test_rls_transaction_successful_execution_on_replica_no_retries(
        self, tenants_fixture, enable_read_replica
    ):
        """Test successful execution on replica without retries."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=enable_read_replica):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                with patch("api.db_utils.transaction.atomic"):
                    with patch("api.db_utils.set_read_db_alias", return_value="token"):
                        with patch("api.db_utils.reset_read_db_alias"):
                            with rls_transaction(tenant_id):
                                pass

                            assert mock_cursor.execute.call_count == 1

    def test_rls_transaction_retry_with_exponential_backoff_on_operational_error(
        self, tenants_fixture, enable_read_replica
    ):
        """Test retry with exponential backoff on OperationalError on replica."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=enable_read_replica):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                call_count = 0

                def atomic_side_effect(*args, **kwargs):
                    nonlocal call_count
                    call_count += 1
                    if call_count < 3:
                        raise OperationalError("Connection error")
                    return MagicMock(
                        __enter__=MagicMock(return_value=None),
                        __exit__=MagicMock(return_value=False),
                    )

                with patch(
                    "api.db_utils.transaction.atomic", side_effect=atomic_side_effect
                ):
                    with patch("api.db_utils.time.sleep") as mock_sleep:
                        with patch(
                            "api.db_utils.set_read_db_alias", return_value="token"
                        ):
                            with patch("api.db_utils.reset_read_db_alias"):
                                with patch("api.db_utils.logger") as mock_logger:
                                    with rls_transaction(tenant_id):
                                        pass

                                    assert mock_sleep.call_count == 2
                                    mock_sleep.assert_any_call(0.5)
                                    mock_sleep.assert_any_call(1.0)
                                    assert mock_logger.info.call_count == 2

    def test_rls_transaction_operational_error_inside_context_no_retry(
        self, tenants_fixture, enable_read_replica
    ):
        """Test OperationalError raised inside context does not retry."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=enable_read_replica):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                with patch("api.db_utils.transaction.atomic") as mock_atomic:
                    mock_atomic.return_value.__enter__.return_value = None
                    mock_atomic.return_value.__exit__.return_value = False

                    with patch("api.db_utils.time.sleep") as mock_sleep:
                        with patch(
                            "api.db_utils.set_read_db_alias", return_value="token"
                        ):
                            with patch("api.db_utils.reset_read_db_alias"):
                                with pytest.raises(OperationalError):
                                    with rls_transaction(tenant_id):
                                        raise OperationalError("Conflict with recovery")

                                mock_sleep.assert_not_called()

    def test_rls_transaction_max_three_attempts_for_replica(
        self, tenants_fixture, enable_read_replica
    ):
        """Test maximum 3 attempts for replica database."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=enable_read_replica):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                with patch("api.db_utils.transaction.atomic") as mock_atomic:
                    mock_atomic.side_effect = OperationalError("Persistent error")

                    with patch("api.db_utils.time.sleep"):
                        with patch(
                            "api.db_utils.set_read_db_alias", return_value="token"
                        ):
                            with patch("api.db_utils.reset_read_db_alias"):
                                with pytest.raises(OperationalError):
                                    with rls_transaction(tenant_id):
                                        pass

                                assert mock_atomic.call_count == 3

    def test_rls_transaction_replica_no_retry_when_disabled(
        self, tenants_fixture, enable_read_replica
    ):
        """Test replica retry is disabled when retry_on_replica=False."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=enable_read_replica):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                with patch("api.db_utils.transaction.atomic") as mock_atomic:
                    mock_atomic.side_effect = OperationalError("Replica error")

                    with patch("api.db_utils.time.sleep") as mock_sleep:
                        with patch(
                            "api.db_utils.set_read_db_alias", return_value="token"
                        ):
                            with patch("api.db_utils.reset_read_db_alias"):
                                with pytest.raises(OperationalError):
                                    with rls_transaction(
                                        tenant_id, retry_on_replica=False
                                    ):
                                        pass

                                assert mock_atomic.call_count == 1
                                mock_sleep.assert_not_called()

    def test_rls_transaction_only_one_attempt_for_primary(self, tenants_fixture):
        """Test only 1 attempt for primary database."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=None):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                with patch("api.db_utils.transaction.atomic") as mock_atomic:
                    mock_atomic.side_effect = OperationalError("Primary error")

                    with pytest.raises(OperationalError):
                        with rls_transaction(tenant_id):
                            pass

                    assert mock_atomic.call_count == 1

    def test_rls_transaction_fallback_to_primary_after_max_attempts(
        self, tenants_fixture, enable_read_replica
    ):
        """Test fallback to primary DB after max attempts on replica."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=enable_read_replica):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                call_count = 0

                def atomic_side_effect(*args, **kwargs):
                    nonlocal call_count
                    call_count += 1
                    if call_count < 3:
                        raise OperationalError("Replica error")
                    return MagicMock(
                        __enter__=MagicMock(return_value=None),
                        __exit__=MagicMock(return_value=False),
                    )

                with patch(
                    "api.db_utils.transaction.atomic", side_effect=atomic_side_effect
                ):
                    with patch("api.db_utils.time.sleep"):
                        with patch(
                            "api.db_utils.set_read_db_alias", return_value="token"
                        ):
                            with patch("api.db_utils.reset_read_db_alias"):
                                with patch("api.db_utils.logger") as mock_logger:
                                    with rls_transaction(tenant_id):
                                        pass

                                    mock_logger.warning.assert_called_once()
                                    warning_msg = mock_logger.warning.call_args[0][0]
                                    assert "falling back to primary DB" in warning_msg

    def test_rls_transaction_logger_warning_on_fallback(
        self, tenants_fixture, enable_read_replica
    ):
        """Test logger warnings are emitted on fallback to primary."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=enable_read_replica):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                call_count = 0

                def atomic_side_effect(*args, **kwargs):
                    nonlocal call_count
                    call_count += 1
                    if call_count < 3:
                        raise OperationalError("Replica error")
                    return MagicMock(
                        __enter__=MagicMock(return_value=None),
                        __exit__=MagicMock(return_value=False),
                    )

                with patch(
                    "api.db_utils.transaction.atomic", side_effect=atomic_side_effect
                ):
                    with patch("api.db_utils.time.sleep"):
                        with patch(
                            "api.db_utils.set_read_db_alias", return_value="token"
                        ):
                            with patch("api.db_utils.reset_read_db_alias"):
                                with patch("api.db_utils.logger") as mock_logger:
                                    with rls_transaction(tenant_id):
                                        pass

                                    assert mock_logger.info.call_count == 2
                                    assert mock_logger.warning.call_count == 1

    def test_rls_transaction_operational_error_raised_immediately_on_primary(
        self, tenants_fixture
    ):
        """Test OperationalError raised immediately on primary without retry."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=None):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                with patch("api.db_utils.transaction.atomic") as mock_atomic:
                    mock_atomic.side_effect = OperationalError("Primary error")

                    with patch("api.db_utils.time.sleep") as mock_sleep:
                        with pytest.raises(OperationalError):
                            with rls_transaction(tenant_id):
                                pass

                        mock_sleep.assert_not_called()

    def test_rls_transaction_operational_error_raised_after_max_attempts(
        self, tenants_fixture, enable_read_replica
    ):
        """Test OperationalError raised after max attempts on replica."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=enable_read_replica):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                with patch("api.db_utils.transaction.atomic") as mock_atomic:
                    mock_atomic.side_effect = OperationalError(
                        "Persistent replica error"
                    )

                    with patch("api.db_utils.time.sleep"):
                        with patch(
                            "api.db_utils.set_read_db_alias", return_value="token"
                        ):
                            with patch("api.db_utils.reset_read_db_alias"):
                                with pytest.raises(OperationalError):
                                    with rls_transaction(tenant_id):
                                        pass

    def test_rls_transaction_router_token_set_for_non_default_alias(
        self, tenants_fixture
    ):
        """Test router token is set when using non-default alias."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)
        custom_alias = "custom_db"

        with patch("api.db_utils.connections") as mock_connections:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
            mock_connections.__getitem__.return_value = mock_conn
            mock_connections.__contains__.return_value = True

            with patch("api.db_utils.transaction.atomic"):
                with patch("api.db_utils.set_read_db_alias") as mock_set_alias:
                    with patch("api.db_utils.reset_read_db_alias") as mock_reset_alias:
                        mock_set_alias.return_value = "test_token"
                        with rls_transaction(tenant_id, using=custom_alias):
                            pass

                        mock_set_alias.assert_called_once_with(custom_alias)
                        mock_reset_alias.assert_called_once_with("test_token")

    def test_rls_transaction_router_token_reset_in_finally_block(self, tenants_fixture):
        """Test router token is reset in finally block even on error."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)
        custom_alias = "custom_db"

        with patch("api.db_utils.connections") as mock_connections:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
            mock_connections.__getitem__.return_value = mock_conn
            mock_connections.__contains__.return_value = True

            with patch("api.db_utils.transaction.atomic") as mock_atomic:
                mock_atomic.side_effect = Exception("Unexpected error")

                with patch("api.db_utils.set_read_db_alias", return_value="test_token"):
                    with patch("api.db_utils.reset_read_db_alias") as mock_reset_alias:
                        with pytest.raises(Exception):
                            with rls_transaction(tenant_id, using=custom_alias):
                                pass

                        mock_reset_alias.assert_called_once_with("test_token")

    def test_rls_transaction_router_token_not_set_for_default_alias(
        self, tenants_fixture
    ):
        """Test router token is not set when using default alias."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with patch("api.db_utils.get_read_db_alias", return_value=None):
            with patch("api.db_utils.connections") as mock_connections:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connections.__getitem__.return_value = mock_conn
                mock_connections.__contains__.return_value = True

                with patch("api.db_utils.transaction.atomic"):
                    with patch("api.db_utils.set_read_db_alias") as mock_set_alias:
                        with patch(
                            "api.db_utils.reset_read_db_alias"
                        ) as mock_reset_alias:
                            with rls_transaction(tenant_id):
                                pass

                            mock_set_alias.assert_not_called()
                            mock_reset_alias.assert_not_called()

    def test_rls_transaction_set_config_query_executed_with_correct_params(
        self, tenants_fixture
    ):
        """Test SET_CONFIG_QUERY executed with correct parameters."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with rls_transaction(tenant_id) as cursor:
            cursor.execute("SELECT current_setting(%s)", [POSTGRES_TENANT_VAR])
            result = cursor.fetchone()
            assert result[0] == tenant_id

    def test_rls_transaction_custom_parameter(self, tenants_fixture):
        """Test rls_transaction with custom parameter name."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)
        custom_param = "api.user_id"

        with rls_transaction(tenant_id, parameter=custom_param) as cursor:
            cursor.execute("SELECT current_setting(%s)", [custom_param])
            result = cursor.fetchone()
            assert result[0] == tenant_id

    def test_rls_transaction_cursor_yielded_correctly(self, tenants_fixture):
        """Test cursor is yielded correctly."""
        tenant = tenants_fixture[0]
        tenant_id = str(tenant.id)

        with rls_transaction(tenant_id) as cursor:
            assert cursor is not None
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            assert result[0] == 1
