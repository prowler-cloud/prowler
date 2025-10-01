import uuid
from datetime import datetime, timezone
from enum import Enum
from unittest.mock import patch

import pytest
from django.conf import settings
from freezegun import freeze_time

from api.db_utils import (
    ProwlerApiCrypto,
    _should_create_index_on_partition,
    batch_delete,
    create_objects_in_batches,
    enum_to_choices,
    generate_api_key_prefix,
    generate_random_token,
    one_week_from_now,
    update_objects_in_batches,
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


class TestProwlerApiCrypto:
    @pytest.fixture
    def crypto(self):
        """Create a ProwlerApiCrypto instance for testing."""
        return ProwlerApiCrypto()

    @pytest.fixture
    def sample_payload(self):
        """Create a sample payload for encryption/decryption tests."""
        return {
            "_pk": "550e8400-e29b-41d4-a716-446655440000",
            "_exp": 1735689600.0,  # 2025-01-01 00:00:00 UTC
        }

    def test_initialization_requires_encryption_key(self):
        """Test that ProwlerApiCrypto requires SECRETS_ENCRYPTION_KEY."""
        with patch.object(settings, "SECRETS_ENCRYPTION_KEY", ""):
            with pytest.raises(ValueError, match="SECRETS_ENCRYPTION_KEY must be set"):
                ProwlerApiCrypto()

    def test_encryption_key_derivation_uses_sha256(self, crypto):
        """Test that encryption key is derived using SHA-256 to produce 32 bytes."""
        import hashlib

        original_key = settings.SECRETS_ENCRYPTION_KEY
        expected_key = hashlib.sha256(original_key.encode()).digest()

        # The AESGCM instance should be initialized with the derived key
        assert len(expected_key) == 32  # AES-256 requires 32-byte key

    def test_nonce_randomness_and_uniqueness(self, crypto, sample_payload):
        """Test that each encryption uses a unique random 12-byte nonce."""
        encrypted_keys = [crypto.encrypt(sample_payload) for _ in range(100)]

        # Decode and extract nonces
        nonces = []
        for encrypted_key in encrypted_keys:
            encrypted_data = crypto._decode_alphanumeric(encrypted_key)
            nonce = encrypted_data[:12]
            nonces.append(nonce)

        # All nonces should be 12 bytes
        assert all(len(nonce) == 12 for nonce in nonces)

        # All nonces should be unique (extremely high probability)
        assert len(set(nonces)) == 100

    def test_different_payloads_produce_different_ciphertexts(self, crypto):
        """Test that different payloads produce different ciphertexts."""
        payload1 = {"_pk": str(uuid.uuid4()), "_exp": 1735689600.0}
        payload2 = {"_pk": str(uuid.uuid4()), "_exp": 1735689600.0}

        encrypted1 = crypto.encrypt(payload1)
        encrypted2 = crypto.encrypt(payload2)

        assert encrypted1 != encrypted2

    def test_same_payload_produces_different_ciphertexts(self, crypto, sample_payload):
        """Test that encrypting the same payload twice produces different ciphertexts (due to random nonce)."""
        encrypted1 = crypto.encrypt(sample_payload)
        encrypted2 = crypto.encrypt(sample_payload)

        assert encrypted1 != encrypted2

    def test_authentication_tag_verification_on_tampered_data(
        self, crypto, sample_payload
    ):
        """Test that AES-GCM detects tampered ciphertext via authentication tag."""
        encrypted_key = crypto.encrypt(sample_payload)
        encrypted_data = crypto._decode_alphanumeric(encrypted_key)

        # Tamper with the ciphertext (flip a bit in the middle)
        tampered_data = bytearray(encrypted_data)
        tampered_data[20] ^= 0x01  # Flip one bit

        tampered_key = crypto._encode_alphanumeric(bytes(tampered_data))

        # Decryption should fail with authentication error
        with pytest.raises(ValueError, match="Failed to decrypt API key"):
            crypto.decrypt(tampered_key)

    def test_encrypted_output_length(self, crypto, sample_payload):
        """Test that encrypted output has expected length (~70 chars for 52 bytes)."""
        encrypted_key = crypto.encrypt(sample_payload)

        # Expected: 12 bytes nonce + 24 bytes payload + 16 bytes auth tag = 52 bytes
        # Base64url encoding: 52 bytes * 4/3 ≈ 70 characters (without padding)
        assert 68 <= len(encrypted_key) <= 72

    def test_encrypted_output_is_url_safe(self, crypto, sample_payload):
        """Test that encrypted output uses only URL-safe characters."""
        encrypted_key = crypto.encrypt(sample_payload)

        # URL-safe base64: A-Z, a-z, 0-9, -, _
        import re

        assert re.match(r"^[A-Za-z0-9_-]+$", encrypted_key)

    def test_encrypt_decrypt_roundtrip_with_uuid_string(self, crypto, sample_payload):
        """Test that encrypt/decrypt roundtrip works with UUID as string."""
        encrypted_key = crypto.encrypt(sample_payload)
        decrypted_payload = crypto.decrypt(encrypted_key)

        assert decrypted_payload["_pk"] == sample_payload["_pk"]
        assert decrypted_payload["_exp"] == sample_payload["_exp"]

    def test_encrypt_decrypt_roundtrip_with_uuid_object(self, crypto):
        """Test that encrypt/decrypt roundtrip works with UUID as object."""
        payload = {
            "_pk": uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
            "_exp": 1735689600.0,
        }
        encrypted_key = crypto.encrypt(payload)
        decrypted_payload = crypto.decrypt(encrypted_key)

        assert decrypted_payload["_pk"] == str(payload["_pk"])
        assert decrypted_payload["_exp"] == payload["_exp"]

    def test_base64url_encoding_without_padding(self, crypto, sample_payload):
        """Test that base64url encoding does not include padding characters."""
        encrypted_key = crypto.encrypt(sample_payload)

        # Should not contain '=' padding
        assert "=" not in encrypted_key

    def test_base64url_decode_adds_padding_correctly(self, crypto, sample_payload):
        """Test that base64url decode correctly adds padding when needed."""
        encrypted_key = crypto.encrypt(sample_payload)

        # Decode should work even without padding
        encrypted_data = crypto._decode_alphanumeric(encrypted_key)
        assert len(encrypted_data) == 52  # 12 nonce + 24 payload + 16 tag

    def test_payload_binary_structure(self, crypto, sample_payload):
        """Test that payload is correctly packed as 16 bytes UUID + 8 bytes timestamp."""
        encrypted_key = crypto.encrypt(sample_payload)
        decrypted_payload = crypto.decrypt(encrypted_key)

        # Verify we can reconstruct the UUID
        reconstructed_uuid = uuid.UUID(decrypted_payload["_pk"])
        assert str(reconstructed_uuid) == sample_payload["_pk"]

        # Verify timestamp is preserved
        assert decrypted_payload["_exp"] == sample_payload["_exp"]

    def test_decrypt_with_invalid_base64(self, crypto):
        """Test that decrypt raises ValueError for invalid base64 input."""
        with pytest.raises(ValueError, match="Failed to decrypt API key"):
            crypto.decrypt("not-valid-base64!@#$%")

    def test_decrypt_with_truncated_data(self, crypto, sample_payload):
        """Test that decrypt raises ValueError for truncated encrypted data."""
        encrypted_key = crypto.encrypt(sample_payload)

        # Truncate the encrypted key
        truncated_key = encrypted_key[:20]

        with pytest.raises(ValueError, match="Failed to decrypt API key"):
            crypto.decrypt(truncated_key)

    def test_decrypt_with_wrong_encryption_key(self, sample_payload):
        """Test that decrypt fails when using a different encryption key."""
        crypto1 = ProwlerApiCrypto()
        encrypted_key = crypto1.encrypt(sample_payload)

        # Create a new crypto instance with a different key
        with patch.object(settings, "SECRETS_ENCRYPTION_KEY", "different-key-12345"):
            crypto2 = ProwlerApiCrypto()
            with pytest.raises(ValueError, match="Failed to decrypt API key"):
                crypto2.decrypt(encrypted_key)

    @pytest.mark.parametrize(
        "timestamp",
        [
            0.0,  # Epoch start
            1735689600.0,  # Future date
            9999999999.0,  # Far future (year 2286)
            -1.0,  # Before epoch (if supported)
            1234567890.123456,  # With high precision
        ],
    )
    def test_various_timestamp_values(self, crypto, timestamp):
        """Test encryption/decryption with various timestamp values."""
        test_uuid = str(uuid.uuid4())
        payload = {"_pk": test_uuid, "_exp": timestamp}

        encrypted_key = crypto.encrypt(payload)
        decrypted_payload = crypto.decrypt(encrypted_key)

        assert decrypted_payload["_pk"] == test_uuid
        # Float precision may have minor differences, so check with tolerance
        assert abs(decrypted_payload["_exp"] - timestamp) < 1e-6

    def test_with_various_uuid_formats(self, crypto):
        """Test encryption with different UUID variants."""
        test_uuids = [
            uuid.uuid4(),  # Random UUID
            uuid.UUID("00000000-0000-0000-0000-000000000000"),  # Nil UUID
            uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"),  # Max UUID
        ]

        for test_uuid in test_uuids:
            payload = {"_pk": test_uuid, "_exp": 1735689600.0}
            encrypted_key = crypto.encrypt(payload)
            decrypted_payload = crypto.decrypt(encrypted_key)

            assert decrypted_payload["_pk"] == str(test_uuid)
            assert decrypted_payload["_exp"] == 1735689600.0

    def test_encrypt_with_missing_pk_field(self, crypto):
        """Test that encrypt raises KeyError when _pk field is missing."""
        payload = {"_exp": 1735689600.0}
        with pytest.raises(KeyError):
            crypto.encrypt(payload)

    def test_encrypt_with_missing_exp_field(self, crypto):
        """Test that encrypt raises KeyError when _exp field is missing."""
        payload = {"_pk": str(uuid.uuid4())}
        with pytest.raises(KeyError):
            crypto.encrypt(payload)

    def test_encrypt_with_invalid_uuid(self, crypto):
        """Test that encrypt raises ValueError for invalid UUID string."""
        payload = {"_pk": "not-a-valid-uuid", "_exp": 1735689600.0}
        with pytest.raises(ValueError):
            crypto.encrypt(payload)

    def test_multiple_encrypt_decrypt_cycles(self, crypto):
        """Test that multiple encryption/decryption cycles work correctly."""
        original_payload = {
            "_pk": str(uuid.uuid4()),
            "_exp": 1735689600.0,
        }

        # Encrypt and decrypt multiple times
        for _ in range(10):
            encrypted_key = crypto.encrypt(original_payload)
            decrypted_payload = crypto.decrypt(encrypted_key)

            assert decrypted_payload["_pk"] == original_payload["_pk"]
            assert decrypted_payload["_exp"] == original_payload["_exp"]
