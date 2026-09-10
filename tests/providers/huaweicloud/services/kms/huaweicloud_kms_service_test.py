from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.kms.kms_service import KMS, KMSKey
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "la-south-2"


def _provider_with_client(regional_client):
    """Return a mocked provider whose regional client is the given mock."""
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.generate_regional_clients = mock.MagicMock(
        return_value={REGION: regional_client}
    )
    return provider


class TestKMSService:
    def test_list_keys_parses_keys(self):
        key_data = SimpleNamespace(
            key_id="key-1",
            domain_id="domain-1",
            key_alias="my-key",
            key_state="2",
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_keys.return_value = SimpleNamespace(key_details=[key_data])
        regional_client.show_key_rotation_status.return_value = SimpleNamespace(
            key_rotation_enabled=True,
            rotation_interval="365",
        )

        kms = KMS(_provider_with_client(regional_client))

        assert len(kms.keys) == 1
        key = kms.keys[0]
        assert isinstance(key, KMSKey)
        assert key.id == "key-1"
        assert key.domain_id == "domain-1"
        assert key.alias == "my-key"
        assert key.state == "2"
        assert key.is_rotation_enabled is True
        assert key.rotation_period == "365"
        assert key.region == REGION

    def test_list_keys_rotation_disabled(self):
        key_data = SimpleNamespace(
            key_id="key-2",
            domain_id="domain-1",
            key_alias="",
            key_state="2",
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_keys.return_value = SimpleNamespace(key_details=[key_data])
        regional_client.show_key_rotation_status.return_value = SimpleNamespace(
            key_rotation_enabled=False,
            rotation_interval="",
        )

        kms = KMS(_provider_with_client(regional_client))

        assert len(kms.keys) == 1
        key = kms.keys[0]
        assert key.state == "2"
        assert key.is_rotation_enabled is False
        assert key.rotation_period == ""

    def test_list_keys_rotation_error_swallowed(self):
        key_data = SimpleNamespace(
            key_id="key-3",
            domain_id="domain-1",
            key_alias="k3",
            key_state="2",
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_keys.return_value = SimpleNamespace(key_details=[key_data])
        regional_client.show_key_rotation_status.side_effect = Exception("boom")

        kms = KMS(_provider_with_client(regional_client))

        # The key is still parsed; rotation defaults are used.
        assert len(kms.keys) == 1
        key = kms.keys[0]
        assert key.id == "key-3"
        assert key.is_rotation_enabled is False
        assert key.rotation_period == ""

    def test_list_keys_empty(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_keys.return_value = SimpleNamespace(key_details=[])

        kms = KMS(_provider_with_client(regional_client))

        assert kms.keys == []

    def test_list_keys_handles_sdk_error(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_keys.side_effect = Exception("boom")

        kms = KMS(_provider_with_client(regional_client))

        # Errors are logged and swallowed; no partial/garbage resources.
        assert kms.keys == []
