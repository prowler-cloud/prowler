from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.evs.evs_service import EVS, Volume
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


class TestEVSService:
    def test_list_volumes_encrypted_via_flag(self):
        vol_data = SimpleNamespace(
            id="vol-1",
            name="encrypted-vol",
            encrypted=True,
            metadata={"__system__cmkid": "cmk-123"},
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_volumes.return_value = SimpleNamespace(volumes=[vol_data])

        evs = EVS(_provider_with_client(regional_client))

        assert len(evs.volumes) == 1
        vol = evs.volumes[0]
        assert isinstance(vol, Volume)
        assert vol.id == "vol-1"
        assert vol.name == "encrypted-vol"
        assert vol.is_encrypted is True
        assert vol.kms_key_id == "cmk-123"
        assert vol.region == REGION

    def test_list_volumes_encrypted_via_metadata(self):
        vol_data = SimpleNamespace(
            id="vol-2",
            name="meta-encrypted",
            encrypted=False,
            metadata={"__system__encrypted": "1", "__system__cmkid": "cmk-9"},
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_volumes.return_value = SimpleNamespace(volumes=[vol_data])

        evs = EVS(_provider_with_client(regional_client))

        vol = evs.volumes[0]
        assert vol.is_encrypted is True
        assert vol.kms_key_id == "cmk-9"

    def test_list_volumes_not_encrypted(self):
        vol_data = SimpleNamespace(
            id="vol-3",
            name="plain-vol",
            encrypted=False,
            metadata={"__system__encrypted": "0"},
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_volumes.return_value = SimpleNamespace(volumes=[vol_data])

        evs = EVS(_provider_with_client(regional_client))

        vol = evs.volumes[0]
        assert vol.is_encrypted is False
        assert vol.kms_key_id == ""

    def test_list_volumes_none_metadata(self):
        vol_data = SimpleNamespace(
            id="vol-4",
            name="no-meta-vol",
            encrypted=False,
            metadata=None,
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_volumes.return_value = SimpleNamespace(volumes=[vol_data])

        evs = EVS(_provider_with_client(regional_client))

        # None metadata must not crash the parser.
        vol = evs.volumes[0]
        assert vol.id == "vol-4"
        assert vol.is_encrypted is False
        assert vol.kms_key_id == ""

    def test_list_volumes_empty(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_volumes.return_value = SimpleNamespace(volumes=[])

        evs = EVS(_provider_with_client(regional_client))

        assert evs.volumes == []

    def test_list_volumes_handles_sdk_error(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_volumes.side_effect = Exception("boom")

        evs = EVS(_provider_with_client(regional_client))

        # Errors are logged and swallowed; no partial/garbage resources.
        assert evs.volumes == []
