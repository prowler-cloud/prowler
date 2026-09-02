from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.sfs.sfs_service import SFS, SFSShare
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "eu-west-101"


def _provider_with_client(regional_client):
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.session.is_mock = False
    provider.generate_regional_clients = mock.MagicMock(
        return_value={REGION: regional_client}
    )
    return provider


class TestSFSService:
    def test_real_session_without_is_mock_lists_shares(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_shares.return_value = SimpleNamespace(shares=[])
        provider = _provider_with_client(regional_client)
        del provider.session.is_mock

        assert SFS(provider).shares == []
        regional_client.list_shares.assert_called_once()

    def test_list_shares_parses_encryption_state(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_shares.return_value = SimpleNamespace(
            shares=[
                SimpleNamespace(
                    id="sfs-encrypted",
                    name="encrypted-share",
                    crypt_key_id="kms-key-1",
                ),
                SimpleNamespace(id="sfs-plain", name="plain-share"),
            ]
        )

        sfs = SFS(_provider_with_client(regional_client))

        assert sfs.shares == [
            SFSShare(
                share_id="sfs-encrypted",
                name="encrypted-share",
                crypt_key_id="kms-key-1",
                region=REGION,
            ),
            SFSShare(
                share_id="sfs-plain",
                name="plain-share",
                crypt_key_id="",
                region=REGION,
            ),
        ]

    def test_list_shares_paginates(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_shares.side_effect = [
            SimpleNamespace(
                shares=[
                    SimpleNamespace(id=f"sfs-{index}", name=f"share-{index}")
                    for index in range(1000)
                ]
            ),
            SimpleNamespace(shares=[SimpleNamespace(id="sfs-1000", name="share-1000")]),
        ]

        sfs = SFS(_provider_with_client(regional_client))

        assert len(sfs.shares) == 1001
        assert sfs.shares[-1].share_id == "sfs-1000"
        assert regional_client.list_shares.call_count == 2
        assert regional_client.list_shares.call_args_list[1].args[0].offset == 1000

    def test_list_shares_handles_empty_response(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_shares.return_value = SimpleNamespace(shares=[])

        assert SFS(_provider_with_client(regional_client)).shares == []

    def test_list_shares_handles_sdk_error(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_shares.side_effect = Exception("boom")

        assert SFS(_provider_with_client(regional_client)).shares == []
