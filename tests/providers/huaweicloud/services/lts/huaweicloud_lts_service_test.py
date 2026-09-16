from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.lts.lts_service import LTS, LTSLogGroup
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


class TestLTSService:
    def test_list_log_groups_parses_response(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_log_groups.return_value = SimpleNamespace(
            log_groups=[
                SimpleNamespace(
                    log_group_id="group-id",
                    log_group_name="campaign-pass",
                    ttl_in_days=30,
                )
            ]
        )

        lts = LTS(_provider_with_client(regional_client))

        assert lts.log_groups == [
            LTSLogGroup(
                log_group_id="group-id",
                log_group_name="campaign-pass",
                ttl_in_days=30,
                region=REGION,
            )
        ]

    def test_list_log_groups_handles_sdk_error(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_log_groups.side_effect = Exception("boom")

        lts = LTS(_provider_with_client(regional_client))

        assert lts.log_groups == []
