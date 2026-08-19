from unittest import mock

from prowler.lib.check.models import CheckMetadata
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_lts_log_group_retention:
    def test_metadata_references_log_group_retention_api(self):
        metadata = CheckMetadata.parse_file(
            "prowler/providers/huaweicloud/services/lts/"
            "lts_log_group_retention/lts_log_group_retention.metadata.json"
        )

        assert metadata.AdditionalURLs == [
            "https://support.huaweicloud.com/intl/en-us/api-lts/UpdateLogGroup.html"
        ]

    def test_no_log_groups(self):
        lts_client = mock.MagicMock()
        lts_client.log_groups = []
        lts_client.region = "la-south-2"
        lts_client.audited_account = "123456789012"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.lts.lts_log_group_retention.lts_log_group_retention.lts_client",
                new=lts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.lts.lts_log_group_retention.lts_log_group_retention import (
                lts_log_group_retention,
            )

            check = lts_log_group_retention()
            result = check.execute()
            assert result == []

    def test_log_group_adequate_retention(self):
        lts_client = mock.MagicMock()
        lts_client.log_groups = [
            mock.MagicMock(
                log_group_id="group-001",
                log_group_name="app-logs",
                ttl_in_days=30,
                region="la-south-2",
            )
        ]
        lts_client.region = "la-south-2"
        lts_client.audited_account = "123456789012"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.lts.lts_log_group_retention.lts_log_group_retention.lts_client",
                new=lts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.lts.lts_log_group_retention.lts_log_group_retention import (
                lts_log_group_retention,
            )

            check = lts_log_group_retention()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "app-logs" in result[0].status_extended
            assert "30" in result[0].status_extended

    def test_log_group_short_retention(self):
        lts_client = mock.MagicMock()
        lts_client.log_groups = [
            mock.MagicMock(
                log_group_id="group-002",
                log_group_name="short-retention-logs",
                ttl_in_days=7,
                region="la-south-2",
            )
        ]
        lts_client.region = "la-south-2"
        lts_client.audited_account = "123456789012"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.lts.lts_log_group_retention.lts_log_group_retention.lts_client",
                new=lts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.lts.lts_log_group_retention.lts_log_group_retention import (
                lts_log_group_retention,
            )

            check = lts_log_group_retention()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "short-retention-logs" in result[0].status_extended
            assert "7" in result[0].status_extended

    def test_mixed_log_groups(self):
        lts_client = mock.MagicMock()
        lts_client.log_groups = [
            mock.MagicMock(
                log_group_id="group-001",
                log_group_name="app-logs",
                ttl_in_days=60,
                region="la-south-2",
            ),
            mock.MagicMock(
                log_group_id="group-002",
                log_group_name="short-retention-logs",
                ttl_in_days=7,
                region="la-south-2",
            ),
        ]
        lts_client.region = "la-south-2"
        lts_client.audited_account = "123456789012"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.lts.lts_log_group_retention.lts_log_group_retention.lts_client",
                new=lts_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.lts.lts_log_group_retention.lts_log_group_retention import (
                lts_log_group_retention,
            )

            check = lts_log_group_retention()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[1].status == "FAIL"
