from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestActionTrailMultiRegionEnabled:
    def test_no_multi_region_trail_fails(self):
        actiontrail_client = mock.MagicMock()
        actiontrail_client.trails = {}
        actiontrail_client.region = "cn-hangzhou"
        actiontrail_client.audited_account = "1234567890"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.actiontrail.actiontrail_multi_region_enabled.actiontrail_multi_region_enabled.actiontrail_client",
                new=actiontrail_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_multi_region_enabled.actiontrail_multi_region_enabled import (
                actiontrail_multi_region_enabled,
            )

            check = actiontrail_multi_region_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not configured" in result[0].status_extended

    def test_enabled_multi_region_trail_passes(self):
        actiontrail_client = mock.MagicMock()
        actiontrail_client.region = "cn-hangzhou"
        actiontrail_client.audited_account = "1234567890"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.actiontrail.actiontrail_multi_region_enabled.actiontrail_multi_region_enabled.actiontrail_client",
                new=actiontrail_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_multi_region_enabled.actiontrail_multi_region_enabled import (
                actiontrail_multi_region_enabled,
            )
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_service import (
                Trail,
            )

            trail = Trail(
                arn="acs:actiontrail::1234567890:trail/multi",
                name="multi",
                home_region="cn-hangzhou",
                trail_region="All",
                status="Enable",
                oss_bucket_name="logs",
                oss_bucket_location="cn-hangzhou",
                sls_project_arn="",
                event_rw="All",
            )

            actiontrail_client.trails = {trail.arn: trail}

            check = actiontrail_multi_region_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "multi-region trail(s)" in result[0].status_extended
            assert "multi" in result[0].status_extended
