from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    set_mocked_alibabacloud_provider,
)


class Test_actiontrail_trail_enabled:
    def test_no_trails(self):
        actiontrail_client = mock.MagicMock
        actiontrail_client.trails = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.actiontrail.actiontrail_trail_enabled.actiontrail_trail_enabled.actiontrail_client",
            new=actiontrail_client,
        ):
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_trail_enabled.actiontrail_trail_enabled import (
                actiontrail_trail_enabled,
            )

            actiontrail_client.account_id = ALIBABACLOUD_ACCOUNT_ID
            check = actiontrail_trail_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No enabled ActionTrail trails" in result[0].status_extended

    def test_trail_disabled(self):
        actiontrail_client = mock.MagicMock
        trail_arn = f"acs:actiontrail::{ALIBABACLOUD_ACCOUNT_ID}:trail/test-trail"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.actiontrail.actiontrail_trail_enabled.actiontrail_trail_enabled.actiontrail_client",
            new=actiontrail_client,
        ):
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_trail_enabled.actiontrail_trail_enabled import (
                actiontrail_trail_enabled,
            )
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_service import (
                Trail,
            )

            actiontrail_client.trails = {
                trail_arn: Trail(
                    name="test-trail",
                    arn=trail_arn,
                    region="global",
                    status="Disabled",
                )
            }
            actiontrail_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = actiontrail_trail_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No enabled ActionTrail trails" in result[0].status_extended

    def test_trail_enabled(self):
        actiontrail_client = mock.MagicMock
        trail_arn = f"acs:actiontrail::{ALIBABACLOUD_ACCOUNT_ID}:trail/test-trail"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.actiontrail.actiontrail_trail_enabled.actiontrail_trail_enabled.actiontrail_client",
            new=actiontrail_client,
        ):
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_trail_enabled.actiontrail_trail_enabled import (
                actiontrail_trail_enabled,
            )
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_service import (
                Trail,
            )

            actiontrail_client.trails = {
                trail_arn: Trail(
                    name="test-trail",
                    arn=trail_arn,
                    region="global",
                    status="Enabled",
                )
            }
            actiontrail_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = actiontrail_trail_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "enabled trail(s)" in result[0].status_extended
            assert "test-trail" in result[0].status_extended
