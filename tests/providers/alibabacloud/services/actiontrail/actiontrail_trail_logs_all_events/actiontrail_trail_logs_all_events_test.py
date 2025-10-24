from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    set_mocked_alibabacloud_provider,
)


class Test_actiontrail_trail_logs_all_events:
    def test_no_trails(self):
        actiontrail_client = mock.MagicMock
        actiontrail_client.trails = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.actiontrail.actiontrail_trail_logs_all_events.actiontrail_trail_logs_all_events.actiontrail_client",
            new=actiontrail_client,
        ):
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_trail_logs_all_events.actiontrail_trail_logs_all_events import (
                actiontrail_trail_logs_all_events,
            )

            check = actiontrail_trail_logs_all_events()
            result = check.execute()
            assert len(result) == 0

    def test_trail_logs_only_write_events(self):
        actiontrail_client = mock.MagicMock
        trail_arn = f"acs:actiontrail::{ALIBABACLOUD_ACCOUNT_ID}:trail/test-trail"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.actiontrail.actiontrail_trail_logs_all_events.actiontrail_trail_logs_all_events.actiontrail_client",
            new=actiontrail_client,
        ):
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_trail_logs_all_events.actiontrail_trail_logs_all_events import (
                actiontrail_trail_logs_all_events,
            )
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_service import (
                Trail,
            )

            actiontrail_client.trails = {
                trail_arn: Trail(
                    name="test-trail",
                    arn=trail_arn,
                    region="global",
                    event_rw="Write",
                )
            }
            actiontrail_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = actiontrail_trail_logs_all_events()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "test-trail"
            assert "only logs Write events" in result[0].status_extended

    def test_trail_logs_all_events(self):
        actiontrail_client = mock.MagicMock
        trail_arn = f"acs:actiontrail::{ALIBABACLOUD_ACCOUNT_ID}:trail/test-trail"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.actiontrail.actiontrail_trail_logs_all_events.actiontrail_trail_logs_all_events.actiontrail_client",
            new=actiontrail_client,
        ):
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_trail_logs_all_events.actiontrail_trail_logs_all_events import (
                actiontrail_trail_logs_all_events,
            )
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_service import (
                Trail,
            )

            actiontrail_client.trails = {
                trail_arn: Trail(
                    name="test-trail",
                    arn=trail_arn,
                    region="global",
                    event_rw="All",
                )
            }
            actiontrail_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = actiontrail_trail_logs_all_events()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "test-trail"
            assert "logs all events" in result[0].status_extended
