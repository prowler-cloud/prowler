from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestActionTrailService:
    def test_service(self):
        alibabacloud_provider = set_mocked_alibabacloud_provider()

        with patch(
            "prowler.providers.alibabacloud.services.actiontrail.actiontrail_service.ActionTrail.__init__",
            return_value=None,
        ):
            from prowler.providers.alibabacloud.services.actiontrail.actiontrail_service import (
                ActionTrail,
            )

            actiontrail_client = ActionTrail(alibabacloud_provider)
            actiontrail_client.service = "actiontrail"
            actiontrail_client.provider = alibabacloud_provider
            actiontrail_client.regional_clients = {}

            assert actiontrail_client.service == "actiontrail"
            assert actiontrail_client.provider == alibabacloud_provider

    def test_describe_trails_retries_transient_connection_reset(self):
        from prowler.providers.alibabacloud.services.actiontrail import (
            actiontrail_service as actiontrail_service_module,
        )

        class ConnectionResetError(Exception):
            pass

        service = actiontrail_service_module.ActionTrail.__new__(
            actiontrail_service_module.ActionTrail
        )
        service.audited_account = "1234567890"
        service.audit_resources = []
        service.trails = {}

        regional_client = MagicMock()
        regional_client.region = "cn-shenzhen"
        regional_client.describe_trails.side_effect = [
            ConnectionResetError(
                "('Connection aborted.', ConnectionResetError(54, 'Connection reset by peer'))"
            ),
            SimpleNamespace(
                body=SimpleNamespace(
                    trail_list=[
                        SimpleNamespace(
                            name="trail-1",
                            trail_region="All",
                            home_region="cn-hangzhou",
                            status="Enable",
                            oss_bucket_name="bucket-1",
                            oss_bucket_location="cn-hangzhou",
                            sls_project_arn="",
                            event_rw="All",
                            create_time="2026-01-01T00:00:00Z",
                        )
                    ]
                )
            ),
        ]

        with patch.object(
            actiontrail_service_module,
            "actiontrail_models",
            SimpleNamespace(DescribeTrailsRequest=MagicMock(return_value=object())),
        ):
            service._describe_trails(regional_client)

        assert regional_client.describe_trails.call_count == 2
        assert len(service.trails) == 1
