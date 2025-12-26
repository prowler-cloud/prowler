from unittest.mock import patch

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
