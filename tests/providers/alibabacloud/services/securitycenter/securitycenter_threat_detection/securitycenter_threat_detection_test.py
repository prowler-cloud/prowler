from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_securitycenter_threat_detection:
    def test_no_config(self):
        securitycenter_client = mock.MagicMock
        securitycenter_client.config = None

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.securitycenter.securitycenter_threat_detection.securitycenter_threat_detection.securitycenter_client",
            new=securitycenter_client,
        ):
            from prowler.providers.alibabacloud.services.securitycenter.securitycenter_threat_detection.securitycenter_threat_detection import (
                securitycenter_threat_detection,
            )

            check = securitycenter_threat_detection()
            result = check.execute()
            assert len(result) == 0

    def test_threat_detection_enabled(self):
        securitycenter_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.securitycenter.securitycenter_threat_detection.securitycenter_threat_detection.securitycenter_client",
            new=securitycenter_client,
        ):
            from prowler.providers.alibabacloud.services.securitycenter.securitycenter_threat_detection.securitycenter_threat_detection import (
                securitycenter_threat_detection,
            )
            from prowler.providers.alibabacloud.services.securitycenter.securitycenter_service import (
                SecurityCenterConfig,
            )

            securitycenter_client.config = SecurityCenterConfig(
                enabled=True,
                threat_detection=True,
            )
            securitycenter_client.account_id = ALIBABACLOUD_ACCOUNT_ID
            securitycenter_client.region = ALIBABACLOUD_REGION

            check = securitycenter_threat_detection()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == ALIBABACLOUD_REGION

    def test_threat_detection_disabled(self):
        securitycenter_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.securitycenter.securitycenter_threat_detection.securitycenter_threat_detection.securitycenter_client",
            new=securitycenter_client,
        ):
            from prowler.providers.alibabacloud.services.securitycenter.securitycenter_threat_detection.securitycenter_threat_detection import (
                securitycenter_threat_detection,
            )
            from prowler.providers.alibabacloud.services.securitycenter.securitycenter_service import (
                SecurityCenterConfig,
            )

            securitycenter_client.config = SecurityCenterConfig(
                enabled=True,
                threat_detection=False,
            )
            securitycenter_client.account_id = ALIBABACLOUD_ACCOUNT_ID
            securitycenter_client.region = ALIBABACLOUD_REGION

            check = securitycenter_threat_detection()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == ALIBABACLOUD_REGION
