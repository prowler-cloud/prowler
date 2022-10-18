from unittest import mock

from providers.aws.services.securityhub.securityhub_service import SecurityHubHub


class Test_accessanalyzer_enabled_without_findings:
    def test_securityhub_hub_inactive(self):
        securityhub_client = mock.MagicMock
        securityhub_client.securityhubs = [
            SecurityHubHub(
                "",
                "",
                "NOT_AVAILABLE",
                "",
                "eu-west-1",
            )
        ]
        with mock.patch(
            "providers.aws.services.securityhub.securityhub_service.SecurityHub",
            new=securityhub_client,
        ):
            # Test Check
            from providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled import (
                securityhub_enabled,
            )

            check = securityhub_enabled()
            result = check.execute()

            assert result[0].status == "FAIL"

    def test_securityhub_hub_active(self):
        securityhub_client = mock.MagicMock
        securityhub_client.securityhubs = [
            SecurityHubHub(
                "arn",
                "id",
                "ACTIVE",
                "standards",
                "eu-west-1",
            )
        ]
        with mock.patch(
            "providers.aws.services.securityhub.securityhub_service.SecurityHub",
            new=securityhub_client,
        ):
            # Test Check
            from providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled import (
                securityhub_enabled,
            )

            check = securityhub_enabled()
            result = check.execute()

            assert result[0].status == "PASS"
