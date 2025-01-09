from unittest import mock

from prowler.providers.aws.services.securityhub.securityhub_service import (
    SecurityHubHub,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1


class Test_securityhub_enabled:
    def test_securityhub_hub_inactive(self):
        securityhub_client = mock.MagicMock
        securityhub_client.region = AWS_REGION_EU_WEST_1
        securityhub_client.get_unknown_arn = (
            lambda x: f"arn:aws:securityhub:{x}:0123456789012:hub/unknown"
        )
        securityhub_client.securityhubs = [
            SecurityHubHub(
                arn=f"arn:aws:securityhub:{AWS_REGION_EU_WEST_1}:0123456789012:hub/unknown",
                id="hub/unknown",
                status="NOT_AVAILABLE",
                standards="",
                integrations="",
                region=AWS_REGION_EU_WEST_1,
                tags=[{"test_key": "test_value"}],
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.securityhub.securityhub_service.SecurityHub",
            new=securityhub_client,
        ), mock.patch(
            "prowler.providers.aws.services.securityhub.securityhub_service.SecurityHub.get_unknown_arn",
            return_value="arn:aws:securityhub:eu-west-1:0123456789012:hub/unknown",
        ):
            # Test Check
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled import (
                securityhub_enabled,
            )

            check = securityhub_enabled()
            result = check.execute()

            assert result[0].status == "FAIL"
            assert result[0].status_extended == "Security Hub is not enabled."
            assert result[0].resource_id == "hub/unknown"
            assert (
                result[0].resource_arn
                == "arn:aws:securityhub:eu-west-1:0123456789012:hub/unknown"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"test_key": "test_value"}]

    def test_securityhub_hub_active_with_standards(self):
        securityhub_client = mock.MagicMock
        securityhub_client.securityhubs = [
            SecurityHubHub(
                arn="arn:aws:securityhub:us-east-1:0123456789012:hub/default",
                id="default",
                status="ACTIVE",
                standards="cis-aws-foundations-benchmark/v/1.2.0",
                integrations="",
                region=AWS_REGION_EU_WEST_1,
                tags=[{"test_key": "test_value"}],
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.securityhub.securityhub_service.SecurityHub",
            new=securityhub_client,
        ):
            # Test Check
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled import (
                securityhub_enabled,
            )

            check = securityhub_enabled()
            result = check.execute()

            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Security Hub is enabled with standards: cis-aws-foundations-benchmark/v/1.2.0."
            )
            assert result[0].resource_id == "default"
            assert (
                result[0].resource_arn
                == "arn:aws:securityhub:us-east-1:0123456789012:hub/default"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"test_key": "test_value"}]

    def test_securityhub_hub_active_with_integrations(self):
        securityhub_client = mock.MagicMock
        securityhub_client.securityhubs = [
            SecurityHubHub(
                arn="arn:aws:securityhub:us-east-1:0123456789012:hub/default",
                id="default",
                status="ACTIVE",
                standards="",
                integrations="prowler",
                region=AWS_REGION_EU_WEST_1,
                tags=[{"test_key": "test_value"}],
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.securityhub.securityhub_service.SecurityHub",
            new=securityhub_client,
        ):
            # Test Check
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled import (
                securityhub_enabled,
            )

            check = securityhub_enabled()
            result = check.execute()

            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Security Hub is enabled without standards but with integrations: prowler."
            )
            assert result[0].resource_id == "default"
            assert (
                result[0].resource_arn
                == "arn:aws:securityhub:us-east-1:0123456789012:hub/default"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"test_key": "test_value"}]

    def test_securityhub_hub_active_without_integrations_or_standards(self):
        securityhub_client = mock.MagicMock
        securityhub_client.region = AWS_REGION_EU_WEST_1
        securityhub_client.audited_partition = "aws"
        securityhub_client.audited_account = "0123456789012"
        securityhub_client.securityhubs = [
            SecurityHubHub(
                arn="arn:aws:securityhub:us-east-1:0123456789012:hub/default",
                id="default",
                status="ACTIVE",
                standards="",
                integrations="",
                region=AWS_REGION_EU_WEST_1,
                tags=[{"test_key": "test_value"}],
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.securityhub.securityhub_service.SecurityHub",
            new=securityhub_client,
        ):
            # Test Check
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled import (
                securityhub_enabled,
            )

            check = securityhub_enabled()
            result = check.execute()

            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Security Hub is enabled but without any standard or integration."
            )
            assert result[0].resource_id == "default"
            assert (
                result[0].resource_arn
                == "arn:aws:securityhub:us-east-1:0123456789012:hub/default"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"test_key": "test_value"}]

    def test_securityhub_hub_active_without_integrations_or_standards_muted(self):
        securityhub_client = mock.MagicMock
        securityhub_client.audit_config = {"mute_non_default_regions": True}
        securityhub_client.region = AWS_REGION_EU_WEST_1
        securityhub_client.audited_partition = "aws"
        securityhub_client.audited_account = "0123456789012"
        securityhub_client.securityhubs = [
            SecurityHubHub(
                arn="arn:aws:securityhub:us-east-1:0123456789012:hub/default",
                id="default",
                status="ACTIVE",
                standards="",
                integrations="",
                region="eu-south-2",
                tags=[],
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.securityhub.securityhub_service.SecurityHub",
            new=securityhub_client,
        ):
            # Test Check
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled import (
                securityhub_enabled,
            )

            check = securityhub_enabled()
            result = check.execute()

            assert result[0].status == "FAIL"
            assert result[0].muted
            assert (
                result[0].status_extended
                == "Security Hub is enabled but without any standard or integration."
            )
            assert result[0].resource_id == "default"
            assert (
                result[0].resource_arn
                == "arn:aws:securityhub:us-east-1:0123456789012:hub/default"
            )
            assert result[0].region == "eu-south-2"
            assert result[0].resource_tags == []
