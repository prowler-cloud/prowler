from unittest import mock

from prowler.providers.aws.services.securityhub.securityhub_service import (
    SecurityHubHub,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

# Patching the check client imports securityhub_client, which instantiates
# SecurityHub against the global provider at module level. Stubbing the class
# first keeps that import from reaching AWS when this file runs on its own.
SERVICE_MODULE = "prowler.providers.aws.services.securityhub.securityhub_service"
CHECK_MODULE = (
    "prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled"
)

HUB_ARN = f"arn:aws:securityhub:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:hub/default"
UNKNOWN_HUB_ARN = (
    f"arn:aws:securityhub:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:hub/unknown"
)


def _mocked_securityhub_client(securityhubs: list, audit_config: dict = None):
    """Build a Security Hub client mock holding the given hubs."""
    securityhub_client = mock.MagicMock()
    securityhub_client.region = AWS_REGION_EU_WEST_1
    securityhub_client.audited_partition = "aws"
    securityhub_client.audited_account = AWS_ACCOUNT_NUMBER
    securityhub_client.audit_config = audit_config if audit_config is not None else {}
    securityhub_client.securityhubs = securityhubs
    return securityhub_client


class Test_securityhub_enabled:
    def test_securityhub_hub_inactive(self):
        securityhub_client = _mocked_securityhub_client(
            [
                SecurityHubHub(
                    arn=UNKNOWN_HUB_ARN,
                    id="hub/unknown",
                    status="NOT_AVAILABLE",
                    standards="",
                    integrations="",
                    region=AWS_REGION_EU_WEST_1,
                    tags=[{"test_key": "test_value"}],
                )
            ]
        )

        with (
            mock.patch(f"{SERVICE_MODULE}.SecurityHub", new=mock.MagicMock()),
            mock.patch(f"{CHECK_MODULE}.securityhub_client", new=securityhub_client),
        ):
            # Test Check
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled import (
                securityhub_enabled,
            )

            check = securityhub_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "Security Hub is not enabled."
            assert result[0].resource_id == "hub/unknown"
            assert result[0].resource_arn == UNKNOWN_HUB_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"test_key": "test_value"}]

    def test_securityhub_hub_active_with_standards(self):
        securityhub_client = _mocked_securityhub_client(
            [
                SecurityHubHub(
                    arn=HUB_ARN,
                    id="default",
                    status="ACTIVE",
                    standards="cis-aws-foundations-benchmark/v/1.2.0",
                    integrations="",
                    region=AWS_REGION_EU_WEST_1,
                    tags=[{"test_key": "test_value"}],
                )
            ]
        )

        with (
            mock.patch(f"{SERVICE_MODULE}.SecurityHub", new=mock.MagicMock()),
            mock.patch(f"{CHECK_MODULE}.securityhub_client", new=securityhub_client),
        ):
            # Test Check
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled import (
                securityhub_enabled,
            )

            check = securityhub_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Security Hub is enabled with standards: cis-aws-foundations-benchmark/v/1.2.0."
            )
            assert result[0].resource_id == "default"
            assert result[0].resource_arn == HUB_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"test_key": "test_value"}]

    def test_securityhub_hub_active_with_integrations(self):
        securityhub_client = _mocked_securityhub_client(
            [
                SecurityHubHub(
                    arn=HUB_ARN,
                    id="default",
                    status="ACTIVE",
                    standards="",
                    integrations="prowler",
                    region=AWS_REGION_EU_WEST_1,
                    tags=[{"test_key": "test_value"}],
                )
            ]
        )

        with (
            mock.patch(f"{SERVICE_MODULE}.SecurityHub", new=mock.MagicMock()),
            mock.patch(f"{CHECK_MODULE}.securityhub_client", new=securityhub_client),
        ):
            # Test Check
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled import (
                securityhub_enabled,
            )

            check = securityhub_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Security Hub is enabled without standards but with integrations: prowler."
            )
            assert result[0].resource_id == "default"
            assert result[0].resource_arn == HUB_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"test_key": "test_value"}]

    def test_securityhub_hub_active_without_integrations_or_standards(self):
        securityhub_client = _mocked_securityhub_client(
            [
                SecurityHubHub(
                    arn=HUB_ARN,
                    id="default",
                    status="ACTIVE",
                    standards="",
                    integrations="",
                    region=AWS_REGION_EU_WEST_1,
                    tags=[{"test_key": "test_value"}],
                )
            ]
        )

        with (
            mock.patch(f"{SERVICE_MODULE}.SecurityHub", new=mock.MagicMock()),
            mock.patch(f"{CHECK_MODULE}.securityhub_client", new=securityhub_client),
        ):
            # Test Check
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled import (
                securityhub_enabled,
            )

            check = securityhub_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert not result[0].muted
            assert (
                result[0].status_extended
                == "Security Hub is enabled but without any standard or integration."
            )
            assert result[0].resource_id == "default"
            assert result[0].resource_arn == HUB_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == [{"test_key": "test_value"}]

    def test_securityhub_hub_active_without_integrations_or_standards_muted(self):
        securityhub_client = _mocked_securityhub_client(
            [
                SecurityHubHub(
                    arn=HUB_ARN,
                    id="default",
                    status="ACTIVE",
                    standards="",
                    integrations="",
                    region="eu-south-2",
                    tags=[],
                )
            ],
            audit_config={"mute_non_default_regions": True},
        )

        with (
            mock.patch(f"{SERVICE_MODULE}.SecurityHub", new=mock.MagicMock()),
            mock.patch(f"{CHECK_MODULE}.securityhub_client", new=securityhub_client),
        ):
            # Test Check
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled import (
                securityhub_enabled,
            )

            check = securityhub_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].muted
            assert (
                result[0].status_extended
                == "Security Hub is enabled but without any standard or integration."
            )
            assert result[0].resource_id == "default"
            assert result[0].resource_arn == HUB_ARN
            assert result[0].region == "eu-south-2"
            assert result[0].resource_tags == []
