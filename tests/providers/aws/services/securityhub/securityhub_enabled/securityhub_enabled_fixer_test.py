from unittest import mock

from moto import mock_aws

from prowler.providers.aws.services.securityhub.securityhub_service import (
    SecurityHubHub,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1


class test_securityhub_enabled_fixer:
    @mock_aws
    def test_securityhub_enabled_fixer(self):
        securityhub_client = mock.MagicMock
        securityhub_client.securityhubs = [
            SecurityHubHub(
                arn="arn:aws:securityhub:us-east-1:0123456789012:hub/default",
                id="default",
                status="ACTIVE",
                standards="cis-aws-foundations-benchmark/v/1.2.0",
                integrations="",
                region="eu-west-1",
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.securityhub.securityhub_service.SecurityHub",
            new=securityhub_client,
        ):
            # Test Check
            from prowler.providers.aws.services.securityhub.securityhub_enabled.securityhub_enabled_fixer import (
                fixer,
            )

            assert fixer(AWS_REGION_EU_WEST_1)
