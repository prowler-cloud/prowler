from unittest import mock
from uuid import uuid4

from moto import mock_aws

from tests.providers.aws.utils import AWS_ACCOUNT_ARN, AWS_ACCOUNT_NUMBER

AWS_REGION = "eu-west-1"

ANALYZER_ID = str(uuid4())
ANALYZER_ARN = (
    f"arn:aws:accessanalyzer:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:detector/{ANALYZER_ID}"
)


class Test_accessanalyzer_enabled_fixer:
    @mock_aws
    def test_accessanalyzer_enabled_fixer(self):
        regional_client = mock.MagicMock()
        accessanalyzer_client = mock.MagicMock()

        accessanalyzer_client.region = AWS_REGION
        accessanalyzer_client.analyzers = []
        accessanalyzer_client.audited_account_arn = AWS_ACCOUNT_ARN
        regional_client.create_analyzer.return_value = None
        accessanalyzer_client.regional_clients = {AWS_REGION: regional_client}

        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            accessanalyzer_client,
        ):
            # Test Check
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled.accessanalyzer_enabled_fixer import (
                fixer,
            )

            assert fixer(AWS_REGION)
