from unittest import mock

from tests.providers.aws.utils import AWS_ACCOUNT_ARN, AWS_REGION_EU_WEST_1


class Test_accessanalyzer_enabled_fixer:
    def test_accessanalyzer_enabled_fixer(self):
        regional_client = mock.MagicMock()
        accessanalyzer_client = mock.MagicMock()

        accessanalyzer_client.region = AWS_REGION_EU_WEST_1
        accessanalyzer_client.analyzers = []
        accessanalyzer_client.audited_account_arn = AWS_ACCOUNT_ARN
        regional_client.create_analyzer.return_value = None
        accessanalyzer_client.regional_clients = {AWS_REGION_EU_WEST_1: regional_client}

        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            new=accessanalyzer_client,
        ) as accessanalyzer_client, mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_client.accessanalyzer_client",
            new=accessanalyzer_client,
        ):
            # Test Check
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled.accessanalyzer_enabled_fixer import (
                fixer,
            )

            assert fixer(AWS_REGION_EU_WEST_1)
