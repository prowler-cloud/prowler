from unittest import mock

AWS_REGION = "eu-west-1"


class Test_accessanalyzer_enabled_fixer:
    def test_accessanalyzer_enabled_fixer(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = []
        accessanalyzer_client.regional_clients = {AWS_REGION: accessanalyzer_client}
        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            new=accessanalyzer_client,
        ):
            # Test Check
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled.accessanalyzer_enabled_fixer import (
                fixer,
            )

            assert fixer(AWS_REGION)
