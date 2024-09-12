from unittest import mock

AWS_REGION = "eu-west-1"


class Test_accessanalyzer_enabled_fixer:
    @mock.patch(
        "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer"
    )
    def test_accessanalyzer_enabled_fixer(self, mock_accessanalyzer_client_class):
        mock_client = mock.MagicMock()
        mock_client.create_analyzer.return_value = None
        mock_accessanalyzer_client_class.return_value.regional_clients = {
            AWS_REGION: mock_client
        }
        mock_accessanalyzer_client_class.return_value.fixer_config = {
            "accessanalyzer_enabled": {
                "AnalyzerName": "DefaultAnalyzer",
                "AnalyzerType": "ACCOUNT_UNUSED_ACCESS",
            }
        }

        from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled.accessanalyzer_enabled_fixer import (
            fixer,
        )

        result = fixer(AWS_REGION)
        assert result
