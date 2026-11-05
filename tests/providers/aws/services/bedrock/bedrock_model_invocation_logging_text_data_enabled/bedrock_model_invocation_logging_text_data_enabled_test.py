from unittest import mock

from prowler.providers.aws.services.bedrock.bedrock_service import LoggingConfiguration
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_bedrock_model_invocation_logging_text_data_enabled:
    def _run(self, configs):
        """Execute the check with logging_configurations set to the given region -> config map.

        Returns the list of reports produced, so a caller can assert both the count and each
        verdict.
        """
        # An INSTANCE, not the class. Assigning attributes to mock.MagicMock itself mutates it
        # for every later test in the session -- it poisoned
        # bedrock_model_invocation_logs_encryption_enabled_test with a plain lambda where it
        # expected a mock attribute.
        bedrock_client = mock.MagicMock()
        bedrock_client.logging_configurations = configs
        bedrock_client.audited_account = AWS_ACCOUNT_NUMBER
        bedrock_client.audited_partition = "aws"
        bedrock_client.region = AWS_REGION_US_EAST_1
        bedrock_client._get_model_invocation_logging_arn_template = (
            lambda region: f"arn:aws:bedrock:{region}:{AWS_ACCOUNT_NUMBER}:model-invocation-logging"
        )
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_model_invocation_logging_text_data_enabled.bedrock_model_invocation_logging_text_data_enabled.bedrock_client",
                bedrock_client,
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_model_invocation_logging_text_data_enabled.bedrock_model_invocation_logging_text_data_enabled import (
                bedrock_model_invocation_logging_text_data_enabled,
            )

            return bedrock_model_invocation_logging_text_data_enabled().execute()

    def test_no_logging_configurations(self):
        """No configuration collected for any Region must produce no findings.

        An empty inventory is the state after the collector reached no Region at all, so there is
        nothing to make a claim about; a PASS here would assert content capture nowhere observed.
        """
        assert self._run({}) == []

    def test_logging_disabled_is_out_of_scope(self):
        """A Region with logging off belongs to the sibling check, not this one."""
        result = self._run({AWS_REGION_US_EAST_1: LoggingConfiguration(enabled=False)})
        assert result == []

    def test_text_delivery_enabled(self):
        """Logging on with textDataDeliveryEnabled true must PASS: prompts and responses are captured."""
        result = self._run(
            {
                AWS_REGION_US_EAST_1: LoggingConfiguration(
                    enabled=True,
                    cloudwatch_log_group="/aws/bedrock",
                    text_data_delivery_enabled=True,
                )
            }
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "delivers prompt and response text" in result[0].status_extended
        # The three identity fields were asserted nowhere, so region, resource_id and the ARN
        # template could each have been wrong or dropped with the suite still green. resource_id is "model-invocation-logging" to match both siblings on this
        # configuration; it used to be the account id, which is identical in every Region and so
        # could not distinguish two Regions' findings.
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "model-invocation-logging"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:model-invocation-logging"
        )

    def test_text_delivery_disabled_is_fail(self):
        """The whole point: a destination is configured but bodies are excluded."""
        result = self._run(
            {
                AWS_REGION_US_EAST_1: LoggingConfiguration(
                    enabled=True,
                    cloudwatch_log_group="/aws/bedrock",
                    text_data_delivery_enabled=False,
                )
            }
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "excludes prompt and response text" in result[0].status_extended
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "model-invocation-logging"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:model-invocation-logging"
        )

    def test_text_delivery_unreported_is_manual_not_pass(self):
        """Absent is not False. An unanswered field must not be read as compliant."""
        result = self._run(
            {
                AWS_REGION_US_EAST_1: LoggingConfiguration(
                    enabled=True, cloudwatch_log_group="/aws/bedrock"
                )
            }
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "model-invocation-logging"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:model-invocation-logging"
        )

    def test_multiple_regions_counts_and_split(self):
        """Multi-resource: assert the finding count and the PASS/FAIL split."""
        result = self._run(
            {
                AWS_REGION_US_EAST_1: LoggingConfiguration(
                    enabled=True, text_data_delivery_enabled=True
                ),
                "eu-west-1": LoggingConfiguration(
                    enabled=True, text_data_delivery_enabled=False
                ),
                "us-west-2": LoggingConfiguration(enabled=False),
            }
        )
        assert len(result) == 2
        # Assert the Region-to-status MAPPING, not the multiset. Counting one PASS and one FAIL
        # passes just as happily if the two verdicts are swapped, which is the one thing a
        # per-Region check can get wrong here. The dict also pins that us-west-2, whose logging is
        # off entirely, produces no finding at all rather than a third one.
        assert {r.region: r.status for r in result} == {
            AWS_REGION_US_EAST_1: "PASS",
            "eu-west-1": "FAIL",
        }
