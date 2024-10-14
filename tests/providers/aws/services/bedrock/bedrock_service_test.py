from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_Bedrock_Service:
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock = Bedrock(aws_provider)
        assert bedrock.service == "bedrock"

    @mock_aws
    def test_client(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock = Bedrock(aws_provider)
        for regional_client in bedrock.regional_clients.values():
            assert regional_client.__class__.__name__ == "Bedrock"

    @mock_aws
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock = Bedrock(aws_provider)
        assert bedrock.session.__class__.__name__ == "Session"

    @mock_aws
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock = Bedrock(aws_provider)
        assert bedrock.audited_account == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_get_model_invocation_logging_configuration(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock_client_eu_west_1 = client("bedrock", region_name="eu-west-1")
        logging_config = {
            "cloudWatchConfig": {
                "logGroupName": "Test",
                "roleArn": "testrole",
                "largeDataDeliveryS3Config": {
                    "bucketName": "testbucket",
                },
            },
            "s3Config": {
                "bucketName": "testconfigbucket",
            },
        }
        bedrock_client_eu_west_1.put_model_invocation_logging_configuration(
            loggingConfig=logging_config
        )
        bedrock = Bedrock(aws_provider)
        assert len(bedrock.logging_configurations) == 2
        assert bedrock.logging_configurations[AWS_REGION_EU_WEST_1].enabled
        assert (
            bedrock.logging_configurations[AWS_REGION_EU_WEST_1].cloudwatch_log_group
            == "Test"
        )
        assert (
            bedrock.logging_configurations[AWS_REGION_EU_WEST_1].s3_bucket
            == "testconfigbucket"
        )
        assert not bedrock.logging_configurations[AWS_REGION_US_EAST_1].enabled
