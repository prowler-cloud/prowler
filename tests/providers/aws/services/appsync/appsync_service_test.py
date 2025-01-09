from boto3 import client
from mock import patch
from moto import mock_aws

from prowler.providers.aws.services.appsync.appsync_service import AppSync
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_AppSync_Service:
    # Test AppSync Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider()
        appsync = AppSync(aws_provider)
        assert appsync.service == "appsync"

    # Test AppSync Client
    def test_client(self):
        aws_provider = set_mocked_aws_provider()
        appsync = AppSync(aws_provider)
        assert appsync.client.__class__.__name__ == "AppSync"

    # Test AppSync Session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider()
        appsync = AppSync(aws_provider)
        assert appsync.session.__class__.__name__ == "Session"

    # Test AppSync Session
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider()
        appsync = AppSync(aws_provider)
        assert appsync.audited_account == AWS_ACCOUNT_NUMBER

    # Test AppSync Describe File Systems
    @mock_aws
    def test_list_graphql_apis(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        appsync = client("appsync", region_name=AWS_REGION_US_EAST_1)
        api = appsync.create_graphql_api(
            name="test-api",
            authenticationType="API_KEY",
            logConfig={"fieldLogLevel": "ALL", "cloudWatchLogsRoleArn": "test"},
        )
        api_arn = api["graphqlApi"]["arn"]
        appsync_client = AppSync(aws_provider)

        assert appsync_client.graphql_apis[api_arn].name == "test-api"
        assert appsync_client.graphql_apis[api_arn].field_log_level == "ALL"
        assert appsync_client.graphql_apis[api_arn].authentication_type == "API_KEY"
        assert appsync_client.graphql_apis[api_arn].tags == [{}]
