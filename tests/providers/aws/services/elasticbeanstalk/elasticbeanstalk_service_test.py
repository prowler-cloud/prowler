from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_service import (
    ElasticBeanstalk,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeConfigurationSettings":
        return {
            "ConfigurationSettings": [
                {
                    "OptionSettings": [
                        {
                            "Namespace": "aws:elasticbeanstalk:healthreporting:system",
                            "OptionName": "SystemType",
                            "Value": "enhanced",
                        },
                        {
                            "Namespace": "aws:elasticbeanstalk:managedactions",
                            "OptionName": "ManagedActionsEnabled",
                            "Value": "true",
                        },
                        {
                            "Namespace": "aws:elasticbeanstalk:cloudwatch:logs",
                            "OptionName": "StreamLogs",
                            "Value": "true",
                        },
                    ],
                }
            ]
        }

    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_ElasticBeanstalk_Service:
    # Test ElasticBeanstalk Client
    @mock_aws
    def test_get_client(self):
        elasticbeanstalk = ElasticBeanstalk(set_mocked_aws_provider())
        assert (
            elasticbeanstalk.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__
            == "ElasticBeanstalk"
        )

    # Test ElasticBeanstalk Session
    @mock_aws
    def test__get_session__(self):
        elasticbeanstalk = ElasticBeanstalk(set_mocked_aws_provider())
        assert elasticbeanstalk.session.__class__.__name__ == "Session"

    # Test ElasticBeanstalk Service
    @mock_aws
    def test__get_service__(self):
        elasticbeanstalk = ElasticBeanstalk(set_mocked_aws_provider())
        assert elasticbeanstalk.service == "elasticbeanstalk"

    # Test _describe_environments
    @mock_aws
    def test_describe_environments(self):
        # Create ElasticBeanstalk app and env
        elasticbeanstalk_client = client(
            "elasticbeanstalk", region_name=AWS_REGION_EU_WEST_1
        )
        elasticbeanstalk_client.create_application(ApplicationName="test-app")
        environment = elasticbeanstalk_client.create_environment(
            ApplicationName="test-app",
            EnvironmentName="test-env",
        )
        # ElasticBeanstalk Class
        elasticbeanstalk = ElasticBeanstalk(set_mocked_aws_provider())

        assert len(elasticbeanstalk.environments) == 1
        assert (
            elasticbeanstalk.environments[environment["EnvironmentArn"]].id
            == environment["EnvironmentId"]
        )
        assert (
            elasticbeanstalk.environments[environment["EnvironmentArn"]].name
            == "test-env"
        )
        assert (
            elasticbeanstalk.environments[environment["EnvironmentArn"]].region
            == AWS_REGION_EU_WEST_1
        )
        assert (
            elasticbeanstalk.environments[
                environment["EnvironmentArn"]
            ].application_name
            == "test-app"
        )

    # Test _describe_configuration_settings
    @mock_aws
    def test_describe_configuration_settings(self):
        # Create ElasticBeanstalk app and env
        elasticbeanstalk_client = client(
            "elasticbeanstalk", region_name=AWS_REGION_EU_WEST_1
        )
        elasticbeanstalk_client.create_application(ApplicationName="test-app")
        environment = elasticbeanstalk_client.create_environment(
            ApplicationName="test-app",
            EnvironmentName="test-env",
        )
        # ElasticBeanstalk Class
        elasticbeanstalk = ElasticBeanstalk(set_mocked_aws_provider())
        assert (
            elasticbeanstalk.environments[
                environment["EnvironmentArn"]
            ].health_reporting
            == "enhanced"
        )
        assert (
            elasticbeanstalk.environments[
                environment["EnvironmentArn"]
            ].managed_platform_updates
            == "true"
        )
        assert (
            elasticbeanstalk.environments[
                environment["EnvironmentArn"]
            ].cloudwatch_stream_logs
            == "true"
        )

    @mock_aws
    def test_list_tags_for_resource(self):
        # Create ElasticBeanstalk app and env
        elasticbeanstalk_client = client(
            "elasticbeanstalk", region_name=AWS_REGION_EU_WEST_1
        )
        elasticbeanstalk_client.create_application(ApplicationName="test-app")
        environment = elasticbeanstalk_client.create_environment(
            ApplicationName="test-app",
            EnvironmentName="test-env",
            Tags=[{"Key": "test-key", "Value": "test-value"}],
        )
        # ElasticBeanstalk Class
        elasticbeanstalk = ElasticBeanstalk(set_mocked_aws_provider())
        assert elasticbeanstalk.environments[environment["EnvironmentArn"]].tags == [
            {"Key": "test-key", "Value": "test-value"}
        ]
