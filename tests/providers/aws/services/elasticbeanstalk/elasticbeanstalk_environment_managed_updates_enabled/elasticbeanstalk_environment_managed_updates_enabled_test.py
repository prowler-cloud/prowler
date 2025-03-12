from unittest import mock

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
                            "Namespace": "aws:elasticbeanstalk:managedactions",
                            "OptionName": "ManagedActionsEnabled",
                            "Value": "true",
                        },
                    ],
                }
            ]
        }

    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "DescribeConfigurationSettings":
        return {
            "ConfigurationSettings": [
                {
                    "OptionSettings": [
                        {
                            "Namespace": "aws:elasticbeanstalk:managedactions",
                            "OptionName": "ManagedActionsEnabled",
                            "Value": "false",
                        },
                    ],
                }
            ]
        }

    return make_api_call(self, operation_name, kwarg)


class Test_elasticbeanstalk_environment_managed_updates_enabled:
    @mock_aws
    def test_elasticbeanstalk_no_environments(self):
        elasticbeanstalk_client = client(
            "elasticbeanstalk", region_name=AWS_REGION_EU_WEST_1
        )
        elasticbeanstalk_client.create_application(ApplicationName="test-app")

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_managed_updates_enabled.elasticbeanstalk_environment_managed_updates_enabled.elasticbeanstalk_client",
            new=ElasticBeanstalk(aws_provider),
        ):
            from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_managed_updates_enabled.elasticbeanstalk_environment_managed_updates_enabled import (
                elasticbeanstalk_environment_managed_updates_enabled,
            )

            check = elasticbeanstalk_environment_managed_updates_enabled()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_elasticbeanstalk_environments_enabled_autoupdate(self):
        elasticbeanstalk_client = client(
            "elasticbeanstalk", region_name=AWS_REGION_EU_WEST_1
        )
        elasticbeanstalk_client.create_application(ApplicationName="test-app")
        environment = elasticbeanstalk_client.create_environment(
            ApplicationName="test-app",
            EnvironmentName="test-env",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_managed_updates_enabled.elasticbeanstalk_environment_managed_updates_enabled.elasticbeanstalk_client",
            new=ElasticBeanstalk(aws_provider),
        ):
            from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_managed_updates_enabled.elasticbeanstalk_environment_managed_updates_enabled import (
                elasticbeanstalk_environment_managed_updates_enabled,
            )

            check = elasticbeanstalk_environment_managed_updates_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Elastic Beanstalk environment test-env has managed platform updates enabled."
            )
            assert result[0].resource_id == environment["EnvironmentName"]
            assert result[0].resource_arn == environment["EnvironmentArn"]
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_elasticbeanstalk_environments_not_enabled_autoupdate(self):
        elasticbeanstalk_client = client(
            "elasticbeanstalk", region_name=AWS_REGION_EU_WEST_1
        )
        elasticbeanstalk_client.create_application(ApplicationName="test-app")
        environment = elasticbeanstalk_client.create_environment(
            ApplicationName="test-app",
            EnvironmentName="test-env",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_managed_updates_enabled.elasticbeanstalk_environment_managed_updates_enabled.elasticbeanstalk_client",
            new=ElasticBeanstalk(aws_provider),
        ):
            from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_managed_updates_enabled.elasticbeanstalk_environment_managed_updates_enabled import (
                elasticbeanstalk_environment_managed_updates_enabled,
            )

            check = elasticbeanstalk_environment_managed_updates_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Elastic Beanstalk environment test-env does not have managed platform updates enabled."
            )
            assert result[0].resource_id == environment["EnvironmentName"]
            assert result[0].resource_arn == environment["EnvironmentArn"]
            assert result[0].region == AWS_REGION_EU_WEST_1
