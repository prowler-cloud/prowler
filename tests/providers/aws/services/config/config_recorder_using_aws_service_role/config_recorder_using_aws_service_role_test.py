from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_config_recorder_using_aws_service_role:
    @mock_aws
    def test_config_no_recorders(self):
        from prowler.providers.aws.services.config.config_service import Config

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.config.config_recorder_using_aws_service_role.config_recorder_using_aws_service_role.config_client",
            new=Config(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.config.config_recorder_using_aws_service_role.config_recorder_using_aws_service_role import (
                config_recorder_using_aws_service_role,
            )

            check = config_recorder_using_aws_service_role()
            results = check.execute()

            assert len(results) == 0

    @mock_aws
    def test_config_one_recoder_disabled(self):
        # Create Config Mocked Resources
        config_client = client("config", region_name=AWS_REGION_US_EAST_1)
        # Create Config Recorder
        config_client.put_configuration_recorder(
            ConfigurationRecorder={"name": "default", "roleARN": "somearn"}
        )
        from prowler.providers.aws.services.config.config_service import Config

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.config.config_recorder_using_aws_service_role.config_recorder_using_aws_service_role.config_client",
            new=Config(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.config.config_recorder_using_aws_service_role.config_recorder_using_aws_service_role import (
                config_recorder_using_aws_service_role,
            )

            check = config_recorder_using_aws_service_role()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_config_recorder_using_aws_service_role(self):
        # Create Config Mocked Resources
        config_client = client("config", region_name=AWS_REGION_US_EAST_1)
        # Create Config Recorder
        config_client.put_configuration_recorder(
            ConfigurationRecorder={
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
            }
        )
        # Make the delivery channel
        config_client.put_delivery_channel(
            DeliveryChannel={"name": "testchannel", "s3BucketName": "somebucket"}
        )
        config_client.start_configuration_recorder(ConfigurationRecorderName="default")
        from prowler.providers.aws.services.config.config_service import Config

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.config.config_recorder_using_aws_service_role.config_recorder_using_aws_service_role.config_client",
            new=Config(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.config.config_recorder_using_aws_service_role.config_recorder_using_aws_service_role import (
                config_recorder_using_aws_service_role,
            )

            check = config_recorder_using_aws_service_role()
            result = check.execute()
            assert len(result) == 1
            # Search for the recorder just created
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "AWS Config recorder default is using AWSServiceRoleForConfig."
            )
            assert result[0].resource_id == "default"
            assert (
                result[0].resource_arn
                == f"arn:aws:config:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:recorder"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_config_recorder_not_using_aws_service_role(self):
        # Create Config Mocked Resources
        config_client = client("config", region_name=AWS_REGION_US_EAST_1)
        # Create Config Recorder
        config_client.put_configuration_recorder(
            ConfigurationRecorder={
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/MyCustomRole",
            }
        )
        # Make the delivery channel
        config_client.put_delivery_channel(
            DeliveryChannel={"name": "testchannel", "s3BucketName": "somebucket"}
        )
        config_client.start_configuration_recorder(ConfigurationRecorderName="default")
        from prowler.providers.aws.services.config.config_service import Config

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.config.config_recorder_using_aws_service_role.config_recorder_using_aws_service_role.config_client",
            new=Config(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.config.config_recorder_using_aws_service_role.config_recorder_using_aws_service_role import (
                config_recorder_using_aws_service_role,
            )

            check = config_recorder_using_aws_service_role()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "AWS Config recorder default is not using AWSServiceRoleForConfig."
            )
            assert result[0].resource_id == "default"
            assert (
                result[0].resource_arn
                == f"arn:aws:config:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:recorder"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
