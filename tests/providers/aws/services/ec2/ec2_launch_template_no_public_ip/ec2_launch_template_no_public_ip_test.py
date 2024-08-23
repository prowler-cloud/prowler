from os import path
from pathlib import Path
from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

ACTUAL_DIRECTORY = Path(path.dirname(path.realpath(__file__)))
FIXTURES_DIR_NAME = "fixtures"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeLaunchTemplateVersions":
        return {
            "LaunchTemplateVersions": [
                {
                    "VersionNumber": 1,
                    "LaunchTemplateData": {
                        "NetworkInterfaces": [{"AssociatePublicIpAddress": False}],
                    },
                }
            ]
        }
    elif operation_name == "DescribeLaunchTemplates":
        return {
            "LaunchTemplates": [
                {
                    "LaunchTemplateName": "tester-nopublicip",
                    "LaunchTemplateId": "lt-1234567890",
                }
            ]
        }
    # Si no es la operación que queremos interceptar, llamamos al método original
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "DescribeLaunchTemplateVersions":
        return {
            "LaunchTemplateVersions": [
                {
                    "VersionNumber": 2,
                    "LaunchTemplateData": {
                        "NetworkInterfaces": [{"AssociatePublicIpAddress": True}],
                    },
                }
            ]
        }
    elif operation_name == "DescribeLaunchTemplates":
        return {
            "LaunchTemplates": [
                {
                    "LaunchTemplateName": "tester-publicip",
                    "LaunchTemplateId": "lt-2224567890",
                }
            ]
        }
    # Si no es la operación que queremos interceptar, llamamos al método original
    return make_api_call(self, operation_name, kwarg)


class Test_ec2_launch_template_no_secrets:
    @mock_aws
    def test_no_launch_templates(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.launch_templates = []

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip import (
                ec2_launch_template_no_public_ip,
            )

            check = ec2_launch_template_no_public_ip()
            result = check.execute()

            assert len(result) == 0

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_launch_template_no_public_ip(self):

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip import (
                ec2_launch_template_no_public_ip,
            )

            check = ec2_launch_template_no_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No versions of EC2 Launch Template tester-nopublicip are configured to assign a public IP address."
            )
            assert result[0].resource_id == "lt-1234567890"
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_launch_template_public_ip(self):

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_public_ip.ec2_launch_template_no_public_ip import (
                ec2_launch_template_no_public_ip,
            )

            check = ec2_launch_template_no_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "EC2 Launch Template tester-publicip in template versions: 2 is configured to assign a public IP address."
            )
            assert result[0].resource_id == "lt-2224567890"
            assert result[0].region == AWS_REGION_US_EAST_1
