from unittest import mock

import botocore
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeInstances":
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-0123456789abcdef0",
                            "State": {"Name": "running"},
                            "InstanceType": "t2.micro",
                            "ImageId": "ami-12345678",
                            "LaunchTime": "2023-09-01T12:34:56Z",
                            "PrivateDnsName": "ip-172-31-32-101.ec2.internal",
                        }
                    ]
                }
            ]
        }
    elif operation_name == "DescribeImages":
        return {
            "Images": [
                {
                    "ImageId": "ami-12345678",
                    "DeprecationTime": "2050-01-01T00:00:00Z",
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_outdated_ami(self, operation_name, kwarg):
    if operation_name == "DescribeInstances":
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-0123456789abcdef0",
                            "State": {"Name": "running"},
                            "InstanceType": "t2.micro",
                            "ImageId": "ami-87654321",
                            "LaunchTime": "2023-09-01T12:34:56Z",
                            "PrivateDnsName": "ip-172-31-32-101.ec2.internal",
                        }
                    ]
                }
            ]
        }
    elif operation_name == "DescribeImages":
        return {
            "Images": [
                {
                    "ImageId": "ami-87654321",
                    "DeprecationTime": "2022-01-01T00:00:00Z",
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_ec2_instance_with_outdated_ami:
    @mock_aws
    def test_ec2_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami import (
                ec2_instance_with_outdated_ami,
            )

            check = ec2_instance_with_outdated_ami()
            result = check.execute()

            assert len(result) == 0

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_instance_ami_not_outdated(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami import (
                ec2_instance_with_outdated_ami,
            )

            check = ec2_instance_with_outdated_ami()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "i-0123456789abcdef0"
            assert (
                result[0].status_extended
                == "EC2 Instance i-0123456789abcdef0 is not using outdated AMIs."
            )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_outdated_ami
    )
    def test_instance_ami_outdated(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami import (
                ec2_instance_with_outdated_ami,
            )

            check = ec2_instance_with_outdated_ami()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "i-0123456789abcdef0"
            assert (
                result[0].status_extended
                == "EC2 Instance i-0123456789abcdef0 is using outdated AMI ami-87654321."
            )
