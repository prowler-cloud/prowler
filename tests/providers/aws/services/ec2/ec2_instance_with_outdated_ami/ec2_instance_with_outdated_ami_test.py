from unittest import mock

import botocore
import pytest

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call
describe_images_calls = []


@pytest.fixture(autouse=True)
def clear_describe_images_calls():
    describe_images_calls.clear()


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
                            "LaunchTime": "2026-11-12T11:34:56.000Z",
                            "PrivateDnsName": "ip-172-31-32-101.ec2.internal",
                        }
                    ]
                }
            ]
        }
    elif operation_name == "DescribeImages":
        describe_images_calls.append(kwarg)
        if kwarg.get("Owners") == ["self"]:
            return {"Images": []}
        if kwarg.get("Owners") == ["amazon"]:
            raise AssertionError(
                "Amazon AMIs must not be fetched with a broad owner lookup"
            )
        if kwarg.get("ImageIds") == ["ami-12345678"]:
            return {
                "Images": [
                    {
                        "ImageId": "ami-12345678",
                        "DeprecationTime": "2050-01-01T00:00:00.000Z",
                        "Public": True,
                        "ImageOwnerAlias": "amazon",
                    }
                ]
            }
        return {"Images": []}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_private(self, operation_name, kwarg):
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
                            "LaunchTime": "2026-11-12T11:34:56.000Z",
                            "PrivateDnsName": "ip-172-31-32-101.ec2.internal",
                        }
                    ]
                }
            ]
        }
    elif operation_name == "DescribeImages":
        describe_images_calls.append(kwarg)
        if kwarg.get("Owners") == ["amazon"]:
            raise AssertionError(
                "Amazon AMIs must not be fetched with a broad owner lookup"
            )
        if kwarg.get("Owners") == ["self"]:
            return {"Images": []}
        return {
            "Images": [
                {
                    "ImageId": "ami-12345678",
                    "DeprecationTime": "2050-01-01T00:00:00.000Z",
                    "Public": False,
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
                            "LaunchTime": "2026-11-12T11:34:56.000Z",
                            "PrivateDnsName": "ip-172-31-32-101.ec2.internal",
                        }
                    ]
                }
            ]
        }
    elif operation_name == "DescribeImages":
        describe_images_calls.append(kwarg)
        if kwarg.get("Owners") == ["self"]:
            return {"Images": []}
        if kwarg.get("Owners") == ["amazon"]:
            raise AssertionError(
                "Amazon AMIs must not be fetched with a broad owner lookup"
            )
        if kwarg.get("ImageIds") == ["ami-87654321"]:
            return {
                "Images": [
                    {
                        "ImageId": "ami-87654321",
                        "DeprecationTime": "2022-01-01T00:00:00.000Z",
                        "Public": True,
                        "ImageOwnerAlias": "amazon",
                    }
                ]
            }
        return {"Images": []}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_missing_ami(self, operation_name, kwarg):
    if operation_name == "DescribeInstances":
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-0123456789abcdef0",
                            "State": {"Name": "running"},
                            "InstanceType": "t2.micro",
                            "ImageId": "ami-missing",
                            "LaunchTime": "2026-11-12T11:34:56.000Z",
                            "PrivateDnsName": "ip-172-31-32-101.ec2.internal",
                        }
                    ]
                }
            ]
        }
    elif operation_name == "DescribeImages":
        describe_images_calls.append(kwarg)
        if kwarg.get("Owners") == ["amazon"]:
            raise AssertionError(
                "Amazon AMIs must not be fetched with a broad owner lookup"
            )
        return {"Images": []}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_no_instances(self, operation_name, kwarg):
    if operation_name == "DescribeInstances":
        return {"Reservations": []}
    elif operation_name == "DescribeImages":
        describe_images_calls.append(kwarg)
        if kwarg.get("Owners") == ["amazon"]:
            raise AssertionError(
                "Amazon AMIs must not be fetched with a broad owner lookup"
            )
        return {"Images": []}
    return make_api_call(self, operation_name, kwarg)


class Test_ec2_instance_with_outdated_ami:
    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_no_instances
    )
    def test_ec2_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami import (
                ec2_instance_with_outdated_ami,
            )

            check = ec2_instance_with_outdated_ami()
            result = check.execute()

            assert len(result) == 0
            assert not any("ImageIds" in call for call in describe_images_calls)

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_private
    )
    def test_ec2_no_public_images(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami import (
                ec2_instance_with_outdated_ami,
            )

            check = ec2_instance_with_outdated_ami()
            result = check.execute()

            assert len(result) == 0
            assert not any(
                call.get("Owners") == ["amazon"] for call in describe_images_calls
            )
            assert any(
                call.get("ImageIds") == ["ami-12345678"]
                for call in describe_images_calls
            )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_instance_ami_not_outdated(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami.ec2_client",
                new=EC2(aws_provider),
            ),
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
                == "EC2 Instance i-0123456789abcdef0 is not using an outdated AMI."
            )
            assert not any(
                call.get("Owners") == ["amazon"] for call in describe_images_calls
            )
            assert any(
                call.get("ImageIds") == ["ami-12345678"]
                for call in describe_images_calls
            )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_outdated_ami
    )
    def test_instance_ami_outdated(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami.ec2_client",
                new=EC2(aws_provider),
            ),
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
            assert not any(
                call.get("Owners") == ["amazon"] for call in describe_images_calls
            )
            assert any(
                call.get("ImageIds") == ["ami-87654321"]
                for call in describe_images_calls
            )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_missing_ami
    )
    def test_instance_missing_ami_details(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_with_outdated_ami.ec2_instance_with_outdated_ami import (
                ec2_instance_with_outdated_ami,
            )

            check = ec2_instance_with_outdated_ami()
            result = check.execute()

            assert result == []
            assert not any(
                call.get("Owners") == ["amazon"] for call in describe_images_calls
            )
            assert any(
                call.get("ImageIds") == ["ami-missing"]
                for call in describe_images_calls
            )
