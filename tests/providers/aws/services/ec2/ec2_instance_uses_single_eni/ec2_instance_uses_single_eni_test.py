from unittest import mock

import botocore
from boto3 import resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

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
                            "Monitoring": {"State": "disabled"},
                            "SecurityGroups": [
                                {"GroupId": "sg-12345678", "GroupName": "default"}
                            ],
                            "SubnetId": "subnet-12345678",
                            "Tags": [{"Key": "Name", "Value": "MyInstance"}],
                            "NetworkInterfaces": [
                                {"NetworkInterfaceId": "eni-1"},
                                {"NetworkInterfaceId": "eni-2"},
                            ],
                        }
                    ]
                }
            ]
        }
    elif operation_name == "DescribeNetworkInterfaces":
        return {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-1",
                    "SubnetId": "subnet-1234abcd",
                    "VpcId": "vpc-1234abcd",
                    "PrivateIpAddress": "192.168.1.1",
                    "InterfaceType": "interface",
                },
                {
                    "NetworkInterfaceId": "eni-2",
                    "SubnetId": "subnet-1234abcd",
                    "VpcId": "vpc-1234abcd",
                    "PrivateIpAddress": "192.168.1.2",
                    "InterfaceType": "efa",
                },
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
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
                            "Monitoring": {"State": "disabled"},
                            "SecurityGroups": [
                                {"GroupId": "sg-12345678", "GroupName": "default"}
                            ],
                            "SubnetId": "subnet-12345678",
                            "Tags": [{"Key": "Name", "Value": "MyInstance"}],
                            "NetworkInterfaces": [],
                        }
                    ]
                }
            ]
        }
    elif operation_name == "DescribeNetworkInterfaces":
        return {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-3",
                    "SubnetId": "subnet-5678abcd",
                    "VpcId": "vpc-5678abcd",
                    "PrivateIpAddress": "192.168.1.3",
                    "InterfaceType": "interface",
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v3(self, operation_name, kwarg):
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
                            "Monitoring": {"State": "disabled"},
                            "SecurityGroups": [
                                {"GroupId": "sg-12345678", "GroupName": "default"}
                            ],
                            "SubnetId": "subnet-12345678",
                            "Tags": [{"Key": "Name", "Value": "MyInstance"}],
                            "NetworkInterfaces": [
                                {"NetworkInterfaceId": "eni-1"},
                                {"NetworkInterfaceId": "eni-2"},
                                {"NetworkInterfaceId": "eni-3"},
                            ],
                        }
                    ]
                }
            ]
        }
    elif operation_name == "DescribeNetworkInterfaces":
        return {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-1",
                    "SubnetId": "subnet-1234abcd",
                    "VpcId": "vpc-1234abcd",
                    "PrivateIpAddress": "192.168.1.1",
                    "InterfaceType": "trunk",
                },
                {
                    "NetworkInterfaceId": "eni-2",
                    "SubnetId": "subnet-1234abcd",
                    "VpcId": "vpc-1234abcd",
                    "PrivateIpAddress": "192.168.1.2",
                    "InterfaceType": "efa",
                },
                {
                    "NetworkInterfaceId": "eni-3",
                    "SubnetId": "subnet-1234abcd",
                    "VpcId": "vpc-1234abcd",
                    "PrivateIpAddress": "192.168.1.3",
                    "InterfaceType": "trunk",
                },
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_ec2_instance_uses_single_eni:
    @mock_aws
    def test_ec2_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_uses_single_eni.ec2_instance_uses_single_eni.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_uses_single_eni.ec2_instance_uses_single_eni import (
                ec2_instance_uses_single_eni,
            )

            check = ec2_instance_uses_single_eni()
            result = check.execute()

            assert len(result) == 0

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_ec2_instance_no_eni(self):

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_uses_single_eni.ec2_instance_uses_single_eni.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_uses_single_eni.ec2_instance_uses_single_eni import (
                ec2_instance_uses_single_eni,
            )

            check = ec2_instance_uses_single_eni()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "i-0123456789abcdef0"
            assert (
                result[0].status_extended
                == "EC2 Instance i-0123456789abcdef0 has no network interfaces attached."
            )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_instance_multiple_enis(self):

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_uses_single_eni.ec2_instance_uses_single_eni.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_uses_single_eni.ec2_instance_uses_single_eni import (
                ec2_instance_uses_single_eni,
            )

            check = ec2_instance_uses_single_eni()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "i-0123456789abcdef0"
            assert (
                result[0].status_extended
                == "EC2 Instance i-0123456789abcdef0 uses multiple ENIs: ( EFAs: ['eni-2'] Interfaces: ['eni-1'] )."
            )

    @mock_aws
    def test_instance_with_single_eni(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId="ami-12c6146b",
            MinCount=1,
            MaxCount=1,
            UserData="This is some user_data",
        )[0]
        network_interface = instance.network_interfaces[0]
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_uses_single_eni.ec2_instance_uses_single_eni.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_uses_single_eni.ec2_instance_uses_single_eni import (
                ec2_instance_uses_single_eni,
            )

            check = ec2_instance_uses_single_eni()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == instance.id
            assert (
                result[0].status_extended
                == f"EC2 Instance {instance.id} uses only one ENI: ( Interfaces: ['{network_interface.id}'] )."
            )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v3)
    def test_instance_one_efa_multiple_trunks(self):

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_uses_single_eni.ec2_instance_uses_single_eni.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_uses_single_eni.ec2_instance_uses_single_eni import (
                ec2_instance_uses_single_eni,
            )

            check = ec2_instance_uses_single_eni()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "i-0123456789abcdef0"
            assert (
                result[0].status_extended
                == "EC2 Instance i-0123456789abcdef0 uses multiple ENIs: ( EFAs: ['eni-2'] Trunks: ['eni-1', 'eni-3'] )."
            )
