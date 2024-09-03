from datetime import datetime
from unittest import mock

import botocore
from boto3 import resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

EXAMPLE_AMI_ID = "ami-12c6146b"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeInstances":
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-1234567890abcdef0",
                            "VirtualizationType": "paravirtual",
                            "State": {"Name": "running"},
                            "InstanceType": "t2.micro",
                            "ImageId": "ami-12345678",
                            "LaunchTime": datetime(2024, 9, 1).isoformat(),
                            "PrivateDnsName": "ip-10-0-0-1.ec2.internal",
                            "PrivateIpAddress": "10.0.0.1",
                            "PublicDnsName": "ec2-54-123-45-67.compute-1.amazonaws.com",
                            "PublicIpAddress": "54.123.45.67",
                            "MetadataOptions": {
                                "HttpTokens": "required",
                                "HttpEndpoint": "enabled",
                            },
                            "IamInstanceProfile": {
                                "Arn": "arn:aws:iam::123456789012:instance-profile/MyInstanceProfile"
                            },
                            "Monitoring": {"State": "enabled"},
                            "SecurityGroups": [{"GroupId": "sg-12345678"}],
                            "SubnetId": "subnet-abc12345",
                            "Tags": [{"Key": "Name", "Value": "test-instance"}],
                        }
                    ]
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_ec2_instance_paravirtual_type:
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
            "prowler.providers.aws.services.ec2.ec2_instance_paravirtual_type.ec2_instance_paravirtual_type.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_paravirtual_type.ec2_instance_paravirtual_type import (
                ec2_instance_paravirtual_type,
            )

            check = ec2_instance_paravirtual_type()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_one_compliant_ec2(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "SubnetId": subnet.id,
                    "AssociatePublicIpAddress": False,
                }
            ],
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_paravirtual_type.ec2_instance_paravirtual_type.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_paravirtual_type.ec2_instance_paravirtual_type import (
                ec2_instance_paravirtual_type,
            )

            check = ec2_instance_paravirtual_type()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended
                == f"EC2 Instance {instance.id} virtualization type is set to HVM."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_one_ec2_with_paravirtual_type(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_paravirtual_type.ec2_instance_paravirtual_type.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_paravirtual_type.ec2_instance_paravirtual_type import (
                ec2_instance_paravirtual_type,
            )

            check = ec2_instance_paravirtual_type()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == "EC2 Instance i-1234567890abcdef0 virtualization type is set to paravirtual."
            )
            assert result[0].resource_id == "i-1234567890abcdef0"
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/i-1234567890abcdef0"
            )
