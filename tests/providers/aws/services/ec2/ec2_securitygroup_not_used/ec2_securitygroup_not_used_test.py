from re import search
from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_securitygroup_not_used:
    @mock_aws
    def test_ec2_default_sgs(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            audited_regions=["us-east-1", "eu-west-1"]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.awslambda_client",
            new=Lambda(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used import (
                ec2_securitygroup_not_used,
            )

            check = ec2_securitygroup_not_used()
            result = check.execute()

            # Default sg per region are excluded
            assert len(result) == 0

    @mock_aws
    def test_ec2_unused_sg(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg_name = "test-sg"
        sg = ec2.create_security_group(
            GroupName=sg_name, Description="test", VpcId=vpc_id
        )

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            audited_regions=["us-east-1", "eu-west-1"]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.awslambda_client",
            new=Lambda(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used import (
                ec2_securitygroup_not_used,
            )

            check = ec2_securitygroup_not_used()
            result = check.execute()

            # One custom sg
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == f"Security group {sg_name} ({sg.id}) it is not being used."
            )
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:security-group/{sg.id}"
            )
            assert result[0].resource_id == sg.id
            assert result[0].resource_details == sg_name
            assert result[0].resource_tags == []

    @mock_aws
    def test_ec2_used_default_sg(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg_name = "test-sg"
        sg = ec2.create_security_group(
            GroupName=sg_name, Description="test", VpcId=vpc_id
        )
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/18")
        subnet.create_network_interface(Groups=[sg.id])

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            audited_regions=["us-east-1", "eu-west-1"]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.awslambda_client",
            new=Lambda(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used import (
                ec2_securitygroup_not_used,
            )

            check = ec2_securitygroup_not_used()
            result = check.execute()

            # One custom sg
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == f"Security group {sg_name} ({sg.id}) it is being used."
            )
            assert search(
                "it is being used",
                result[0].status_extended,
            )
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:security-group/{sg.id}"
            )
            assert result[0].resource_id == sg.id
            assert result[0].resource_details == sg_name
            assert result[0].resource_tags == []

    @mock_aws
    def test_ec2_used_default_sg_by_lambda(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg_name = "test-sg"
        sg = ec2.create_security_group(
            GroupName=sg_name, Description="test", VpcId=vpc_id
        )
        subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/18")
        subnet.create_network_interface(Groups=[sg.id])
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        iam_role = iam_client.create_role(
            RoleName="my-role",
            AssumeRolePolicyDocument="some policy",
            Path="/my-path/",
        )["Role"]["Arn"]
        lambda_client = client("lambda", AWS_REGION_US_EAST_1)
        lambda_client.create_function(
            FunctionName="test-function",
            Runtime="python3.11",
            Role=iam_role,
            Handler="lambda_function.lambda_handler",
            Code={
                "ImageUri": f"{AWS_ACCOUNT_NUMBER}.dkr.ecr.us-east-1.amazonaws.com/testlambdaecr:prod"
            },
            Description="test lambda function",
            Timeout=3,
            MemorySize=128,
            Publish=True,
            VpcConfig={
                "SecurityGroupIds": [sg.id],
                "SubnetIds": [subnet.id],
            },
        )

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            audited_regions=["us-east-1", "eu-west-1"]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.awslambda_client",
            new=Lambda(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used import (
                ec2_securitygroup_not_used,
            )

            check = ec2_securitygroup_not_used()
            result = check.execute()

            # One custom sg
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == f"Security group {sg_name} ({sg.id}) it is being used."
            )
            assert search(
                "it is being used",
                result[0].status_extended,
            )
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:security-group/{sg.id}"
            )
            assert result[0].resource_id == sg.id
            assert result[0].resource_details == sg_name
            assert result[0].resource_tags == []

    @mock_aws
    def test_ec2_associated_sg(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        sg_name = "test-sg"
        sg_name1 = "test-sg1"
        sg = ec2.create_security_group(
            GroupName=sg_name, Description="test", VpcId=vpc_id
        )
        sg1 = ec2.create_security_group(
            GroupName=sg_name1, Description="test1", VpcId=vpc_id
        )

        ec2_client.authorize_security_group_ingress(
            GroupId=sg.id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "UserIdGroupPairs": [
                        {
                            "GroupId": sg1.id,
                            "Description": "Allow traffic from source SG",
                        }
                    ],
                }
            ],
        )

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            audited_regions=["us-east-1", "eu-west-1"]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used.awslambda_client",
            new=Lambda(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_securitygroup_not_used.ec2_securitygroup_not_used import (
                ec2_securitygroup_not_used,
            )

            check = ec2_securitygroup_not_used()
            result = check.execute()

            # One custom sg
            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].status_extended
                == f"Security group {sg_name} ({sg.id}) it is not being used."
            )
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:security-group/{sg.id}"
            )
            assert result[0].resource_id == sg.id
            assert result[0].resource_details == sg_name
            assert result[0].resource_tags == []
            assert result[1].status == "PASS"
            assert result[1].region == AWS_REGION_US_EAST_1
            assert (
                result[1].status_extended
                == f"Security group {sg_name1} ({sg1.id}) it is being used."
            )
            assert (
                result[1].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.audited_account}:security-group/{sg1.id}"
            )
            assert result[1].resource_id == sg1.id
            assert result[1].resource_details == sg_name1
            assert result[1].resource_tags == []
