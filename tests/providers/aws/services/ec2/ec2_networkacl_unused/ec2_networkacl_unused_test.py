from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_ec2_networkacl_unused:
    @mock_aws
    def test_ec2_default_nacls(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_networkacl_unused.ec2_networkacl_unused.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_networkacl_unused.ec2_networkacl_unused import (
                ec2_networkacl_unused,
            )

            check = ec2_networkacl_unused()
            result = check.execute()

            # One default nacl per region
            assert len(result) == 0

    @mock_aws
    def test_ec2_unused_non_default_nacl(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        nacl_id = ec2_client.create_network_acl(VpcId=vpc_id)["NetworkAcl"][
            "NetworkAclId"
        ]
        arn = f"arn:aws:ec2:eu-west-1:123456789012:network-acl/{nacl_id}"

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_networkacl_unused.ec2_networkacl_unused.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_networkacl_unused.ec2_networkacl_unused import (
                ec2_networkacl_unused,
            )

            check = ec2_networkacl_unused()
            result = check.execute()

            assert len(result) == 1

            assert result[0].status == "FAIL"
            assert result[0].region == "eu-west-1"
            assert result[0].resource_id == nacl_id
            assert result[0].resource_arn == arn
            assert (
                result[0].status_extended
                == f"Network ACL {nacl_id} is not associated with any subnet and is not the default network ACL."
            )

    @mock_aws
    def test_ec2_used_non_default_nacl(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        nacl_id = ec2_client.create_network_acl(VpcId=vpc_id)["NetworkAcl"][
            "NetworkAclId"
        ]
        arn = f"arn:aws:ec2:eu-west-1:123456789012:network-acl/{nacl_id}"

        default_nacl_association_id = ec2_client.describe_network_acls()["NetworkAcls"][
            0
        ]["Associations"][0]["NetworkAclAssociationId"]
        # Replace the default association with the new Network ACL
        ec2_client.replace_network_acl_association(
            AssociationId=default_nacl_association_id, NetworkAclId=nacl_id
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_networkacl_unused.ec2_networkacl_unused.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_networkacl_unused.ec2_networkacl_unused import (
                ec2_networkacl_unused,
            )

            check = ec2_networkacl_unused()
            result = check.execute()

            assert len(result) == 1
            # Search changed sg
            assert result[0].status == "PASS"
            assert result[0].region == "eu-west-1"
            assert result[0].resource_id == nacl_id
            assert result[0].resource_arn == arn
            assert (
                result[0].status_extended
                == f"Network ACL {nacl_id} is associated with a subnet."
            )
