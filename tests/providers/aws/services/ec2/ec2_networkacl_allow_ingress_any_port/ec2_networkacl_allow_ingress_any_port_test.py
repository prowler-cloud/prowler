from unittest import mock

from boto3 import client
from moto import mock_ec2

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_ec2_networkacl_allow_ingress_any_port:
    @mock_ec2
    def test_ec2_default_nacls(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_networkacl_allow_ingress_any_port.ec2_networkacl_allow_ingress_any_port.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_networkacl_allow_ingress_any_port.ec2_networkacl_allow_ingress_any_port import (
                ec2_networkacl_allow_ingress_any_port,
            )

            check = ec2_networkacl_allow_ingress_any_port()
            result = check.execute()

            # One default nacl per region
            assert len(result) == 2

    @mock_ec2
    def test_ec2_non_default_compliant_nacl(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_networkacl_allow_ingress_any_port.ec2_networkacl_allow_ingress_any_port.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_networkacl_allow_ingress_any_port.ec2_networkacl_allow_ingress_any_port import (
                ec2_networkacl_allow_ingress_any_port,
            )

            check = ec2_networkacl_allow_ingress_any_port()
            result = check.execute()

            # One default sg per region
            assert len(result) == 2

            # by default nacls are public
            assert result[0].status == "FAIL"
            assert result[0].region in (AWS_REGION, "eu-west-1")
            assert result[0].resource_tags == []
            assert (
                result[0].status_extended
                == f"Network ACL {result[0].resource_id} has every port open to the Internet."
            )

    @mock_ec2
    def test_ec2_non_compliant_nacl(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        nacl_id = ec2_client.create_network_acl(VpcId=vpc_id)["NetworkAcl"][
            "NetworkAclId"
        ]
        ec2_client.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=100,
            Protocol="-1",
            RuleAction="allow",
            Egress=False,
            CidrBlock="0.0.0.0/0",
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_networkacl_allow_ingress_any_port.ec2_networkacl_allow_ingress_any_port.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_networkacl_allow_ingress_any_port.ec2_networkacl_allow_ingress_any_port import (
                ec2_networkacl_allow_ingress_any_port,
            )

            check = ec2_networkacl_allow_ingress_any_port()
            result = check.execute()

            # One default sg per region + default of new VPC + new NACL
            assert len(result) == 4
            # Search changed sg
            for nacl in result:
                if nacl.resource_id == nacl_id:
                    assert nacl.status == "FAIL"
                    assert result[0].region in (AWS_REGION, "eu-west-1")
                    assert result[0].resource_tags == []
                    assert (
                        nacl.status_extended
                        == f"Network ACL {nacl_id} has every port open to the Internet."
                    )
                    assert (
                        nacl.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:network-acl/{nacl_id}"
                    )

    @mock_ec2
    def test_ec2_compliant_nacl(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        nacl_id = ec2_client.create_network_acl(VpcId=vpc_id)["NetworkAcl"][
            "NetworkAclId"
        ]
        ec2_client.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=100,
            Protocol="-1",
            RuleAction="allow",
            Egress=False,
            CidrBlock="10.0.0.2/32",
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_networkacl_allow_ingress_any_port.ec2_networkacl_allow_ingress_any_port.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_networkacl_allow_ingress_any_port.ec2_networkacl_allow_ingress_any_port import (
                ec2_networkacl_allow_ingress_any_port,
            )

            check = ec2_networkacl_allow_ingress_any_port()
            result = check.execute()

            # One default sg per region + default of new VPC + new NACL
            assert len(result) == 4
            # Search changed sg
            for nacl in result:
                if nacl.resource_id == nacl_id:
                    assert nacl.status == "PASS"
                    assert result[0].region in (AWS_REGION, "eu-west-1")
                    assert result[0].resource_tags == []
                    assert (
                        nacl.status_extended
                        == f"Network ACL {nacl_id} does not have every port open to the Internet."
                    )
                    assert (
                        nacl.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:network-acl/{nacl_id}"
                    )

    @mock_ec2
    def test_ec2_non_compliant_nacl_ignoring(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        nacl_id = ec2_client.create_network_acl(VpcId=vpc_id)["NetworkAcl"][
            "NetworkAclId"
        ]
        ec2_client.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=100,
            Protocol="-1",
            RuleAction="allow",
            Egress=False,
            CidrBlock="0.0.0.0/0",
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        current_audit_info.ignore_unused_services = True

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_networkacl_allow_ingress_any_port.ec2_networkacl_allow_ingress_any_port.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_networkacl_allow_ingress_any_port.ec2_networkacl_allow_ingress_any_port import (
                ec2_networkacl_allow_ingress_any_port,
            )

            check = ec2_networkacl_allow_ingress_any_port()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    def test_ec2_non_compliant_nacl_ignoring_with_sgs(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        nacl_id = ec2_client.create_network_acl(VpcId=vpc_id)["NetworkAcl"][
            "NetworkAclId"
        ]
        ec2_client.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=100,
            Protocol="-1",
            RuleAction="allow",
            Egress=False,
            CidrBlock="0.0.0.0/0",
        )
        ec2_client.create_security_group(GroupName="sg", Description="test")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        current_audit_info.ignore_unused_services = True

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_networkacl_allow_ingress_any_port.ec2_networkacl_allow_ingress_any_port.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_networkacl_allow_ingress_any_port.ec2_networkacl_allow_ingress_any_port import (
                ec2_networkacl_allow_ingress_any_port,
            )

            check = ec2_networkacl_allow_ingress_any_port()
            result = check.execute()

            # One default sg per region + default of new VPC + new NACL
            assert len(result) == 3
            # Search changed sg
            for nacl in result:
                if nacl.resource_id == nacl_id:
                    assert nacl.status == "FAIL"
                    assert result[0].region in (AWS_REGION, "eu-west-1")
                    assert result[0].resource_tags == []
                    assert (
                        nacl.status_extended
                        == f"Network ACL {nacl_id} has every port open to the Internet."
                    )
                    assert (
                        nacl.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:network-acl/{nacl_id}"
                    )
