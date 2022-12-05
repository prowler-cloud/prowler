from unittest import mock

from boto3 import client
from moto import mock_ec2

AWS_REGION = "us-east-1"


class Test_ec2_networkacl_allow_ingress_tcp_port_3389:
    @mock_ec2
    def test_ec2_default_nacls(self):

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_networkacl_allow_ingress_tcp_port_3389.ec2_networkacl_allow_ingress_tcp_port_3389.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_networkacl_allow_ingress_tcp_port_3389.ec2_networkacl_allow_ingress_tcp_port_3389 import (
                ec2_networkacl_allow_ingress_tcp_port_3389,
            )

            check = ec2_networkacl_allow_ingress_tcp_port_3389()
            result = check.execute()

            # One default nacl per region
            assert len(result) == 25

    @mock_ec2
    def test_ec2_non_default_compliant_nacl(self):

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_networkacl_allow_ingress_tcp_port_3389.ec2_networkacl_allow_ingress_tcp_port_3389.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_networkacl_allow_ingress_tcp_port_3389.ec2_networkacl_allow_ingress_tcp_port_3389 import (
                ec2_networkacl_allow_ingress_tcp_port_3389,
            )

            check = ec2_networkacl_allow_ingress_tcp_port_3389()
            result = check.execute()

            # One default sg per region
            assert len(result) == 25

            # by default nacls are public
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Network ACL {result[0].resource_id} has Microsoft RDP port 3389 open to the Internet."
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
            Protocol="6",
            PortRange={"From": 3389, "To": 3389},
            RuleAction="allow",
            Egress=False,
            CidrBlock="0.0.0.0/0",
        )

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_networkacl_allow_ingress_tcp_port_3389.ec2_networkacl_allow_ingress_tcp_port_3389.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_networkacl_allow_ingress_tcp_port_3389.ec2_networkacl_allow_ingress_tcp_port_3389 import (
                ec2_networkacl_allow_ingress_tcp_port_3389,
            )

            check = ec2_networkacl_allow_ingress_tcp_port_3389()
            result = check.execute()

            # One default sg per region + default of new VPC + new NACL
            assert len(result) == 27
            # Search changed sg
            for nacl in result:
                if nacl.resource_id == nacl_id:
                    assert nacl.status == "FAIL"
                    assert (
                        nacl.status_extended
                        == f"Network ACL {nacl_id} has Microsoft RDP port 3389 open to the Internet."
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
            Protocol="6",
            PortRange={"From": 3389, "To": 3389},
            RuleAction="allow",
            Egress=False,
            CidrBlock="10.0.0.2/32",
        )

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_networkacl_allow_ingress_tcp_port_3389.ec2_networkacl_allow_ingress_tcp_port_3389.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_networkacl_allow_ingress_tcp_port_3389.ec2_networkacl_allow_ingress_tcp_port_3389 import (
                ec2_networkacl_allow_ingress_tcp_port_3389,
            )

            check = ec2_networkacl_allow_ingress_tcp_port_3389()
            result = check.execute()

            # One default sg per region + default of new VPC + new NACL
            assert len(result) == 27
            # Search changed sg
            for nacl in result:
                if nacl.resource_id == nacl_id:
                    assert nacl.status == "PASS"
                    assert (
                        nacl.status_extended
                        == f"Network ACL {nacl_id} has not Microsoft RDP port 3389 open to the Internet."
                    )
