from unittest import mock

from boto3 import client, session
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class ec2_networkacl_allow_ingress_any_port:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
        )

        return audit_info

    @mock_ec2
    def test_ec2_default_nacls(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

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
            assert len(result) == 3

    @mock_ec2
    def test_ec2_non_default_compliant_nacl(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

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
            assert len(result) == 3

            # by default nacls are public
            assert result[0].status == "FAIL"
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

        current_audit_info = self.set_mocked_audit_info()

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

        current_audit_info = self.set_mocked_audit_info()

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
                    assert (
                        nacl.status_extended
                        == f"Network ACL {nacl_id} has not every port open to the Internet."
                    )
                    assert (
                        nacl.resource_arn
                        == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:network-acl/{nacl_id}"
                    )
