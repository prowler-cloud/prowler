from unittest import mock

from boto3 import client, session
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_vpc_subnet_different_az:
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )

        return audit_info

    @mock_ec2
    def test_vpc_subnet_different_az(self):
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        # VPC AZ 1
        ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION}a",
        )

        # VPC AZ 2
        ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=f"{AWS_REGION}b",
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_subnet_different_az.vpc_subnet_different_az.vpc_client",
                new=VPC(current_audit_info),
            ):
                from prowler.providers.aws.services.vpc.vpc_subnet_different_az.vpc_subnet_different_az import (
                    vpc_subnet_different_az,
                )

                check = vpc_subnet_different_az()
                results = check.execute()

                found = False
                for result in results:
                    if result.resource_id == vpc["Vpc"]["VpcId"]:
                        found = True
                        assert result.status == "PASS"
                        assert (
                            result.status_extended
                            == f"VPC {vpc['Vpc']['VpcId']} has subnets in more than one availability zone."
                        )
                        assert result.resource_id == vpc["Vpc"]["VpcId"]
                        assert result.resource_tags == []
                        assert result.region == AWS_REGION
                if not found:
                    assert False

    @mock_ec2
    def test_vpc_subnet_same_az(self):
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        # VPC AZ 1
        ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION}a",
        )

        # VPC AZ 2
        ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=f"{AWS_REGION}a",
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_subnet_different_az.vpc_subnet_different_az.vpc_client",
                new=VPC(current_audit_info),
            ):
                from prowler.providers.aws.services.vpc.vpc_subnet_different_az.vpc_subnet_different_az import (
                    vpc_subnet_different_az,
                )

                check = vpc_subnet_different_az()
                results = check.execute()

                found = False
                for result in results:
                    if result.resource_id == vpc["Vpc"]["VpcId"]:
                        found = True
                        assert result.status == "FAIL"
                        assert (
                            result.status_extended
                            == f"VPC {vpc['Vpc']['VpcId']} has only subnets in {AWS_REGION}a."
                        )
                        assert result.resource_id == vpc["Vpc"]["VpcId"]
                        assert result.resource_tags == []
                        assert result.region == AWS_REGION
                if not found:
                    assert False

    @mock_ec2
    def test_vpc_no_subnets(self):
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_subnet_different_az.vpc_subnet_different_az.vpc_client",
                new=VPC(current_audit_info),
            ):
                from prowler.providers.aws.services.vpc.vpc_subnet_different_az.vpc_subnet_different_az import (
                    vpc_subnet_different_az,
                )

                check = vpc_subnet_different_az()
                results = check.execute()

                found = False
                for result in results:
                    if result.resource_id == vpc["Vpc"]["VpcId"]:
                        found = True
                        assert result.status == "FAIL"
                        assert (
                            result.status_extended
                            == f"VPC {vpc['Vpc']['VpcId']} has no subnets."
                        )
                        assert result.resource_id == vpc["Vpc"]["VpcId"]
                        assert result.resource_tags == []
                        assert result.region == AWS_REGION
                if not found:
                    assert False
