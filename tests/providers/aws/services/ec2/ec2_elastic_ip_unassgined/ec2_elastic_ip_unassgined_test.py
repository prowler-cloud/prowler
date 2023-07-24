from re import search
from unittest import mock

from boto3 import client, resource, session
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
EXAMPLE_AMI_ID = "ami-12c6146b"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_ec2_elastic_ip_unassgined:
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
    def test_no_eips(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_elastic_ip_unassgined.ec2_elastic_ip_unassgined.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_elastic_ip_unassgined.ec2_elastic_ip_unassgined import (
                ec2_elastic_ip_unassgined,
            )

            check = ec2_elastic_ip_unassgined()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    def test_eip_unassociated(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        allocation_id = ec2_client.allocate_address(
            Domain="vpc", Address="127.38.43.222"
        )["AllocationId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_elastic_ip_unassgined.ec2_elastic_ip_unassgined.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_elastic_ip_unassgined.ec2_elastic_ip_unassgined import (
                ec2_elastic_ip_unassgined,
            )

            check = ec2_elastic_ip_unassgined()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert search(
                "is not associated",
                results[0].status_extended,
            )
            assert (
                results[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:eip-allocation/{allocation_id}"
            )

    @mock_ec2
    def test_eip_associated(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_resource = resource("ec2", region_name=AWS_REGION)

        reservation = ec2_client.run_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1
        )
        instance = ec2_resource.Instance(reservation["Instances"][0]["InstanceId"])

        eip = ec2_client.allocate_address(Domain="vpc")

        eip = ec2_resource.VpcAddress(eip["AllocationId"])

        ec2_client.associate_address(
            InstanceId=instance.id, AllocationId=eip.allocation_id
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_elastic_ip_unassgined.ec2_elastic_ip_unassgined.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_elastic_ip_unassgined.ec2_elastic_ip_unassgined import (
                ec2_elastic_ip_unassgined,
            )

            check = ec2_elastic_ip_unassgined()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "PASS"
            assert search(
                "is associated",
                results[0].status_extended,
            )
            assert (
                results[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:eip-allocation/{eip.allocation_id}"
            )
