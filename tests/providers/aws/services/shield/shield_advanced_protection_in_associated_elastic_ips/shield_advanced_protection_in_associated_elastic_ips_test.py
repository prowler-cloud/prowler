from unittest import mock

from boto3 import client, session
from mock import patch
from moto import mock_ec2
from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.shield.shield_service import Protection
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "eu-west-1"


# Mock generate_regional_clients()
def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch(
    "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_shield_advanced_protection_in_associated_elastic_ips:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=DEFAULT_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{DEFAULT_ACCOUNT_ID}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
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
    def test_no_shield_not_active(self):
        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips.ec2_client",
            new=EC2(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips import (
                shield_advanced_protection_in_associated_elastic_ips,
            )

            check = shield_advanced_protection_in_associated_elastic_ips()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    def test_shield_enabled_ip_protected(self):
        # EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        resp = ec2_client.allocate_address(Domain="vpc", Address="127.38.43.222")
        allocation_id = resp["AllocationId"]
        elastic_ip_arn = f"arn:aws:ec2:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:eip-allocation/{allocation_id}"

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION
        protection_id = "test-protection"
        shield_client.protections = {
            protection_id: Protection(
                id=protection_id,
                name="",
                resource_arn=elastic_ip_arn,
                protection_arn="",
                region=AWS_REGION,
            )
        }

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips.ec2_client",
            new=EC2(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips import (
                shield_advanced_protection_in_associated_elastic_ips,
            )

            check = shield_advanced_protection_in_associated_elastic_ips()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == allocation_id
            assert result[0].resource_arn == elastic_ip_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Elastic IP {allocation_id} is protected by AWS Shield Advanced"
            )

    @mock_ec2
    def test_shield_enabled_ip_not_protected(self):
        # EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        resp = ec2_client.allocate_address(Domain="vpc", Address="127.38.43.222")
        allocation_id = resp["AllocationId"]
        elastic_ip_arn = f"arn:aws:ec2:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:eip-allocation/{allocation_id}"

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = True
        shield_client.region = AWS_REGION
        shield_client.protections = {}

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips.ec2_client",
            new=EC2(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips import (
                shield_advanced_protection_in_associated_elastic_ips,
            )

            check = shield_advanced_protection_in_associated_elastic_ips()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == allocation_id
            assert result[0].resource_arn == elastic_ip_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Elastic IP {allocation_id} is not protected by AWS Shield Advanced"
            )

    @mock_ec2
    def test_shield_disabled_ip_not_protected(self):
        # EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        resp = ec2_client.allocate_address(Domain="vpc", Address="127.38.43.222")
        allocation_id = resp["AllocationId"]
        _ = f"arn:aws:ec2:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:eip-allocation/{allocation_id}"

        # Shield Client
        shield_client = mock.MagicMock
        shield_client.enabled = False
        shield_client.region = AWS_REGION
        shield_client.protections = {}

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.shield.shield_service.Shield",
            new=shield_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips.ec2_client",
            new=EC2(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.shield.shield_advanced_protection_in_associated_elastic_ips.shield_advanced_protection_in_associated_elastic_ips import (
                shield_advanced_protection_in_associated_elastic_ips,
            )

            check = shield_advanced_protection_in_associated_elastic_ips()
            result = check.execute()

            assert len(result) == 0
