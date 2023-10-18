from unittest import mock

from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.macie.macie_service import Session
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"


AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_macie_is_enabled:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
                region_name=AWS_REGION,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
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

    def test_macie_disabled(self):
        macie_client = mock.MagicMock
        s3_client = mock.MagicMock
        s3_client.audit_info = self.set_mocked_audit_info()
        macie_client.audit_info = self.set_mocked_audit_info()
        macie_client.audited_account = AWS_ACCOUNT_NUMBER
        macie_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        macie_client.sessions = [
            Session(
                status="DISABLED",
                region="eu-west-1",
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.macie.macie_service.Macie",
            new=macie_client,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_service.S3",
            new=s3_client,
        ):
            # Test Check
            from prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled import (
                macie_is_enabled,
            )

            check = macie_is_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "Macie is not enabled."
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER

    def test_macie_enabled(self):
        macie_client = mock.MagicMock
        s3_client = mock.MagicMock
        s3_client.audit_info = self.set_mocked_audit_info()
        macie_client.audit_info = self.set_mocked_audit_info()
        macie_client.audited_account = AWS_ACCOUNT_NUMBER
        macie_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        macie_client.sessions = [
            Session(
                status="ENABLED",
                region="eu-west-1",
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.macie.macie_service.Macie",
            new=macie_client,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_service.S3",
            new=s3_client,
        ):
            # Test Check
            from prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled import (
                macie_is_enabled,
            )

            check = macie_is_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "Macie is enabled."
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER

    def test_macie_suspended_ignored(self):
        macie_client = mock.MagicMock
        s3_client = mock.MagicMock
        s3_client.audit_info = self.set_mocked_audit_info()
        s3_client.buckets = []
        macie_client.audit_info = self.set_mocked_audit_info()
        macie_client.audited_account = AWS_ACCOUNT_NUMBER
        macie_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        macie_client.sessions = [
            Session(
                status="PAUSED",
                region="eu-west-1",
            )
        ]

        macie_client.audit_info.ignore_unused_services = True
        with mock.patch(
            "prowler.providers.aws.services.macie.macie_service.Macie",
            new=macie_client,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_service.S3",
            new=s3_client,
        ):

            # Test Check
            from prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled import (
                macie_is_enabled,
            )

            check = macie_is_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_macie_suspended(self):
        macie_client = mock.MagicMock
        s3_client = mock.MagicMock
        s3_client.audit_info = self.set_mocked_audit_info()
        macie_client.audit_info = self.set_mocked_audit_info()
        macie_client.audited_account = AWS_ACCOUNT_NUMBER
        macie_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        macie_client.sessions = [
            Session(
                status="PAUSED",
                region="eu-west-1",
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.macie.macie_service.Macie",
            new=macie_client,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_service.S3",
            new=s3_client,
        ):

            # Test Check
            from prowler.providers.aws.services.macie.macie_is_enabled.macie_is_enabled import (
                macie_is_enabled,
            )

            check = macie_is_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended == "Macie is currently in a SUSPENDED state."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
