from unittest import mock

from boto3 import session
from mock import patch
from moto import mock_athena

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.services.athena.athena_service_test import mock_make_api_call

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
ATHENA_PRIMARY_WORKGROUP = "primary"
ATHENA_PRIMARY_WORKGROUP_ARN = f"arn:aws:athena:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:workgroup/{ATHENA_PRIMARY_WORKGROUP}"


class Test_athena_workgroup_encryption:
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
            audited_regions=[AWS_REGION],
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

    @mock_athena
    def test_primary_workgroup_not_encrypted(self):
        from prowler.providers.aws.services.athena.athena_service import Athena

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.athena.athena_workgroup_encryption.athena_workgroup_encryption.athena_client",
            new=Athena(current_audit_info),
        ):
            from prowler.providers.aws.services.athena.athena_workgroup_encryption.athena_workgroup_encryption import (
                athena_workgroup_encryption,
            )

            check = athena_workgroup_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Athena WorkGroup {ATHENA_PRIMARY_WORKGROUP} does not encrypt the query results."
            )
            assert result[0].resource_id == ATHENA_PRIMARY_WORKGROUP
            assert result[0].resource_arn == ATHENA_PRIMARY_WORKGROUP_ARN
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    @mock_athena
    # We mock the get_work_group to return an encrypted workgroup
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_primary_workgroup_encrypted(self):
        from prowler.providers.aws.services.athena.athena_service import Athena

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.athena.athena_workgroup_encryption.athena_workgroup_encryption.athena_client",
            new=Athena(current_audit_info),
        ):
            from prowler.providers.aws.services.athena.athena_workgroup_encryption.athena_workgroup_encryption import (
                athena_workgroup_encryption,
            )

            check = athena_workgroup_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Athena WorkGroup {ATHENA_PRIMARY_WORKGROUP} encrypts the query results using SSE_S3."
            )
            assert result[0].resource_id == ATHENA_PRIMARY_WORKGROUP
            assert result[0].resource_arn == ATHENA_PRIMARY_WORKGROUP_ARN
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []
