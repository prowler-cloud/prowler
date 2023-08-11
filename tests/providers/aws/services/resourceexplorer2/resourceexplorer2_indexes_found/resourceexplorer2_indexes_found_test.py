from unittest import mock

from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_service import (
    Indexes,
)
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"
INDEX_ARN = "arn:aws:resource-explorer-2:ap-south-1:123456789012:index/123456-2896-4fe8-93d2-15ec137e5c47"
INDEX_REGION = "us-east-1"


class Test_resourceexplorer2_indexes_found:
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

    def test_no_indexes_found(self):
        resourceexplorer2_client = mock.MagicMock
        resourceexplorer2_client.indexes = []
        resourceexplorer2_client.audited_account = AWS_ACCOUNT_NUMBER
        resourceexplorer2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        resourceexplorer2_client.region = AWS_REGION
        with mock.patch(
            "prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_service.ResourceExplorer2",
            new=resourceexplorer2_client,
        ):
            # Test Check
            from prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_indexes_found.resourceexplorer2_indexes_found import (
                resourceexplorer2_indexes_found,
            )

            check = resourceexplorer2_indexes_found()
            result = check.execute()

            # Assertions
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "No Resource Explorer Indexes found."
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
            assert result[0].region == AWS_REGION

    def test_one_index_found(self):
        resourceexplorer2_client = mock.MagicMock
        resourceexplorer2_client.indexes = [
            Indexes(arn=INDEX_ARN, region=INDEX_REGION, type="LOCAL")
        ]
        resourceexplorer2_client.audited_account = AWS_ACCOUNT_NUMBER
        resourceexplorer2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        resourceexplorer2_client.region = AWS_REGION
        with mock.patch(
            "prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_service.ResourceExplorer2",
            new=resourceexplorer2_client,
        ):
            # Test Check
            from prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_indexes_found.resourceexplorer2_indexes_found import (
                resourceexplorer2_indexes_found,
            )

            check = resourceexplorer2_indexes_found()
            result = check.execute()

            # Assertions
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "Resource Explorer Indexes found: 1."
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == INDEX_ARN
            assert result[0].region == AWS_REGION
