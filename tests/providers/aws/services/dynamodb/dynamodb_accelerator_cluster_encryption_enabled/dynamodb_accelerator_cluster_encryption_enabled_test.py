from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_dax
from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_REGION = "us-east-1"


class Test_dynamodb_accelerator_cluster_encryption_enabled:
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

    @mock_dax
    def test_dax_no_clusters(self):
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_accelerator_cluster_encryption_enabled.dynamodb_accelerator_cluster_encryption_enabled.dax_client",
            new=DAX(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_accelerator_cluster_encryption_enabled.dynamodb_accelerator_cluster_encryption_enabled import (
                dynamodb_accelerator_cluster_encryption_enabled,
            )

            check = dynamodb_accelerator_cluster_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_dax
    def test_dax_cluster_no_encryption(self):
        dax_client = client("dax", region_name=AWS_REGION)
        iam_role_arn = f"arn:aws:iam::{DEFAULT_ACCOUNT_ID}:role/aws-service-role/dax.amazonaws.com/AWSServiceRoleForDAX"
        cluster = dax_client.create_cluster(
            ClusterName="daxcluster",
            NodeType="dax.t3.small",
            ReplicationFactor=3,
            IamRoleArn=iam_role_arn,
        )["Cluster"]
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_accelerator_cluster_encryption_enabled.dynamodb_accelerator_cluster_encryption_enabled.dax_client",
            new=DAX(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_accelerator_cluster_encryption_enabled.dynamodb_accelerator_cluster_encryption_enabled import (
                dynamodb_accelerator_cluster_encryption_enabled,
            )

            check = dynamodb_accelerator_cluster_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have encryption at rest enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == cluster["ClusterName"]
            assert result[0].resource_arn == cluster["ClusterArn"]
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    @mock_dax
    def test_dax_cluster_with_encryption(self):
        dax_client = client("dax", region_name=AWS_REGION)
        iam_role_arn = f"arn:aws:iam::{DEFAULT_ACCOUNT_ID}:role/aws-service-role/dax.amazonaws.com/AWSServiceRoleForDAX"
        cluster = dax_client.create_cluster(
            ClusterName="daxcluster",
            NodeType="dax.t3.small",
            ReplicationFactor=3,
            IamRoleArn=iam_role_arn,
            SSESpecification={"Enabled": True},
        )["Cluster"]
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_accelerator_cluster_encryption_enabled.dynamodb_accelerator_cluster_encryption_enabled.dax_client",
            new=DAX(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_accelerator_cluster_encryption_enabled.dynamodb_accelerator_cluster_encryption_enabled import (
                dynamodb_accelerator_cluster_encryption_enabled,
            )

            check = dynamodb_accelerator_cluster_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("has encryption at rest enabled", result[0].status_extended)
            assert result[0].resource_id == cluster["ClusterName"]
            assert result[0].resource_arn == cluster["ClusterArn"]
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []
