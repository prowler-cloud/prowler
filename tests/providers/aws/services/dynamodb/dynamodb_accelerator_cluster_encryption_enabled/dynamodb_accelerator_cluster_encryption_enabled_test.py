from re import search
from unittest import mock

from boto3 import client
from moto import mock_dax

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_dynamodb_accelerator_cluster_encryption_enabled:
    @mock_dax
    def test_dax_no_clusters(self):
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

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
        dax_client = client("dax", region_name=AWS_REGION_US_EAST_1)
        iam_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/aws-service-role/dax.amazonaws.com/AWSServiceRoleForDAX"
        cluster = dax_client.create_cluster(
            ClusterName="daxcluster",
            NodeType="dax.t3.small",
            ReplicationFactor=3,
            IamRoleArn=iam_role_arn,
        )["Cluster"]
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

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
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_dax
    def test_dax_cluster_with_encryption(self):
        dax_client = client("dax", region_name=AWS_REGION_US_EAST_1)
        iam_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/aws-service-role/dax.amazonaws.com/AWSServiceRoleForDAX"
        cluster = dax_client.create_cluster(
            ClusterName="daxcluster",
            NodeType="dax.t3.small",
            ReplicationFactor=3,
            IamRoleArn=iam_role_arn,
            SSESpecification={"Enabled": True},
        )["Cluster"]
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

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
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
