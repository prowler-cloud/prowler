from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_dynamodb_accelerator_cluster_multi_az:
    @mock_aws
    def test_dax_no_clusters(self):
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_accelerator_cluster_multi_az.dynamodb_accelerator_cluster_multi_az.dax_client",
            new=DAX(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_accelerator_cluster_multi_az.dynamodb_accelerator_cluster_multi_az import (
                dynamodb_accelerator_cluster_multi_az,
            )

            check = dynamodb_accelerator_cluster_multi_az()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_dax_cluster_no_multi_az(self):
        dax_client = client("dax", region_name=AWS_REGION_US_EAST_1)
        iam_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/aws-service-role/dax.amazonaws.com/AWSServiceRoleForDAX"
        cluster = dax_client.create_cluster(
            ClusterName="daxcluster",
            NodeType="dax.t3.small",
            ReplicationFactor=3,
            IamRoleArn=iam_role_arn,
        )["Cluster"]
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_accelerator_cluster_multi_az.dynamodb_accelerator_cluster_multi_az.dax_client",
            new=DAX(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_accelerator_cluster_multi_az.dynamodb_accelerator_cluster_multi_az import (
                dynamodb_accelerator_cluster_multi_az,
            )

            check = dynamodb_accelerator_cluster_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "DAX cluster daxcluster does not have nodes in multiple availability zones."
            )
            assert result[0].resource_id == cluster["ClusterName"]
            assert result[0].resource_arn == cluster["ClusterArn"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_dax_cluster_with_multi_az(self):
        dax_client = client("dax", region_name=AWS_REGION_US_EAST_1)
        iam_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/aws-service-role/dax.amazonaws.com/AWSServiceRoleForDAX"
        cluster = dax_client.create_cluster(
            ClusterName="daxcluster",
            NodeType="dax.t3.small",
            ReplicationFactor=3,
            IamRoleArn=iam_role_arn,
            ClusterEndpointEncryptionType="TLS",
        )["Cluster"]
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_accelerator_cluster_multi_az.dynamodb_accelerator_cluster_multi_az.dax_client",
            new=DAX(aws_provider),
        ) as service_client:
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_accelerator_cluster_multi_az.dynamodb_accelerator_cluster_multi_az import (
                dynamodb_accelerator_cluster_multi_az,
            )

            # Setting node_azs manually as Moto does not support that yet.
            service_client.clusters[0].node_azs = ["us-east-1a", "us-east-1b"]
            check = dynamodb_accelerator_cluster_multi_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "DAX cluster daxcluster has nodes in multiple availability zones."
            )
            assert result[0].resource_id == cluster["ClusterName"]
            assert result[0].resource_arn == cluster["ClusterArn"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
