from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.eks.eks_service import EKS
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

cluster_name = "test"
cidr_block_vpc = "10.0.0.0/16"
cidr_block_subnet_1 = "10.0.0.0/22"
cidr_block_subnet_2 = "10.0.4.0/22"


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_EKS_Service:
    # Test EKS Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider()
        eks = EKS(aws_provider)
        assert eks.service == "eks"

    # Test EKS client
    def test_client(self):
        aws_provider = set_mocked_aws_provider()
        eks = EKS(aws_provider)
        for reg_client in eks.regional_clients.values():
            assert reg_client.__class__.__name__ == "EKS"

    # Test EKS session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider()
        eks = EKS(aws_provider)
        assert eks.session.__class__.__name__ == "Session"

    # Test EKS list clusters
    @mock_aws
    def test__list_clusters(self):
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        eks_client = client("eks", region_name=AWS_REGION_EU_WEST_1)
        vpc = ec2_client.create_vpc(CidrBlock=cidr_block_vpc)
        subnet1 = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"], CidrBlock=cidr_block_subnet_1
        )
        subnet2 = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"], CidrBlock=cidr_block_subnet_2
        )
        eks_client.create_cluster(
            version="1.10",
            name=cluster_name,
            clientRequestToken="1d2129a1-3d38-460a-9756-e5b91fddb951",
            resourcesVpcConfig={
                "subnetIds": [
                    subnet1["Subnet"]["SubnetId"],
                    subnet2["Subnet"]["SubnetId"],
                ],
            },
            roleArn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/eks-service-role-AWSServiceRoleForAmazonEKS-J7ONKE3BQ4PI",
            tags={"test": "test"},
        )
        aws_provider = set_mocked_aws_provider()
        eks = EKS(aws_provider)
        assert len(eks.clusters) == 1
        assert eks.clusters[0].name == cluster_name
        assert eks.clusters[0].region == AWS_REGION_EU_WEST_1
        assert eks.clusters[0].tags == [{"test": "test"}]

    # Test EKS describe clusters
    @mock_aws
    def test__describe_clusters(self):
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        eks_client = client("eks", region_name=AWS_REGION_EU_WEST_1)
        vpc = ec2_client.create_vpc(CidrBlock=cidr_block_vpc)
        subnet1 = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"], CidrBlock=cidr_block_subnet_1
        )
        subnet2 = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"], CidrBlock=cidr_block_subnet_2
        )
        cluster = eks_client.create_cluster(
            version="1.10",
            name=cluster_name,
            clientRequestToken="1d2129a1-3d38-460a-9756-e5b91fddb951",
            resourcesVpcConfig={
                "subnetIds": [
                    subnet1["Subnet"]["SubnetId"],
                    subnet2["Subnet"]["SubnetId"],
                ],
                "endpointPublicAccess": True,
                "endpointPrivateAccess": True,
                "publicAccessCidrs": [
                    "0.0.0.0/0",
                ],
            },
            logging={
                "clusterLogging": [
                    {
                        "types": [
                            "api",
                        ],
                        "enabled": True,
                    },
                ]
            },
            roleArn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/eks-service-role-AWSServiceRoleForAmazonEKS-J7ONKE3BQ4PI",
            encryptionConfig=[
                {
                    "resources": [
                        "secrets",
                    ],
                },
            ],
        )
        aws_provider = set_mocked_aws_provider()
        eks = EKS(aws_provider)
        assert len(eks.clusters) == 1
        assert eks.clusters[0].name == cluster_name
        assert eks.clusters[0].region == AWS_REGION_EU_WEST_1
        assert eks.clusters[0].arn == cluster["cluster"]["arn"]
        assert eks.clusters[0].logging.types == ["api"]
        assert eks.clusters[0].logging.enabled
        assert eks.clusters[0].endpoint_public_access
        assert eks.clusters[0].endpoint_private_access
        assert eks.clusters[0].public_access_cidrs == ["0.0.0.0/0"]
        assert eks.clusters[0].encryptionConfig
        assert eks.clusters[0].version == "1.10"
