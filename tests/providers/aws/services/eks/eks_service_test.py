from unittest.mock import patch

from boto3 import client, session
from moto import mock_ec2, mock_eks

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.eks.eks_service import EKS

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "eu-west-1"

cluster_name = "test"
cidr_block_vpc = "10.0.0.0/16"
cidr_block_subnet_1 = "10.0.0.0/22"
cidr_block_subnet_2 = "10.0.4.0/22"


def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch(
    "prowler.providers.aws.services.eks.eks_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_EKS_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    # Test EKS Service
    def test_service(self):
        audit_info = self.set_mocked_audit_info()
        eks = EKS(audit_info)
        assert eks.service == "eks"

    # Test EKS client
    def test_client(self):
        audit_info = self.set_mocked_audit_info()
        eks = EKS(audit_info)
        for reg_client in eks.regional_clients.values():
            assert reg_client.__class__.__name__ == "EKS"

    # Test EKS session
    def test__get_session__(self):
        audit_info = self.set_mocked_audit_info()
        eks = EKS(audit_info)
        assert eks.session.__class__.__name__ == "Session"

    # Test EKS list clusters
    @mock_ec2
    @mock_eks
    def test__list_clusters(self):
        ec2_client = client("ec2", region_name=AWS_REGION)
        eks_client = client("eks", region_name=AWS_REGION)
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
        audit_info = self.set_mocked_audit_info()
        eks = EKS(audit_info)
        assert len(eks.clusters) == 1
        assert eks.clusters[0].name == cluster_name
        assert eks.clusters[0].region == AWS_REGION
        assert eks.clusters[0].tags == [{"test": "test"}]

    # Test EKS describe clusters
    @mock_ec2
    @mock_eks
    def test__describe_clusters(self):
        ec2_client = client("ec2", region_name=AWS_REGION)
        eks_client = client("eks", region_name=AWS_REGION)
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
        audit_info = self.set_mocked_audit_info()
        eks = EKS(audit_info)
        assert len(eks.clusters) == 1
        assert eks.clusters[0].name == cluster_name
        assert eks.clusters[0].region == AWS_REGION
        assert eks.clusters[0].arn == cluster["cluster"]["arn"]
        assert eks.clusters[0].logging.types == ["api"]
        assert eks.clusters[0].logging.enabled
        assert eks.clusters[0].endpoint_public_access
        assert eks.clusters[0].endpoint_private_access
        assert eks.clusters[0].public_access_cidrs == ["0.0.0.0/0"]
        assert eks.clusters[0].encryptionConfig
