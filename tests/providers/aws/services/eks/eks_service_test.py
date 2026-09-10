from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.eks.eks_service import EKS
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    mocked_api_response,
    set_mocked_aws_provider,
)

cluster_name = "test"
cidr_block_vpc = "10.0.0.0/16"
cidr_block_subnet_1 = "10.0.0.0/22"
cidr_block_subnet_2 = "10.0.4.0/22"
cluster_arn = (
    f"arn:aws:eks:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster/{cluster_name}"
)
vpc_cni_addon_arn = f"arn:aws:eks:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:addon/{cluster_name}/vpc-cni/1a2b3c4d"
vpc_cni_configuration_values = '{"enableNetworkPolicy":"true"}'

make_api_call = botocore.client.BaseClient._make_api_call
described_addons = []


def _addon_response(addon_name, arn, configuration_values=None):
    """Build a DescribeAddon response, omitting `configurationValues` when none is given.

    The key is absent from the API response for an add-on left at its defaults, so passing None
    reproduces that rather than sending an empty string.
    """
    addon = {"addonName": addon_name, "addonArn": arn, "clusterName": cluster_name}
    if configuration_values is not None:
        addon["configurationValues"] = configuration_values
    return mocked_api_response("eks", "DescribeAddon", {"addon": addon})


def mock_make_api_call_addons(self, operation_name, kwargs):
    """Serve the add-on inventory, with vpc-cni on the SECOND ListAddons page."""
    if operation_name == "ListClusters":
        return mocked_api_response("eks", "ListClusters", {"clusters": [cluster_name]})
    if operation_name == "DescribeCluster":
        return mocked_api_response(
            "eks",
            "DescribeCluster",
            {"cluster": {"name": cluster_name, "arn": cluster_arn, "version": "1.34"}},
        )
    if operation_name == "ListAddons":
        if kwargs.get("nextToken") is None:
            return mocked_api_response(
                "eks",
                "ListAddons",
                {"addons": ["coredns"], "nextToken": "second-page"},
            )
        return mocked_api_response("eks", "ListAddons", {"addons": ["vpc-cni"]})
    if operation_name == "DescribeAddon":
        described_addons.append(kwargs["addonName"])
        if kwargs["addonName"] == "vpc-cni":
            return _addon_response(
                "vpc-cni", vpc_cni_addon_arn, vpc_cni_configuration_values
            )
        return _addon_response(
            "coredns",
            f"arn:aws:eks:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:addon/{cluster_name}/coredns/5e6f7a8b",
        )
    return make_api_call(self, operation_name, kwargs)


def mock_make_api_call_list_addons_denied(self, operation_name, kwargs):
    """Deny ListAddons and serve every other call, as a role without eks:ListAddons would."""
    if operation_name == "ListAddons":
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return mock_make_api_call_addons(self, operation_name, kwargs)


def mock_make_api_call_describe_vpc_cni_denied(self, operation_name, kwargs):
    """Deny DescribeAddon for vpc-cni only, so listing succeeds and the per-add-on read fails."""
    if operation_name == "DescribeAddon" and kwargs["addonName"] == "vpc-cni":
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return mock_make_api_call_addons(self, operation_name, kwargs)


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
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        eks = EKS(aws_provider)
        assert eks.service == "eks"

    # Test EKS client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        eks = EKS(aws_provider)
        for reg_client in eks.regional_clients.values():
            assert reg_client.__class__.__name__ == "EKS"

    # Test EKS session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
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
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
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
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
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


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_EKS_Service_Addons:
    # Test EKS describe cluster add-ons
    @mock_aws
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_addons,
    )
    def test__describe_cluster_addons(self):
        """vpc-cni is collected with its ARN and configuration from the SECOND ListAddons page.

        Also asserts coredns costs no DescribeAddon call: it is listed on the cluster but not in
        COLLECTED_ADDONS, and DescribeAddon has no batch form, so describing it would be one extra
        API call per cluster for data no check reads.
        """
        described_addons.clear()
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        eks = EKS(aws_provider)

        assert len(eks.clusters) == 1
        cluster = eks.clusters[0]
        assert not cluster.addons_discovery_failed
        # vpc-cni is only on the second ListAddons page, so this fails without pagination
        assert sorted(cluster.addons) == ["vpc-cni"]
        assert cluster.addons["vpc-cni"].name == "vpc-cni"
        assert cluster.addons["vpc-cni"].arn == vpc_cni_addon_arn
        assert (
            cluster.addons["vpc-cni"].configuration_values
            == vpc_cni_configuration_values
        )
        assert not cluster.addons["vpc-cni"].configuration_discovery_failed
        # coredns is listed but not in COLLECTED_ADDONS, so it costs no DescribeAddon call
        assert described_addons == ["vpc-cni"]

    # Test EKS cluster add-ons cannot be listed
    @mock_aws
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_list_addons_denied,
    )
    def test__describe_cluster_addons_list_denied(self):
        """A denied ListAddons sets addons_discovery_failed and issues no DescribeAddon call.

        The cluster itself must survive collection: a missing add-on permission may not cost the
        scan every other EKS finding for that cluster.
        """
        described_addons.clear()
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        eks = EKS(aws_provider)

        assert len(eks.clusters) == 1
        assert eks.clusters[0].addons_discovery_failed
        assert eks.clusters[0].addons == {}
        assert described_addons == []

    # Test EKS cluster add-on configuration cannot be described
    @mock_aws
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_describe_vpc_cni_denied,
    )
    def test__describe_cluster_addons_describe_denied(self):
        """A denied DescribeAddon flags the add-on, not the cluster, and leaves its fields None.

        The add-on is known to exist because ListAddons succeeded, so the failure belongs on
        `configuration_discovery_failed` while `addons_discovery_failed` stays false.
        """
        described_addons.clear()
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        eks = EKS(aws_provider)

        assert len(eks.clusters) == 1
        cluster = eks.clusters[0]
        assert not cluster.addons_discovery_failed
        assert sorted(cluster.addons) == ["vpc-cni"]
        assert cluster.addons["vpc-cni"].configuration_discovery_failed
        assert cluster.addons["vpc-cni"].configuration_values is None
        assert cluster.addons["vpc-cni"].arn is None
