from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.redshift.redshift_service import Cluster
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

CLUSTER_ID = str(uuid4())
CLUSTER_ARN = (
    f"arn:aws:redshift:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster:{CLUSTER_ID}"
)


class Test_redshift_cluster_public_access:
    def test_no_clusters(self):
        redshift_client = mock.MagicMock
        redshift_client.clusters = []
        vpc_client = mock.MagicMock
        ec2_client = mock.MagicMock
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.redshift_client",
                new=redshift_client,
            ), mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.vpc_client",
                new=vpc_client,
            ), mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.ec2_client",
                new=ec2_client,
            ):
                from prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access import (
                    redshift_cluster_public_access,
                )

                check = redshift_cluster_public_access()
                result = check.execute()
                assert len(result) == 0

    def test_cluster_with_public_endpoint(self):
        redshift_client = mock.MagicMock
        redshift_client.clusters = []
        redshift_client.clusters.append(
            Cluster(
                id=CLUSTER_ID,
                arn=CLUSTER_ARN,
                region=AWS_REGION_EU_WEST_1,
                public_access=True,
                endpoint_address="192.192.192.192",
            )
        )
        vpc_client = mock.MagicMock
        ec2_client = mock.MagicMock
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.redshift_client",
                new=redshift_client,
            ), mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.vpc_client",
                new=vpc_client,
            ), mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.ec2_client",
                new=ec2_client,
            ):
                from prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access import (
                    redshift_cluster_public_access,
                )

                check = redshift_cluster_public_access()
                result = check.execute()
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Redshift Cluster {CLUSTER_ID} has the endpoint 192.192.192.192 set as publicly accessible but is not publicly exposed."
                )
                assert result[0].resource_id == CLUSTER_ID
                assert result[0].resource_arn == CLUSTER_ARN

    def test_cluster_is_not_public1(self):
        redshift_client = mock.MagicMock
        redshift_client.clusters = []
        redshift_client.clusters.append(
            Cluster(
                id=CLUSTER_ID,
                arn=CLUSTER_ARN,
                region=AWS_REGION_EU_WEST_1,
                public_access=False,
                endpoint_address="192.192.192.192",
            )
        )
        vpc_client = mock.MagicMock
        ec2_client = mock.MagicMock
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.redshift_client",
                new=redshift_client,
            ), mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.vpc_client",
                new=vpc_client,
            ), mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.ec2_client",
                new=ec2_client,
            ):
                from prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access import (
                    redshift_cluster_public_access,
                )

                check = redshift_cluster_public_access()
                result = check.execute()
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Redshift Cluster {CLUSTER_ID} is not publicly accessible."
                )
                assert result[0].resource_id == CLUSTER_ID
                assert result[0].resource_arn == CLUSTER_ARN

    def test_cluster_is_not_public2(self):
        redshift_client = mock.MagicMock
        redshift_client.clusters = []
        redshift_client.clusters.append(
            Cluster(
                id=CLUSTER_ID,
                arn=CLUSTER_ARN,
                region=AWS_REGION_EU_WEST_1,
                public_access=True,
            )
        )
        vpc_client = mock.MagicMock
        ec2_client = mock.MagicMock
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.redshift_client",
                new=redshift_client,
            ), mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.vpc_client",
                new=vpc_client,
            ), mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.ec2_client",
                new=ec2_client,
            ):
                from prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access import (
                    redshift_cluster_public_access,
                )

                check = redshift_cluster_public_access()
                result = check.execute()
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Redshift Cluster {CLUSTER_ID} is not publicly accessible."
                )
                assert result[0].resource_id == CLUSTER_ID
                assert result[0].resource_arn == CLUSTER_ARN

    def test_cluster_is_in_public_subnet(self):
        redshift_client = mock.MagicMock
        redshift_client.clusters = []
        redshift_client.clusters.append(
            Cluster(
                id=CLUSTER_ID,
                arn=CLUSTER_ARN,
                region=AWS_REGION_EU_WEST_1,
                public_access=True,
                vpc_id="vpc-123456",
                subnets=["subnet-123456"],
                endpoint_address="192.192.192.192",
            )
        )
        vpc_client = mock.MagicMock
        vpc_client.subnets = {"subnet-123456": mock.MagicMock(public=True)}
        ec2_client = mock.MagicMock
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.redshift_client",
                new=redshift_client,
            ), mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.vpc_client",
                new=vpc_client,
            ), mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.ec2_client",
                new=ec2_client,
            ):
                from prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access import (
                    redshift_cluster_public_access,
                )

                check = redshift_cluster_public_access()
                result = check.execute()
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Redshift Cluster {CLUSTER_ID} has the endpoint 192.192.192.192 set as publicly accessible in a public subnet but is not publicly exposed."
                )
                assert result[0].resource_id == CLUSTER_ID
                assert result[0].resource_arn == CLUSTER_ARN

    def test_cluster_with_public_vpc_sgs(self):
        redshift_client = mock.MagicMock
        redshift_client.audited_partition = "aws"
        redshift_client.audited_account = AWS_ACCOUNT_NUMBER
        redshift_client.clusters = []
        redshift_client.clusters.append(
            Cluster(
                id=CLUSTER_ID,
                arn=CLUSTER_ARN,
                region=AWS_REGION_EU_WEST_1,
                vpc_id="vpc-123456",
                public_access=True,
                vpc_security_groups=["sg-123456"],
                endpoint_address="192.192.192.192",
                subnets=["subnet-123456"],
            )
        )
        vpc_client = mock.MagicMock
        vpc_client.subnets = {"subnet-123456": mock.MagicMock(public=True)}
        ec2_client = mock.MagicMock
        ec2_client.security_groups = {
            f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:security-group/sg-123456": mock.MagicMock(
                id="sg-123456",
                ingress_rules=[
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [
                            {
                                "CidrIp": "0.0.0.0/0",
                            },
                        ],
                    }
                ],
            )
        }
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.redshift_client",
                new=redshift_client,
            ), mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.vpc_client",
                new=vpc_client,
            ), mock.patch(
                "prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access.ec2_client",
                new=ec2_client,
            ):
                from prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access import (
                    redshift_cluster_public_access,
                )

                check = redshift_cluster_public_access()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Redshift Cluster {CLUSTER_ID} has the endpoint 192.192.192.192 set as publicly accessible and it is exposed to the Internet by security group (sg-123456) in a public subnet."
                )
                assert result[0].resource_id == CLUSTER_ID
                assert result[0].resource_arn == CLUSTER_ARN
