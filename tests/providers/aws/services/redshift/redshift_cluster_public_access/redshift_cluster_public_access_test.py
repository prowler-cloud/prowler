from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.redshift.redshift_service import Cluster
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

CLUSTER_ID = str(uuid4())
CLUSTER_ARN = (
    f"arn:aws:redshift:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster:{CLUSTER_ID}"
)


class Test_redshift_cluster_public_access:
    def test_no_clusters(self):
        redshift_client = mock.MagicMock
        redshift_client.clusters = []
        with mock.patch(
            "prowler.providers.aws.services.redshift.redshift_service.Redshift",
            redshift_client,
        ):
            from prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access import (
                redshift_cluster_public_access,
            )

            check = redshift_cluster_public_access()
            result = check.execute()
            assert len(result) == 0

    def test_cluster_is_public(self):
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
        with mock.patch(
            "prowler.providers.aws.services.redshift.redshift_service.Redshift",
            redshift_client,
        ):
            from prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access import (
                redshift_cluster_public_access,
            )

            check = redshift_cluster_public_access()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search("is publicly accessible", result[0].status_extended)
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
        with mock.patch(
            "prowler.providers.aws.services.redshift.redshift_service.Redshift",
            redshift_client,
        ):
            from prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access import (
                redshift_cluster_public_access,
            )

            check = redshift_cluster_public_access()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search("is not publicly accessible", result[0].status_extended)
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
        with mock.patch(
            "prowler.providers.aws.services.redshift.redshift_service.Redshift",
            redshift_client,
        ):
            from prowler.providers.aws.services.redshift.redshift_cluster_public_access.redshift_cluster_public_access import (
                redshift_cluster_public_access,
            )

            check = redshift_cluster_public_access()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search("is not publicly accessible", result[0].status_extended)
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_arn == CLUSTER_ARN
