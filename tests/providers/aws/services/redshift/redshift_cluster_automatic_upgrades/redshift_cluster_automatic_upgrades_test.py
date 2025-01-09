from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.redshift.redshift_service import Cluster
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

CLUSTER_ID = str(uuid4())
CLUSTER_ARN = (
    f"arn:aws:redshift:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:cluster:{CLUSTER_ID}"
)


class Test_redshift_cluster_automatic_upgrades:
    def test_no_clusters(self):
        redshift_client = mock.MagicMock
        redshift_client.clusters = []
        with mock.patch(
            "prowler.providers.aws.services.redshift.redshift_service.Redshift",
            redshift_client,
        ), mock.patch(
            "prowler.providers.aws.services.redshift.redshift_client.redshift_client",
            redshift_client,
        ):
            from prowler.providers.aws.services.redshift.redshift_cluster_automatic_upgrades.redshift_cluster_automatic_upgrades import (
                redshift_cluster_automatic_upgrades,
            )

            check = redshift_cluster_automatic_upgrades()
            result = check.execute()
            assert len(result) == 0

    def test_cluster_not_automatic_upgrades(self):
        redshift_client = mock.MagicMock
        redshift_client.clusters = []
        redshift_client.clusters.append(
            Cluster(
                id=CLUSTER_ID,
                arn=CLUSTER_ARN,
                region=AWS_REGION_EU_WEST_1,
                allow_version_upgrade=False,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.redshift.redshift_service.Redshift",
            redshift_client,
        ), mock.patch(
            "prowler.providers.aws.services.redshift.redshift_client.redshift_client",
            redshift_client,
        ):
            from prowler.providers.aws.services.redshift.redshift_cluster_automatic_upgrades.redshift_cluster_automatic_upgrades import (
                redshift_cluster_automatic_upgrades,
            )

            check = redshift_cluster_automatic_upgrades()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Redshift Cluster {CLUSTER_ID} has AllowVersionUpgrade disabled."
            )
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_arn == CLUSTER_ARN

    def test_cluster_automatic_upgrades(self):
        redshift_client = mock.MagicMock
        redshift_client.clusters = []
        redshift_client.clusters.append(
            Cluster(
                id=CLUSTER_ID,
                arn=CLUSTER_ARN,
                region=AWS_REGION_EU_WEST_1,
                allow_version_upgrade=True,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.redshift.redshift_service.Redshift",
            redshift_client,
        ), mock.patch(
            "prowler.providers.aws.services.redshift.redshift_client.redshift_client",
            redshift_client,
        ):
            from prowler.providers.aws.services.redshift.redshift_cluster_automatic_upgrades.redshift_cluster_automatic_upgrades import (
                redshift_cluster_automatic_upgrades,
            )

            check = redshift_cluster_automatic_upgrades()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Redshift Cluster {CLUSTER_ID} has AllowVersionUpgrade enabled."
            )
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_arn == CLUSTER_ARN
