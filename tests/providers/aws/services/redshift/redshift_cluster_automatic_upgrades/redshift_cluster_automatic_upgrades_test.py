from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.redshift.redshift_service import Cluster

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

cluster_id = str(uuid4())


class Test_redshift_cluster_automatic_upgrades:
    def test_no_clusters(self):
        redshift_client = mock.MagicMock
        redshift_client.clusters = []
        with mock.patch(
            "prowler.providers.aws.services.redshift.redshift_service.Redshift",
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
                id=cluster_id,
                region=AWS_REGION,
                allow_version_upgrade=False,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.redshift.redshift_service.Redshift",
            redshift_client,
        ):
            from prowler.providers.aws.services.redshift.redshift_cluster_automatic_upgrades.redshift_cluster_automatic_upgrades import (
                redshift_cluster_automatic_upgrades,
            )

            check = redshift_cluster_automatic_upgrades()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search("has AllowVersionUpgrade disabled", result[0].status_extended)
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == ""

    def test_cluster_automatic_upgrades(self):
        redshift_client = mock.MagicMock
        redshift_client.clusters = []
        redshift_client.clusters.append(
            Cluster(id=cluster_id, region=AWS_REGION, allow_version_upgrade=True)
        )
        with mock.patch(
            "prowler.providers.aws.services.redshift.redshift_service.Redshift",
            redshift_client,
        ):
            from prowler.providers.aws.services.redshift.redshift_cluster_automatic_upgrades.redshift_cluster_automatic_upgrades import (
                redshift_cluster_automatic_upgrades,
            )

            check = redshift_cluster_automatic_upgrades()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search("has AllowVersionUpgrade enabled", result[0].status_extended)
            assert result[0].resource_id == cluster_id
            assert result[0].resource_arn == ""
