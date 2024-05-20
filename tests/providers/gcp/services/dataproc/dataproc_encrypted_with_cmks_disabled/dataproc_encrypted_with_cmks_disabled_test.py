from re import search
from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_dataproc_encrypted_with_cmks_disabled:
    def test_dataproc_no_clsuters(self):
        dataproc_client = mock.MagicMock
        dataproc_client.clusters = []

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.dataproc.dataproc_encrypted_with_cmks_disabled.dataproc_encrypted_with_cmks_disabled.dataproc_client",
            new=dataproc_client,
        ):
            from prowler.providers.gcp.services.dataproc.dataproc_encrypted_with_cmks_disabled.dataproc_encrypted_with_cmks_disabled import (
                dataproc_encrypted_with_cmks_disabled,
            )

            check = dataproc_encrypted_with_cmks_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_cluster(self):
        dataproc_client = mock.MagicMock
        dataproc_client.project_ids = [GCP_PROJECT_ID]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.dataproc.dataproc_encrypted_with_cmks_disabled.dataproc_encrypted_with_cmks_disabled.dataproc_client",
            new=dataproc_client,
        ):
            from prowler.providers.gcp.services.dataproc.dataproc_service import Cluster

            cluster = Cluster(
                name="test",
                id="1234567890",
                encryption_config={"gcePdKmsKeyName": "test"},
                project_id=GCP_PROJECT_ID,
            )
            dataproc_client.clusters = [cluster]

            from prowler.providers.gcp.services.dataproc.dataproc_encrypted_with_cmks_disabled.dataproc_encrypted_with_cmks_disabled import (
                dataproc_encrypted_with_cmks_disabled,
            )

            check = dataproc_encrypted_with_cmks_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Dataproc cluster {cluster.name} is encrypted with customer managed encryption keys.",
                result[0].status_extended,
            )
            assert result[0].resource_id == cluster.id

    def test_cluster_without_encryption(self):
        dataproc_client = mock.MagicMock
        dataproc_client.project_ids = [GCP_PROJECT_ID]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.dataproc.dataproc_encrypted_with_cmks_disabled.dataproc_encrypted_with_cmks_disabled.dataproc_client",
            new=dataproc_client,
        ):

            from prowler.providers.gcp.services.dataproc.dataproc_service import Cluster

            cluster = Cluster(
                name="test",
                id="1234567890",
                encryption_config={},
                project_id=GCP_PROJECT_ID,
            )
            dataproc_client.clusters = [cluster]

            from prowler.providers.gcp.services.dataproc.dataproc_encrypted_with_cmks_disabled.dataproc_encrypted_with_cmks_disabled import (
                dataproc_encrypted_with_cmks_disabled,
            )

            check = dataproc_encrypted_with_cmks_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Dataproc cluster {cluster.name} is not encrypted with customer managed encryption keys.",
                result[0].status_extended,
            )
            assert result[0].resource_id == cluster.id
