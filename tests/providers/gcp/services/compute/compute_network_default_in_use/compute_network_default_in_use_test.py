from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_network_default_in_use:
    def test_compute_no_projects(self):
        compute_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_network_default_in_use.compute_network_default_in_use.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_network_default_in_use.compute_network_default_in_use import (
                compute_network_default_in_use,
            )

            compute_client.project_ids = []
            compute_client.networks = []

            check = compute_network_default_in_use()
            result = check.execute()
            assert len(result) == 0

    def test_compute_no_networks(self):
        compute_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_network_default_in_use.compute_network_default_in_use.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_network_default_in_use.compute_network_default_in_use import (
                compute_network_default_in_use,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.networks = []

            check = compute_network_default_in_use()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Default network does not exist in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == "default"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "default"
            assert result[0].location == "global"

    def test_compute_one_project_default_network(self):
        compute_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_network_default_in_use.compute_network_default_in_use.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_network_default_in_use.compute_network_default_in_use import (
                compute_network_default_in_use,
            )
            from prowler.providers.gcp.services.compute.compute_service import Network

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.networks = [
                Network(
                    name="default",
                    id="default",
                    subnet_mode="custom",
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = compute_network_default_in_use()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Default network is in use in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == "default"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "default"
            assert result[0].location == "global"

    def test_compute_one_project_no_default_network(self):
        compute_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_network_default_in_use.compute_network_default_in_use.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_network_default_in_use.compute_network_default_in_use import (
                compute_network_default_in_use,
            )
            from prowler.providers.gcp.services.compute.compute_service import Network

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.networks = [
                Network(
                    name="not-default",
                    id="not-default",
                    subnet_mode="custom",
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = compute_network_default_in_use()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Default network does not exist in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == "default"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "default"
            assert result[0].location == "global"
