from re import search
from unittest import mock

from prowler.providers.gcp.models import GCPProject
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_instance_group_load_balancer_attached:

    def test_no_instance_groups(self):
        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_group_load_balancer_attached.compute_instance_group_load_balancer_attached.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_load_balancer_attached.compute_instance_group_load_balancer_attached import (
                compute_instance_group_load_balancer_attached,
            )

            check = compute_instance_group_load_balancer_attached()
            result = check.execute()
            assert len(result) == 0

    def test_mig_attached_to_load_balancer_pass(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="mig-with-lb",
            id="123456789",
            region="us-central1",
            zone=None,
            zones=["us-central1-a", "us-central1-b"],
            is_regional=True,
            target_size=2,
            project_id=GCP_PROJECT_ID,
            load_balanced=True,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = [mig]
        compute_client.projects = {
            GCP_PROJECT_ID: GCPProject(
                id=GCP_PROJECT_ID,
                number="123456789012",
                name="test-project",
                labels={},
                lifecycle_state="ACTIVE",
            )
        }
        compute_client.region = "us-central1"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_group_load_balancer_attached.compute_instance_group_load_balancer_attached.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_load_balancer_attached.compute_instance_group_load_balancer_attached import (
                compute_instance_group_load_balancer_attached,
            )

            check = compute_instance_group_load_balancer_attached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Managed Instance Group {mig.name} is attached to a load balancer",
                result[0].status_extended,
            )
            assert result[0].resource_id == mig.id
            assert result[0].resource_name == mig.name
            assert result[0].location == mig.region
            assert result[0].project_id == GCP_PROJECT_ID

    def test_mig_not_attached_to_load_balancer_fail(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="mig-without-lb",
            id="987654321",
            region="us-central1",
            zone="us-central1-a",
            zones=["us-central1-a"],
            is_regional=False,
            target_size=1,
            project_id=GCP_PROJECT_ID,
            load_balanced=False,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = [mig]
        compute_client.projects = {
            GCP_PROJECT_ID: GCPProject(
                id=GCP_PROJECT_ID,
                number="123456789012",
                name="test-project",
                labels={},
                lifecycle_state="ACTIVE",
            )
        }
        compute_client.region = "us-central1"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_group_load_balancer_attached.compute_instance_group_load_balancer_attached.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_load_balancer_attached.compute_instance_group_load_balancer_attached import (
                compute_instance_group_load_balancer_attached,
            )

            check = compute_instance_group_load_balancer_attached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Managed Instance Group {mig.name} is not attached to any load balancer",
                result[0].status_extended,
            )
            assert result[0].resource_id == mig.id
            assert result[0].resource_name == mig.name
            assert result[0].location == mig.region
            assert result[0].project_id == GCP_PROJECT_ID

    def test_multiple_migs_mixed_results(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            ManagedInstanceGroup,
        )

        mig_with_lb = ManagedInstanceGroup(
            name="mig-with-lb",
            id="111",
            region="us-central1",
            zone=None,
            zones=["us-central1-a", "us-central1-b"],
            is_regional=True,
            target_size=2,
            project_id=GCP_PROJECT_ID,
            load_balanced=True,
        )

        mig_without_lb = ManagedInstanceGroup(
            name="mig-without-lb",
            id="222",
            region="us-central1",
            zone="us-central1-a",
            zones=["us-central1-a"],
            is_regional=False,
            target_size=1,
            project_id=GCP_PROJECT_ID,
            load_balanced=False,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = [mig_with_lb, mig_without_lb]
        compute_client.projects = {
            GCP_PROJECT_ID: GCPProject(
                id=GCP_PROJECT_ID,
                number="123456789012",
                name="test-project",
                labels={},
                lifecycle_state="ACTIVE",
            )
        }
        compute_client.region = "us-central1"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_group_load_balancer_attached.compute_instance_group_load_balancer_attached.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_load_balancer_attached.compute_instance_group_load_balancer_attached import (
                compute_instance_group_load_balancer_attached,
            )

            check = compute_instance_group_load_balancer_attached()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[0].resource_id == mig_with_lb.id
            assert result[1].status == "FAIL"
            assert result[1].resource_id == mig_without_lb.id

    def test_zonal_mig_attached_to_load_balancer_pass(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="zonal-mig-with-lb",
            id="333",
            region="europe-west1",
            zone="europe-west1-b",
            zones=["europe-west1-b"],
            is_regional=False,
            target_size=3,
            project_id=GCP_PROJECT_ID,
            load_balanced=True,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = [mig]
        compute_client.projects = {
            GCP_PROJECT_ID: GCPProject(
                id=GCP_PROJECT_ID,
                number="123456789012",
                name="test-project",
                labels={},
                lifecycle_state="ACTIVE",
            )
        }
        compute_client.region = "europe-west1"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_group_load_balancer_attached.compute_instance_group_load_balancer_attached.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_load_balancer_attached.compute_instance_group_load_balancer_attached import (
                compute_instance_group_load_balancer_attached,
            )

            check = compute_instance_group_load_balancer_attached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "is attached to a load balancer",
                result[0].status_extended,
            )
            assert result[0].resource_id == mig.id
            assert result[0].resource_name == mig.name
            assert result[0].location == mig.region
            assert result[0].project_id == GCP_PROJECT_ID
