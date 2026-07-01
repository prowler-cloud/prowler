from re import search
from unittest import mock

from prowler.providers.gcp.models import GCPProject
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_instance_group_multiple_zones:
    """Tests for the compute_instance_group_multiple_zones check."""

    def test_no_instance_groups(self):
        """Test when there are no managed instance groups."""
        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = []
        compute_client.audit_config = {"mig_min_zones": 2}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones import (
                compute_instance_group_multiple_zones,
            )

            check = compute_instance_group_multiple_zones()
            result = check.execute()
            assert len(result) == 0

    def test_regional_mig_multiple_zones_pass(self):
        """Test a regional MIG spanning multiple zones - should PASS."""
        from prowler.providers.gcp.services.compute.compute_service import (
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="regional-mig-1",
            id="123456789",
            region="us-central1",
            zone=None,
            zones=["us-central1-a", "us-central1-b", "us-central1-c"],
            is_regional=True,
            target_size=3,
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = [mig]
        compute_client.audit_config = {"mig_min_zones": 2}
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
                "prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones import (
                compute_instance_group_multiple_zones,
            )

            check = compute_instance_group_multiple_zones()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Managed Instance Group {mig.name} is a regional MIG spanning 3 zones",
                result[0].status_extended,
            )
            assert result[0].resource_id == mig.id
            assert result[0].resource_name == mig.name
            assert result[0].location == mig.region
            assert result[0].project_id == GCP_PROJECT_ID

    def test_zonal_mig_single_zone_fail(self):
        """Test a zonal MIG in a single zone - should FAIL."""
        from prowler.providers.gcp.services.compute.compute_service import (
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="zonal-mig-1",
            id="987654321",
            region="us-central1",
            zone="us-central1-a",
            zones=["us-central1-a"],
            is_regional=False,
            target_size=2,
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = [mig]
        compute_client.audit_config = {"mig_min_zones": 2}
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
                "prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones import (
                compute_instance_group_multiple_zones,
            )

            check = compute_instance_group_multiple_zones()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Managed Instance Group {mig.name} is a zonal MIG running only in",
                result[0].status_extended,
            )
            assert result[0].resource_id == mig.id
            assert result[0].resource_name == mig.name
            assert result[0].location == mig.region
            assert result[0].project_id == GCP_PROJECT_ID

    def test_regional_mig_single_zone_fail(self):
        """Test a regional MIG with only one zone configured - should FAIL."""
        from prowler.providers.gcp.services.compute.compute_service import (
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="regional-mig-single-zone",
            id="111222333",
            region="europe-west1",
            zone=None,
            zones=["europe-west1-b"],
            is_regional=True,
            target_size=1,
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = [mig]
        compute_client.audit_config = {"mig_min_zones": 2}
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
                "prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones import (
                compute_instance_group_multiple_zones,
            )

            check = compute_instance_group_multiple_zones()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Managed Instance Group {mig.name} is a regional MIG but only spans 1 zone",
                result[0].status_extended,
            )
            assert result[0].resource_id == mig.id
            assert result[0].resource_name == mig.name
            assert result[0].location == mig.region
            assert result[0].project_id == GCP_PROJECT_ID

    def test_multiple_migs_mixed_results(self):
        """Test multiple MIGs with mixed compliance results."""
        from prowler.providers.gcp.services.compute.compute_service import (
            ManagedInstanceGroup,
        )

        mig_regional_pass = ManagedInstanceGroup(
            name="regional-mig-good",
            id="111",
            region="us-central1",
            zone=None,
            zones=["us-central1-a", "us-central1-b"],
            is_regional=True,
            target_size=2,
            project_id=GCP_PROJECT_ID,
        )

        mig_zonal_fail = ManagedInstanceGroup(
            name="zonal-mig-bad",
            id="222",
            region="us-central1",
            zone="us-central1-a",
            zones=["us-central1-a"],
            is_regional=False,
            target_size=1,
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = [mig_regional_pass, mig_zonal_fail]
        compute_client.audit_config = {"mig_min_zones": 2}
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
                "prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones import (
                compute_instance_group_multiple_zones,
            )

            check = compute_instance_group_multiple_zones()
            result = check.execute()

            assert len(result) == 2
            # First MIG (regional with 2 zones) should pass
            assert result[0].status == "PASS"
            assert result[0].resource_id == mig_regional_pass.id
            # Second MIG (zonal with 1 zone) should fail
            assert result[1].status == "FAIL"
            assert result[1].resource_id == mig_zonal_fail.id

    def test_custom_min_zones_config(self):
        """Test that the configurable min zones parameter is respected."""
        from prowler.providers.gcp.services.compute.compute_service import (
            ManagedInstanceGroup,
        )

        # MIG with 2 zones - should fail if min_zones is 3
        mig = ManagedInstanceGroup(
            name="regional-mig-2zones",
            id="333",
            region="us-central1",
            zone=None,
            zones=["us-central1-a", "us-central1-b"],
            is_regional=True,
            target_size=2,
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = [mig]
        compute_client.audit_config = {"mig_min_zones": 3}  # Require 3 zones
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
                "prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones import (
                compute_instance_group_multiple_zones,
            )

            check = compute_instance_group_multiple_zones()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("minimum required is 3", result[0].status_extended)

    def test_default_min_zones_when_not_configured(self):
        """Test that default min_zones (2) is used when not configured."""
        from prowler.providers.gcp.services.compute.compute_service import (
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="regional-mig-default",
            id="444",
            region="us-central1",
            zone=None,
            zones=["us-central1-a", "us-central1-b"],
            is_regional=True,
            target_size=2,
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = [mig]
        compute_client.audit_config = {}  # No mig_min_zones configured
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
                "prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_multiple_zones.compute_instance_group_multiple_zones import (
                compute_instance_group_multiple_zones,
            )

            check = compute_instance_group_multiple_zones()
            result = check.execute()

            assert len(result) == 1
            # 2 zones >= default 2, so should PASS
            assert result[0].status == "PASS"
