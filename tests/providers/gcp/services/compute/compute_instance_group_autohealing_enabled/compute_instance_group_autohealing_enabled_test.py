from re import search
from unittest import mock

from prowler.providers.gcp.models import GCPProject
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_instance_group_autohealing_enabled:

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
                "prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled import (
                compute_instance_group_autohealing_enabled,
            )

            check = compute_instance_group_autohealing_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_mig_with_autohealing_pass(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            AutoHealingPolicy,
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="mig-with-autohealing",
            id="123456789",
            region="us-central1",
            zone="us-central1-a",
            zones=["us-central1-a"],
            is_regional=False,
            target_size=3,
            project_id=GCP_PROJECT_ID,
            auto_healing_policies=[
                AutoHealingPolicy(
                    health_check="http-health-check",
                    initial_delay_sec=300,
                )
            ],
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
                "prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled import (
                compute_instance_group_autohealing_enabled,
            )

            check = compute_instance_group_autohealing_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Managed Instance Group {mig.name} has autohealing enabled with health check",
                result[0].status_extended,
            )
            assert "http-health-check" in result[0].status_extended
            assert result[0].resource_id == mig.id
            assert result[0].resource_name == mig.name
            assert result[0].location == mig.region
            assert result[0].project_id == GCP_PROJECT_ID

    def test_mig_without_autohealing_fail(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="mig-no-autohealing",
            id="987654321",
            region="us-central1",
            zone="us-central1-a",
            zones=["us-central1-a"],
            is_regional=False,
            target_size=2,
            project_id=GCP_PROJECT_ID,
            auto_healing_policies=[],
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
                "prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled import (
                compute_instance_group_autohealing_enabled,
            )

            check = compute_instance_group_autohealing_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Managed Instance Group {mig.name} does not have autohealing enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == mig.id
            assert result[0].resource_name == mig.name
            assert result[0].location == mig.region
            assert result[0].project_id == GCP_PROJECT_ID

    def test_mig_with_autohealing_but_missing_health_check_fail(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            AutoHealingPolicy,
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="mig-missing-health-check",
            id="111222333",
            region="europe-west1",
            zone=None,
            zones=["europe-west1-b", "europe-west1-c"],
            is_regional=True,
            target_size=2,
            project_id=GCP_PROJECT_ID,
            auto_healing_policies=[
                AutoHealingPolicy(
                    health_check=None,
                    initial_delay_sec=300,
                )
            ],
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
                "prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled import (
                compute_instance_group_autohealing_enabled,
            )

            check = compute_instance_group_autohealing_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Managed Instance Group {mig.name} has autohealing configured but is missing a valid health check",
                result[0].status_extended,
            )
            assert result[0].resource_id == mig.id
            assert result[0].resource_name == mig.name
            assert result[0].location == mig.region
            assert result[0].project_id == GCP_PROJECT_ID

    def test_regional_mig_with_autohealing_pass(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            AutoHealingPolicy,
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="regional-mig-autohealing",
            id="444555666",
            region="us-east1",
            zone=None,
            zones=["us-east1-b", "us-east1-c", "us-east1-d"],
            is_regional=True,
            target_size=6,
            project_id=GCP_PROJECT_ID,
            auto_healing_policies=[
                AutoHealingPolicy(
                    health_check="tcp-health-check",
                    initial_delay_sec=120,
                )
            ],
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
        compute_client.region = "us-east1"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled import (
                compute_instance_group_autohealing_enabled,
            )

            check = compute_instance_group_autohealing_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Managed Instance Group {mig.name} has autohealing enabled",
                result[0].status_extended,
            )
            assert "tcp-health-check" in result[0].status_extended
            assert result[0].resource_id == mig.id
            assert result[0].resource_name == mig.name
            assert result[0].location == mig.region
            assert result[0].project_id == GCP_PROJECT_ID

    def test_multiple_migs_mixed_results(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            AutoHealingPolicy,
            ManagedInstanceGroup,
        )

        mig_pass = ManagedInstanceGroup(
            name="mig-good",
            id="111",
            region="us-central1",
            zone="us-central1-a",
            zones=["us-central1-a"],
            is_regional=False,
            target_size=2,
            project_id=GCP_PROJECT_ID,
            auto_healing_policies=[
                AutoHealingPolicy(
                    health_check="http-health-check",
                    initial_delay_sec=300,
                )
            ],
        )

        mig_fail_no_autohealing = ManagedInstanceGroup(
            name="mig-no-autohealing",
            id="222",
            region="us-central1",
            zone="us-central1-b",
            zones=["us-central1-b"],
            is_regional=False,
            target_size=1,
            project_id=GCP_PROJECT_ID,
            auto_healing_policies=[],
        )

        mig_fail_no_health_check = ManagedInstanceGroup(
            name="mig-no-health-check",
            id="333",
            region="us-central1",
            zone=None,
            zones=["us-central1-a", "us-central1-b"],
            is_regional=True,
            target_size=3,
            project_id=GCP_PROJECT_ID,
            auto_healing_policies=[
                AutoHealingPolicy(
                    health_check=None,
                    initial_delay_sec=120,
                )
            ],
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instance_groups = [
            mig_pass,
            mig_fail_no_autohealing,
            mig_fail_no_health_check,
        ]
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
                "prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled import (
                compute_instance_group_autohealing_enabled,
            )

            check = compute_instance_group_autohealing_enabled()
            result = check.execute()

            assert len(result) == 3
            assert result[0].status == "PASS"
            assert result[0].resource_id == mig_pass.id
            assert result[1].status == "FAIL"
            assert result[1].resource_id == mig_fail_no_autohealing.id
            assert "does not have autohealing enabled" in result[1].status_extended
            assert result[2].status == "FAIL"
            assert result[2].resource_id == mig_fail_no_health_check.id
            assert "missing a valid health check" in result[2].status_extended

    def test_mig_with_multiple_health_checks_pass(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            AutoHealingPolicy,
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="mig-multiple-policies",
            id="777888999",
            region="asia-east1",
            zone=None,
            zones=["asia-east1-a", "asia-east1-b"],
            is_regional=True,
            target_size=4,
            project_id=GCP_PROJECT_ID,
            auto_healing_policies=[
                AutoHealingPolicy(
                    health_check="http-health-check-1",
                    initial_delay_sec=300,
                ),
                AutoHealingPolicy(
                    health_check="tcp-health-check-2",
                    initial_delay_sec=120,
                ),
            ],
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
        compute_client.region = "asia-east1"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled import (
                compute_instance_group_autohealing_enabled,
            )

            check = compute_instance_group_autohealing_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "http-health-check-1" in result[0].status_extended
            assert "tcp-health-check-2" in result[0].status_extended
            assert result[0].resource_id == mig.id
            assert result[0].resource_name == mig.name
            assert result[0].location == mig.region
            assert result[0].project_id == GCP_PROJECT_ID

    def test_mig_with_empty_health_check_string_fail(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            AutoHealingPolicy,
            ManagedInstanceGroup,
        )

        mig = ManagedInstanceGroup(
            name="mig-empty-health-check",
            id="999000111",
            region="europe-north1",
            zone="europe-north1-a",
            zones=["europe-north1-a"],
            is_regional=False,
            target_size=1,
            project_id=GCP_PROJECT_ID,
            auto_healing_policies=[
                AutoHealingPolicy(
                    health_check="",
                    initial_delay_sec=300,
                )
            ],
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
        compute_client.region = "europe-north1"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_group_autohealing_enabled.compute_instance_group_autohealing_enabled import (
                compute_instance_group_autohealing_enabled,
            )

            check = compute_instance_group_autohealing_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Managed Instance Group {mig.name} has autohealing configured but is missing a valid health check",
                result[0].status_extended,
            )
