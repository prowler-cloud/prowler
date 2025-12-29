from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_configuration_changes:
    def test_no_audit_entries(self):
        from prowler.providers.gcp.models import GCPProject

        logging_client = mock.MagicMock()
        logging_client.project_ids = [GCP_PROJECT_ID]
        logging_client.projects = {
            GCP_PROJECT_ID: GCPProject(
                id=GCP_PROJECT_ID,
                number="123456789012",
                name="test-project",
                labels={},
                lifecycle_state="ACTIVE",
            )
        }
        logging_client.region = "global"
        logging_client.compute_audit_entries = {GCP_PROJECT_ID: []}
        logging_client.audit_config = {"compute_audit_log_lookback_days": 1}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_configuration_changes.compute_configuration_changes.logging_client",
                new=logging_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_configuration_changes.compute_configuration_changes import (
                compute_configuration_changes,
            )

            check = compute_configuration_changes()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                f"No Compute Engine configuration changes detected in project {GCP_PROJECT_ID}"
                in result[0].status_extended
            )
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_id == GCP_PROJECT_ID
            assert result[0].location == "global"

    def test_single_audit_entry(self):
        from prowler.providers.gcp.models import GCPProject
        from prowler.providers.gcp.services.logging.logging_service import AuditLogEntry

        audit_entry = AuditLogEntry(
            insert_id="test-insert-id-1",
            timestamp="2024-01-15T10:30:00Z",
            receive_timestamp="2024-01-15T10:30:01Z",
            resource_type="gce_instance",
            resource_name="test-instance",
            method_name="v1.compute.instances.insert",
            service_name="compute.googleapis.com",
            principal_email="user@example.com",
            caller_ip="192.168.1.1",
            project_id=GCP_PROJECT_ID,
        )

        logging_client = mock.MagicMock()
        logging_client.project_ids = [GCP_PROJECT_ID]
        logging_client.projects = {
            GCP_PROJECT_ID: GCPProject(
                id=GCP_PROJECT_ID,
                number="123456789012",
                name="test-project",
                labels={},
                lifecycle_state="ACTIVE",
            )
        }
        logging_client.region = "global"
        logging_client.compute_audit_entries = {GCP_PROJECT_ID: [audit_entry]}
        logging_client.audit_config = {"compute_audit_log_lookback_days": 1}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_configuration_changes.compute_configuration_changes.logging_client",
                new=logging_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_configuration_changes.compute_configuration_changes import (
                compute_configuration_changes,
            )

            check = compute_configuration_changes()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "v1.compute.instances.insert" in result[0].status_extended
            assert "test-instance" in result[0].status_extended
            assert "user@example.com" in result[0].status_extended
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_id == "test-insert-id-1"
            assert result[0].resource_name == "test-instance"

    def test_multiple_audit_entries(self):
        from prowler.providers.gcp.models import GCPProject
        from prowler.providers.gcp.services.logging.logging_service import AuditLogEntry

        audit_entries = [
            AuditLogEntry(
                insert_id="test-insert-id-1",
                timestamp="2024-01-15T10:30:00Z",
                resource_type="gce_instance",
                resource_name="test-instance-1",
                method_name="v1.compute.instances.insert",
                service_name="compute.googleapis.com",
                principal_email="admin@example.com",
                project_id=GCP_PROJECT_ID,
            ),
            AuditLogEntry(
                insert_id="test-insert-id-2",
                timestamp="2024-01-15T11:00:00Z",
                resource_type="gce_disk",
                resource_name="test-disk",
                method_name="v1.compute.disks.delete",
                service_name="compute.googleapis.com",
                principal_email="user@example.com",
                project_id=GCP_PROJECT_ID,
            ),
            AuditLogEntry(
                insert_id="test-insert-id-3",
                timestamp="2024-01-15T11:30:00Z",
                resource_type="gce_network",
                resource_name="test-network",
                method_name="v1.compute.networks.patch",
                service_name="compute.googleapis.com",
                principal_email="admin@example.com",
                project_id=GCP_PROJECT_ID,
            ),
        ]

        logging_client = mock.MagicMock()
        logging_client.project_ids = [GCP_PROJECT_ID]
        logging_client.projects = {
            GCP_PROJECT_ID: GCPProject(
                id=GCP_PROJECT_ID,
                number="123456789012",
                name="test-project",
                labels={},
                lifecycle_state="ACTIVE",
            )
        }
        logging_client.region = "global"
        logging_client.compute_audit_entries = {GCP_PROJECT_ID: audit_entries}
        logging_client.audit_config = {"compute_audit_log_lookback_days": 1}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_configuration_changes.compute_configuration_changes.logging_client",
                new=logging_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_configuration_changes.compute_configuration_changes import (
                compute_configuration_changes,
            )

            check = compute_configuration_changes()
            result = check.execute()

            assert len(result) == 3
            assert all(r.status == "FAIL" for r in result)
            assert result[0].resource_name == "test-instance-1"
            assert result[1].resource_name == "test-disk"
            assert result[2].resource_name == "test-network"

    def test_multiple_projects_mixed_results(self):
        from prowler.providers.gcp.models import GCPProject
        from prowler.providers.gcp.services.logging.logging_service import AuditLogEntry

        project_id_1 = "project-1"
        project_id_2 = "project-2"

        audit_entry = AuditLogEntry(
            insert_id="test-insert-id-1",
            timestamp="2024-01-15T10:30:00Z",
            resource_type="gce_instance",
            resource_name="test-instance",
            method_name="v1.compute.instances.delete",
            service_name="compute.googleapis.com",
            principal_email="user@example.com",
            project_id=project_id_1,
        )

        logging_client = mock.MagicMock()
        logging_client.project_ids = [project_id_1, project_id_2]
        logging_client.projects = {
            project_id_1: GCPProject(
                id=project_id_1,
                number="111111111111",
                name="test-project-1",
                labels={},
                lifecycle_state="ACTIVE",
            ),
            project_id_2: GCPProject(
                id=project_id_2,
                number="222222222222",
                name="test-project-2",
                labels={},
                lifecycle_state="ACTIVE",
            ),
        }
        logging_client.region = "global"
        logging_client.compute_audit_entries = {
            project_id_1: [audit_entry],
            project_id_2: [],
        }
        logging_client.audit_config = {"compute_audit_log_lookback_days": 1}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(
                    project_ids=[project_id_1, project_id_2]
                ),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_configuration_changes.compute_configuration_changes.logging_client",
                new=logging_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_configuration_changes.compute_configuration_changes import (
                compute_configuration_changes,
            )

            check = compute_configuration_changes()
            result = check.execute()

            assert len(result) == 2

            fail_result = [r for r in result if r.status == "FAIL"][0]
            pass_result = [r for r in result if r.status == "PASS"][0]

            assert fail_result.project_id == project_id_1
            assert "v1.compute.instances.delete" in fail_result.status_extended

            assert pass_result.project_id == project_id_2
            assert (
                "No Compute Engine configuration changes detected"
                in pass_result.status_extended
            )

    def test_no_projects(self):
        logging_client = mock.MagicMock()
        logging_client.project_ids = []
        logging_client.projects = {}
        logging_client.region = "global"
        logging_client.compute_audit_entries = {}
        logging_client.audit_config = {"compute_audit_log_lookback_days": 1}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(project_ids=[]),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_configuration_changes.compute_configuration_changes.logging_client",
                new=logging_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_configuration_changes.compute_configuration_changes import (
                compute_configuration_changes,
            )

            check = compute_configuration_changes()
            result = check.execute()

            assert len(result) == 0

    def test_audit_entry_without_principal_email(self):
        from prowler.providers.gcp.models import GCPProject
        from prowler.providers.gcp.services.logging.logging_service import AuditLogEntry

        audit_entry = AuditLogEntry(
            insert_id="test-insert-id-1",
            timestamp="2024-01-15T10:30:00Z",
            resource_type="gce_instance",
            resource_name="test-instance",
            method_name="v1.compute.instances.insert",
            service_name="compute.googleapis.com",
            principal_email=None,
            project_id=GCP_PROJECT_ID,
        )

        logging_client = mock.MagicMock()
        logging_client.project_ids = [GCP_PROJECT_ID]
        logging_client.projects = {
            GCP_PROJECT_ID: GCPProject(
                id=GCP_PROJECT_ID,
                number="123456789012",
                name="test-project",
                labels={},
                lifecycle_state="ACTIVE",
            )
        }
        logging_client.region = "global"
        logging_client.compute_audit_entries = {GCP_PROJECT_ID: [audit_entry]}
        logging_client.audit_config = {"compute_audit_log_lookback_days": 1}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_configuration_changes.compute_configuration_changes.logging_client",
                new=logging_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_configuration_changes.compute_configuration_changes import (
                compute_configuration_changes,
            )

            check = compute_configuration_changes()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "unknown actor" in result[0].status_extended
