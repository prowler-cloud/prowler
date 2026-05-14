from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class TestComputeInstanceOnHostMaintenanceMigrate:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock()
        compute_client.instances = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate import (
                compute_instance_on_host_maintenance_migrate,
            )

            check = compute_instance_on_host_maintenance_migrate()
            result = check.execute()
            assert len(result) == 0

    def test_instance_with_on_host_maintenance_migrate(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate import (
                compute_instance_on_host_maintenance_migrate,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="test-instance",
                    id="1234567890",
                    zone="us-central1-a",
                    region="us-central1",
                    public_ip=True,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[("disk1", False)],
                    automatic_restart=True,
                    project_id=GCP_PROJECT_ID,
                    on_host_maintenance="MIGRATE",
                )
            ]

            check = compute_instance_on_host_maintenance_migrate()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "VM Instance test-instance has On Host Maintenance set to MIGRATE."
            )
            assert result[0].resource_id == compute_client.instances[0].id
            assert result[0].resource_name == compute_client.instances[0].name
            assert result[0].location == "us-central1"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_with_on_host_maintenance_terminate(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate import (
                compute_instance_on_host_maintenance_migrate,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="test-instance-terminate",
                    id="0987654321",
                    zone="us-west1-b",
                    region="us-west1",
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=False,
                    shielded_enabled_integrity_monitoring=False,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    automatic_restart=False,
                    project_id=GCP_PROJECT_ID,
                    on_host_maintenance="TERMINATE",
                )
            ]

            check = compute_instance_on_host_maintenance_migrate()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "VM Instance test-instance-terminate has On Host Maintenance set to TERMINATE instead of MIGRATE."
            )
            assert result[0].resource_id == compute_client.instances[0].id
            assert result[0].resource_name == compute_client.instances[0].name
            assert result[0].location == "us-west1"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_multiple_instances_mixed(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate import (
                compute_instance_on_host_maintenance_migrate,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="compliant-instance",
                    id="1111111111",
                    zone="us-central1-a",
                    region="us-central1",
                    public_ip=True,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    automatic_restart=True,
                    project_id=GCP_PROJECT_ID,
                    on_host_maintenance="MIGRATE",
                ),
                Instance(
                    name="non-compliant-instance",
                    id="2222222222",
                    zone="us-west1-b",
                    region="us-west1",
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=False,
                    shielded_enabled_integrity_monitoring=False,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    automatic_restart=False,
                    project_id=GCP_PROJECT_ID,
                    on_host_maintenance="TERMINATE",
                ),
            ]

            check = compute_instance_on_host_maintenance_migrate()
            result = check.execute()

            assert len(result) == 2

            compliant_result = next(r for r in result if r.resource_id == "1111111111")
            non_compliant_result = next(
                r for r in result if r.resource_id == "2222222222"
            )

            assert compliant_result.status == "PASS"
            assert (
                compliant_result.status_extended
                == "VM Instance compliant-instance has On Host Maintenance set to MIGRATE."
            )
            assert compliant_result.resource_id == "1111111111"
            assert compliant_result.resource_name == "compliant-instance"
            assert compliant_result.location == "us-central1"
            assert compliant_result.project_id == GCP_PROJECT_ID

            assert non_compliant_result.status == "FAIL"
            assert (
                non_compliant_result.status_extended
                == "VM Instance non-compliant-instance has On Host Maintenance set to TERMINATE instead of MIGRATE."
            )
            assert non_compliant_result.resource_id == "2222222222"
            assert non_compliant_result.resource_name == "non-compliant-instance"
            assert non_compliant_result.location == "us-west1"
            assert non_compliant_result.project_id == GCP_PROJECT_ID

    def test_instance_with_default_on_host_maintenance(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate import (
                compute_instance_on_host_maintenance_migrate,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="default-instance",
                    id="3333333333",
                    zone="us-east1-b",
                    region="us-east1",
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    automatic_restart=True,
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = compute_instance_on_host_maintenance_migrate()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "VM Instance default-instance has On Host Maintenance set to MIGRATE."
            )
            assert result[0].resource_id == "3333333333"
            assert result[0].resource_name == "default-instance"
            assert result[0].location == "us-east1"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_preemptible_instance_fails_with_explanation(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate import (
                compute_instance_on_host_maintenance_migrate,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="preemptible-instance",
                    id="4444444444",
                    zone="us-central1-a",
                    region="us-central1",
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=False,
                    shielded_enabled_integrity_monitoring=False,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    automatic_restart=False,
                    project_id=GCP_PROJECT_ID,
                    preemptible=True,
                    provisioning_model="STANDARD",
                    on_host_maintenance="TERMINATE",
                )
            ]

            check = compute_instance_on_host_maintenance_migrate()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "VM Instance preemptible-instance is a preemptible VM and has On Host Maintenance set to TERMINATE. Preemptible VMs cannot use MIGRATE and must always use TERMINATE. If high availability is required, consider using a non-preemptible VM instead."
            )
            assert result[0].resource_id == "4444444444"
            assert result[0].resource_name == "preemptible-instance"

    def test_spot_instance_fails_with_explanation(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate import (
                compute_instance_on_host_maintenance_migrate,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="spot-instance",
                    id="5555555555",
                    zone="us-west1-a",
                    region="us-west1",
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=False,
                    shielded_enabled_integrity_monitoring=False,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    automatic_restart=False,
                    project_id=GCP_PROJECT_ID,
                    preemptible=False,
                    provisioning_model="SPOT",
                    on_host_maintenance="TERMINATE",
                )
            ]

            check = compute_instance_on_host_maintenance_migrate()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "VM Instance spot-instance is a Spot VM and has On Host Maintenance set to TERMINATE. Spot VMs cannot use MIGRATE and must always use TERMINATE. If high availability is required, consider using a non-preemptible VM instead."
            )
            assert result[0].resource_id == "5555555555"
            assert result[0].resource_name == "spot-instance"

    def test_mixed_with_preemptible_and_spot(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_on_host_maintenance_migrate.compute_instance_on_host_maintenance_migrate import (
                compute_instance_on_host_maintenance_migrate,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="regular-instance-pass",
                    id="6666666666",
                    zone="us-central1-a",
                    region="us-central1",
                    public_ip=True,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    automatic_restart=True,
                    project_id=GCP_PROJECT_ID,
                    preemptible=False,
                    provisioning_model="STANDARD",
                    on_host_maintenance="MIGRATE",
                ),
                Instance(
                    name="preemptible-instance",
                    id="7777777777",
                    zone="us-west1-a",
                    region="us-west1",
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=False,
                    shielded_enabled_integrity_monitoring=False,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    automatic_restart=False,
                    project_id=GCP_PROJECT_ID,
                    preemptible=True,
                    provisioning_model="STANDARD",
                    on_host_maintenance="TERMINATE",
                ),
                Instance(
                    name="spot-instance",
                    id="8888888888",
                    zone="us-east1-b",
                    region="us-east1",
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=False,
                    shielded_enabled_integrity_monitoring=False,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    automatic_restart=False,
                    project_id=GCP_PROJECT_ID,
                    preemptible=False,
                    provisioning_model="SPOT",
                    on_host_maintenance="TERMINATE",
                ),
                Instance(
                    name="regular-instance-fail",
                    id="9999999999",
                    zone="us-central1-b",
                    region="us-central1",
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=False,
                    shielded_enabled_integrity_monitoring=False,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    automatic_restart=False,
                    project_id=GCP_PROJECT_ID,
                    preemptible=False,
                    provisioning_model="STANDARD",
                    on_host_maintenance="TERMINATE",
                ),
            ]

            check = compute_instance_on_host_maintenance_migrate()
            result = check.execute()

            assert len(result) == 4

            pass_result = next(r for r in result if r.resource_id == "6666666666")
            preemptible_result = next(
                r for r in result if r.resource_id == "7777777777"
            )
            spot_result = next(r for r in result if r.resource_id == "8888888888")
            fail_result = next(r for r in result if r.resource_id == "9999999999")

            assert pass_result.status == "PASS"
            assert (
                pass_result.status_extended
                == "VM Instance regular-instance-pass has On Host Maintenance set to MIGRATE."
            )
            assert pass_result.resource_name == "regular-instance-pass"

            assert preemptible_result.status == "FAIL"
            assert (
                preemptible_result.status_extended
                == "VM Instance preemptible-instance is a preemptible VM and has On Host Maintenance set to TERMINATE. Preemptible VMs cannot use MIGRATE and must always use TERMINATE. If high availability is required, consider using a non-preemptible VM instead."
            )
            assert preemptible_result.resource_name == "preemptible-instance"

            assert spot_result.status == "FAIL"
            assert (
                spot_result.status_extended
                == "VM Instance spot-instance is a Spot VM and has On Host Maintenance set to TERMINATE. Spot VMs cannot use MIGRATE and must always use TERMINATE. If high availability is required, consider using a non-preemptible VM instead."
            )
            assert spot_result.resource_name == "spot-instance"

            assert fail_result.status == "FAIL"
            assert (
                fail_result.status_extended
                == "VM Instance regular-instance-fail has On Host Maintenance set to TERMINATE instead of MIGRATE."
            )
            assert fail_result.resource_name == "regular-instance-fail"
