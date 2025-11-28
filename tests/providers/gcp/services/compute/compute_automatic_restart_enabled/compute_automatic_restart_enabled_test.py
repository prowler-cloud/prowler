from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class TestComputeInstanceAutomaticRestartEnabled:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock()
        compute_client.instances = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_automatic_restart_enabled.compute_instance_automatic_restart_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_automatic_restart_enabled.compute_instance_automatic_restart_enabled import (
                compute_instance_automatic_restart_enabled,
            )

            check = compute_instance_automatic_restart_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_instance_with_automatic_restart_enabled(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_automatic_restart_enabled.compute_instance_automatic_restart_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_automatic_restart_enabled.compute_instance_automatic_restart_enabled import (
                compute_instance_automatic_restart_enabled,
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
                )
            ]

            check = compute_instance_automatic_restart_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"VM Instance {compute_client.instances[0].name} has Automatic Restart enabled."
            )
            assert result[0].resource_id == compute_client.instances[0].id
            assert result[0].resource_name == compute_client.instances[0].name
            assert result[0].location == "us-central1"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_without_automatic_restart(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_automatic_restart_enabled.compute_instance_automatic_restart_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_automatic_restart_enabled.compute_instance_automatic_restart_enabled import (
                compute_instance_automatic_restart_enabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="test-instance-disabled",
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
                )
            ]

            check = compute_instance_automatic_restart_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"VM Instance {compute_client.instances[0].name} does not have Automatic Restart enabled."
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
                "prowler.providers.gcp.services.compute.compute_instance_automatic_restart_enabled.compute_instance_automatic_restart_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_automatic_restart_enabled.compute_instance_automatic_restart_enabled import (
                compute_instance_automatic_restart_enabled,
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
                ),
            ]

            check = compute_instance_automatic_restart_enabled()
            result = check.execute()

            assert len(result) == 2

            compliant_result = next(r for r in result if r.resource_id == "1111111111")
            non_compliant_result = next(
                r for r in result if r.resource_id == "2222222222"
            )

            assert compliant_result.status == "PASS"
            assert (
                compliant_result.status_extended
                == "VM Instance compliant-instance has Automatic Restart enabled."
            )
            assert compliant_result.resource_id == "1111111111"
            assert compliant_result.resource_name == "compliant-instance"
            assert compliant_result.location == "us-central1"
            assert compliant_result.project_id == GCP_PROJECT_ID

            assert non_compliant_result.status == "FAIL"
            assert (
                non_compliant_result.status_extended
                == "VM Instance non-compliant-instance does not have Automatic Restart enabled."
            )
            assert non_compliant_result.resource_id == "2222222222"
            assert non_compliant_result.resource_name == "non-compliant-instance"
            assert non_compliant_result.location == "us-west1"
            assert non_compliant_result.project_id == GCP_PROJECT_ID

    def test_preemptible_instance_fails(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_automatic_restart_enabled.compute_instance_automatic_restart_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_automatic_restart_enabled.compute_instance_automatic_restart_enabled import (
                compute_instance_automatic_restart_enabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="preemptible-instance",
                    id="3333333333",
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
                    preemptible=True,
                    provisioning_model="STANDARD",
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = compute_instance_automatic_restart_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"VM Instance {compute_client.instances[0].name} is a Preemptible or Spot instance, which cannot have Automatic Restart enabled by design."
            )
            assert result[0].resource_id == compute_client.instances[0].id
            assert result[0].resource_name == compute_client.instances[0].name
            assert result[0].location == "us-central1"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_spot_instance_fails(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_automatic_restart_enabled.compute_instance_automatic_restart_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_automatic_restart_enabled.compute_instance_automatic_restart_enabled import (
                compute_instance_automatic_restart_enabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="spot-instance",
                    id="4444444444",
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
                    preemptible=False,
                    provisioning_model="SPOT",
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = compute_instance_automatic_restart_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"VM Instance {compute_client.instances[0].name} is a Preemptible or Spot instance, which cannot have Automatic Restart enabled by design."
            )
            assert result[0].resource_id == compute_client.instances[0].id
            assert result[0].resource_name == compute_client.instances[0].name
            assert result[0].location == "us-west1"
            assert result[0].project_id == GCP_PROJECT_ID
