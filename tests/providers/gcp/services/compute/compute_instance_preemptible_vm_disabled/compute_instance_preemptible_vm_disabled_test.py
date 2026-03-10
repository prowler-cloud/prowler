from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class TestComputeInstancePreemptibleVmDisabled:
    def test_no_instances(self):
        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled import (
                compute_instance_preemptible_vm_disabled,
            )

            check = compute_instance_preemptible_vm_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_instance_not_preemptible(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled import (
                compute_instance_preemptible_vm_disabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="test",
                    id="1234567890",
                    zone="us-central1-a",
                    region="us-central1",
                    public_ip=True,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=True,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[("disk1", False), ("disk2", False)],
                    project_id=GCP_PROJECT_ID,
                    preemptible=False,
                    provisioning_model="",
                )
            ]

            check = compute_instance_preemptible_vm_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"VM Instance {compute_client.instances[0].name} is not preemptible or Spot VM."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].resource_name == "test"
            assert result[0].location == "us-central1"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_preemptible(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled import (
                compute_instance_preemptible_vm_disabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="test",
                    id="1234567890",
                    zone="us-central1-a",
                    region="us-central1",
                    public_ip=True,
                    metadata={},
                    shielded_enabled_vtpm=False,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[("disk1", False), ("disk2", False)],
                    project_id=GCP_PROJECT_ID,
                    preemptible=True,
                    provisioning_model="",
                )
            ]

            check = compute_instance_preemptible_vm_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"VM Instance {compute_client.instances[0].name} is configured as preemptible."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].resource_name == "test"
            assert result[0].location == "us-central1"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_multiple_instances_mixed_preemptible_and_standard(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled import (
                compute_instance_preemptible_vm_disabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="preemptible-instance",
                    id="111111111",
                    zone="us-central1-a",
                    region="us-central1",
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    project_id=GCP_PROJECT_ID,
                    preemptible=True,
                    provisioning_model="",
                ),
                Instance(
                    name="standard-instance",
                    id="222222222",
                    zone="europe-west1-b",
                    region="europe-west1",
                    public_ip=True,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=True,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    project_id=GCP_PROJECT_ID,
                    preemptible=False,
                    provisioning_model="",
                ),
            ]

            check = compute_instance_preemptible_vm_disabled()
            result = check.execute()

            assert len(result) == 2

            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "VM Instance preemptible-instance is configured as preemptible."
            )
            assert result[0].resource_id == "111111111"
            assert result[0].resource_name == "preemptible-instance"

            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "VM Instance standard-instance is not preemptible or Spot VM."
            )
            assert result[1].resource_id == "222222222"
            assert result[1].resource_name == "standard-instance"

    def test_instance_spot_vm(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled import (
                compute_instance_preemptible_vm_disabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="spot-vm",
                    id="3333333333",
                    zone="us-west1-a",
                    region="us-west1",
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    project_id=GCP_PROJECT_ID,
                    preemptible=False,
                    provisioning_model="SPOT",
                )
            ]

            check = compute_instance_preemptible_vm_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "VM Instance spot-vm is configured as Spot VM."
            )
            assert result[0].resource_id == "3333333333"
            assert result[0].resource_name == "spot-vm"
            assert result[0].location == "us-west1"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_instance_standard_provisioning_model(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled import (
                compute_instance_preemptible_vm_disabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="standard-vm",
                    id="4444444444",
                    zone="asia-east1-a",
                    region="asia-east1",
                    public_ip=True,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    project_id=GCP_PROJECT_ID,
                    preemptible=False,
                    provisioning_model="STANDARD",
                )
            ]

            check = compute_instance_preemptible_vm_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "VM Instance standard-vm is not preemptible or Spot VM."
            )
            assert result[0].resource_id == "4444444444"
            assert result[0].resource_name == "standard-vm"
            assert result[0].location == "asia-east1"
            assert result[0].project_id == GCP_PROJECT_ID

    def test_multiple_instances_spot_and_standard(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_instance_preemptible_vm_disabled.compute_instance_preemptible_vm_disabled import (
                compute_instance_preemptible_vm_disabled,
            )
            from prowler.providers.gcp.services.compute.compute_service import Instance

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.instances = [
                Instance(
                    name="spot-instance",
                    id="5555555555",
                    zone="us-central1-c",
                    region="us-central1",
                    public_ip=False,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=False,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    project_id=GCP_PROJECT_ID,
                    preemptible=False,
                    provisioning_model="SPOT",
                ),
                Instance(
                    name="standard-instance-2",
                    id="6666666666",
                    zone="europe-west2-a",
                    region="europe-west2",
                    public_ip=True,
                    metadata={},
                    shielded_enabled_vtpm=True,
                    shielded_enabled_integrity_monitoring=True,
                    confidential_computing=True,
                    service_accounts=[],
                    ip_forward=False,
                    disks_encryption=[],
                    project_id=GCP_PROJECT_ID,
                    preemptible=False,
                    provisioning_model="STANDARD",
                ),
            ]

            check = compute_instance_preemptible_vm_disabled()
            result = check.execute()

            assert len(result) == 2

            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "VM Instance spot-instance is configured as Spot VM."
            )
            assert result[0].resource_id == "5555555555"
            assert result[0].resource_name == "spot-instance"

            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "VM Instance standard-instance-2 is not preemptible or Spot VM."
            )
            assert result[1].resource_id == "6666666666"
            assert result[1].resource_name == "standard-instance-2"
