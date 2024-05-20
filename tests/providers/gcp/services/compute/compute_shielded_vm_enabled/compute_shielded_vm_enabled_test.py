from re import search
from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_instance_shielded_vm_enabled:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = []

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_shielded_vm_enabled.compute_instance_shielded_vm_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_shielded_vm_enabled.compute_instance_shielded_vm_enabled import (
                compute_instance_shielded_vm_enabled,
            )

            check = compute_instance_shielded_vm_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_instance(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=True,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[("disk1", False), ("disk2", False)],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_shielded_vm_enabled.compute_instance_shielded_vm_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_shielded_vm_enabled.compute_instance_shielded_vm_enabled import (
                compute_instance_shielded_vm_enabled,
            )

            check = compute_instance_shielded_vm_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"VM Instance {instance.name} has vTPM or Integrity Monitoring set to on",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_instance_with_shielded_vtpm_disabled(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={},
            shielded_enabled_vtpm=False,
            shielded_enabled_integrity_monitoring=True,
            confidential_computing=True,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[("disk1", False), ("disk2", False)],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_shielded_vm_enabled.compute_instance_shielded_vm_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_shielded_vm_enabled.compute_instance_shielded_vm_enabled import (
                compute_instance_shielded_vm_enabled,
            )

            check = compute_instance_shielded_vm_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"VM Instance {instance.name} doesn't have vTPM and Integrity Monitoring set to on",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_instance_with_shielded_integrity_monitoring_disabled(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=False,
            confidential_computing=True,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[("disk1", False), ("disk2", False)],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_shielded_vm_enabled.compute_instance_shielded_vm_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_shielded_vm_enabled.compute_instance_shielded_vm_enabled import (
                compute_instance_shielded_vm_enabled,
            )

            check = compute_instance_shielded_vm_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"VM Instance {instance.name} doesn't have vTPM and Integrity Monitoring set to on",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
