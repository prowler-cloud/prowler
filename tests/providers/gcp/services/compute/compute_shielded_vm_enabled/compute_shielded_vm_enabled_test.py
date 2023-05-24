from re import search
from unittest import mock

GCP_PROJECT_ID = "123456789012"


class Test_compute_shielded_vm_enabled:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = []

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_shielded_vm_enabled.compute_shielded_vm_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_shielded_vm_enabled.compute_shielded_vm_enabled import (
                compute_shielded_vm_enabled,
            )

            check = compute_shielded_vm_enabled()
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
            service_accounts=[],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_shielded_vm_enabled.compute_shielded_vm_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_shielded_vm_enabled.compute_shielded_vm_enabled import (
                compute_shielded_vm_enabled,
            )

            check = compute_shielded_vm_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"VM Instance {instance.name} have vTPM or Integrity Monitoring set to on",
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
            service_accounts=[],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_shielded_vm_enabled.compute_shielded_vm_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_shielded_vm_enabled.compute_shielded_vm_enabled import (
                compute_shielded_vm_enabled,
            )

            check = compute_shielded_vm_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"VM Instance {instance.name} don't have vTPM and Integrity Monitoring set to on",
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
            service_accounts=[],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_shielded_vm_enabled.compute_shielded_vm_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_shielded_vm_enabled.compute_shielded_vm_enabled import (
                compute_shielded_vm_enabled,
            )

            check = compute_shielded_vm_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"VM Instance {instance.name} don't have vTPM and Integrity Monitoring set to on",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
