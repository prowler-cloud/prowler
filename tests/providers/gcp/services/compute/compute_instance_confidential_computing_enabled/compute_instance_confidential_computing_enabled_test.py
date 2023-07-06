from re import search
from unittest import mock

GCP_PROJECT_ID = "123456789012"


class Test_compute_instance_confidential_computing_enabled:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = []

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_confidential_computing_enabled.compute_instance_confidential_computing_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_confidential_computing_enabled.compute_instance_confidential_computing_enabled import (
                compute_instance_confidential_computing_enabled,
            )

            check = compute_instance_confidential_computing_enabled()
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
            "prowler.providers.gcp.services.compute.compute_instance_confidential_computing_enabled.compute_instance_confidential_computing_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_confidential_computing_enabled.compute_instance_confidential_computing_enabled import (
                compute_instance_confidential_computing_enabled,
            )

            check = compute_instance_confidential_computing_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"VM Instance {instance.name} has Confidential Computing enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
            assert result[0].resource_name == instance.name
            assert result[0].location == instance.zone
            assert result[0].project_id == GCP_PROJECT_ID

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
            confidential_computing=False,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[("disk1", False), ("disk2", False)],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_confidential_computing_enabled.compute_instance_confidential_computing_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_confidential_computing_enabled.compute_instance_confidential_computing_enabled import (
                compute_instance_confidential_computing_enabled,
            )

            check = compute_instance_confidential_computing_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"VM Instance {instance.name} does not have Confidential Computing enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
            assert result[0].resource_name == instance.name
            assert result[0].location == instance.zone
            assert result[0].project_id == GCP_PROJECT_ID
