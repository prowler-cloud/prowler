from re import search
from unittest import mock

GCP_PROJECT_ID = "123456789012"


class Test_compute_instance_encryption_with_csek_enabled:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = []

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_encryption_with_csek_enabled.compute_instance_encryption_with_csek_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_encryption_with_csek_enabled.compute_instance_encryption_with_csek_enabled import (
                compute_instance_encryption_with_csek_enabled,
            )

            check = compute_instance_encryption_with_csek_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_instance_with_all_encrypted_disks(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={"items": [{"key": "block-project-ssh-keys", "value": "true"}]},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[("disk1", True), ("disk2", True)],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_encryption_with_csek_enabled.compute_instance_encryption_with_csek_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_encryption_with_csek_enabled.compute_instance_encryption_with_csek_enabled import (
                compute_instance_encryption_with_csek_enabled,
            )

            check = compute_instance_encryption_with_csek_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"The VM Instance {instance.name} have every disk encrypted.",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_instance_with_one_unecrypted_disk(self):
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
            ip_forward=False,
            disks_encryption=[("disk1", False), ("disk2", True)],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_encryption_with_csek_enabled.compute_instance_encryption_with_csek_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_encryption_with_csek_enabled.compute_instance_encryption_with_csek_enabled import (
                compute_instance_encryption_with_csek_enabled,
            )

            check = compute_instance_encryption_with_csek_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"The VM Instance {instance.name} have the following unencrypted disks: '{', '.join([i[0] for i in instance.disks_encryption if not i[1]])}'",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_instance_with_all_unencrypted_disks(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={"items": [{"key": "block-project-ssh-keys", "value": "false"}]},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            service_accounts=[],
            ip_forward=False,
            disks_encryption=[("disk1", False), ("disk2", False)],
            project_id=GCP_PROJECT_ID,
        )

        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = [instance]

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_encryption_with_csek_enabled.compute_instance_encryption_with_csek_enabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_encryption_with_csek_enabled.compute_instance_encryption_with_csek_enabled import (
                compute_instance_encryption_with_csek_enabled,
            )

            check = compute_instance_encryption_with_csek_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"The VM Instance {instance.name} have the following unencrypted disks: '{', '.join([i[0] for i in instance.disks_encryption if not i[1]])}'",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
