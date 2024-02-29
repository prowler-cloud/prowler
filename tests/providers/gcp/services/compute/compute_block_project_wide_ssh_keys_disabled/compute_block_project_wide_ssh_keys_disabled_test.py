from re import search
from unittest import mock

from tests.providers.gcp.lib.audit_info_utils import GCP_PROJECT_ID


class Test_compute_instance_block_project_wide_ssh_keys_disabled:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = []

        with mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_block_project_wide_ssh_keys_disabled.compute_instance_block_project_wide_ssh_keys_disabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_block_project_wide_ssh_keys_disabled.compute_instance_block_project_wide_ssh_keys_disabled import (
                compute_instance_block_project_wide_ssh_keys_disabled,
            )

            check = compute_instance_block_project_wide_ssh_keys_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_instance_with_block_project_ssh_keys_true(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={"items": [{"key": "block-project-ssh-keys", "value": "true"}]},
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
            "prowler.providers.gcp.services.compute.compute_instance_block_project_wide_ssh_keys_disabled.compute_instance_block_project_wide_ssh_keys_disabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_block_project_wide_ssh_keys_disabled.compute_instance_block_project_wide_ssh_keys_disabled import (
                compute_instance_block_project_wide_ssh_keys_disabled,
            )

            check = compute_instance_block_project_wide_ssh_keys_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"The VM Instance {instance.name} is not making use of common/shared project-wide SSH key",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_instance_without_metadata(self):
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
            "prowler.providers.gcp.services.compute.compute_instance_block_project_wide_ssh_keys_disabled.compute_instance_block_project_wide_ssh_keys_disabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_block_project_wide_ssh_keys_disabled.compute_instance_block_project_wide_ssh_keys_disabled import (
                compute_instance_block_project_wide_ssh_keys_disabled,
            )

            check = compute_instance_block_project_wide_ssh_keys_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"The VM Instance {instance.name} is making use of common/shared project-wide SSH key",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_instance_with_block_project_ssh_keys_false(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={"items": [{"key": "block-project-ssh-keys", "value": "false"}]},
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
            "prowler.providers.gcp.services.compute.compute_instance_block_project_wide_ssh_keys_disabled.compute_instance_block_project_wide_ssh_keys_disabled.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_block_project_wide_ssh_keys_disabled.compute_instance_block_project_wide_ssh_keys_disabled import (
                compute_instance_block_project_wide_ssh_keys_disabled,
            )

            check = compute_instance_block_project_wide_ssh_keys_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"The VM Instance {instance.name} is making use of common/shared project-wide SSH key",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
