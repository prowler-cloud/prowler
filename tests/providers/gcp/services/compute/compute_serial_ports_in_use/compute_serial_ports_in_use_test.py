from re import search
from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_instance_serial_ports_in_use:
    def test_compute_no_instances(self):
        compute_client = mock.MagicMock
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.instances = []

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_instance_serial_ports_in_use.compute_instance_serial_ports_in_use.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_serial_ports_in_use.compute_instance_serial_ports_in_use import (
                compute_instance_serial_ports_in_use,
            )

            check = compute_instance_serial_ports_in_use()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_instance_without_metadata(self):
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
            "prowler.providers.gcp.services.compute.compute_instance_serial_ports_in_use.compute_instance_serial_ports_in_use.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_serial_ports_in_use.compute_instance_serial_ports_in_use import (
                compute_instance_serial_ports_in_use,
            )

            check = compute_instance_serial_ports_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"VM Instance {instance.name} has Enable Connecting to Serial Ports off",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_compliant_instance_with_0(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={"items": [{"key": "serial-port-enabled", "value": "0"}]},
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
            "prowler.providers.gcp.services.compute.compute_instance_serial_ports_in_use.compute_instance_serial_ports_in_use.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_serial_ports_in_use.compute_instance_serial_ports_in_use import (
                compute_instance_serial_ports_in_use,
            )

            check = compute_instance_serial_ports_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"VM Instance {instance.name} has Enable Connecting to Serial Ports off",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_compliant_instance_with_false(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={"items": [{"key": "serial-port-enabled", "value": "false"}]},
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
            "prowler.providers.gcp.services.compute.compute_instance_serial_ports_in_use.compute_instance_serial_ports_in_use.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_serial_ports_in_use.compute_instance_serial_ports_in_use import (
                compute_instance_serial_ports_in_use,
            )

            check = compute_instance_serial_ports_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"VM Instance {instance.name} has Enable Connecting to Serial Ports off",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_instance_with_serial_ports_enable_1(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={"items": [{"key": "serial-port-enable", "value": "1"}]},
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
            "prowler.providers.gcp.services.compute.compute_instance_serial_ports_in_use.compute_instance_serial_ports_in_use.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_serial_ports_in_use.compute_instance_serial_ports_in_use import (
                compute_instance_serial_ports_in_use,
            )

            check = compute_instance_serial_ports_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"VM Instance {instance.name} has Enable Connecting to Serial Ports set to on",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_instance_with_serial_ports_enable_true(self):
        from prowler.providers.gcp.services.compute.compute_service import Instance

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={"items": [{"key": "serial-port-enable", "value": "true"}]},
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
            "prowler.providers.gcp.services.compute.compute_instance_serial_ports_in_use.compute_instance_serial_ports_in_use.compute_client",
            new=compute_client,
        ):
            from prowler.providers.gcp.services.compute.compute_instance_serial_ports_in_use.compute_instance_serial_ports_in_use import (
                compute_instance_serial_ports_in_use,
            )

            check = compute_instance_serial_ports_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"VM Instance {instance.name} has Enable Connecting to Serial Ports set to on",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
