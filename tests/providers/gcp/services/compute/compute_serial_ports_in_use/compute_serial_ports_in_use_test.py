from re import search
from unittest import mock

from prowler.providers.gcp.lib.audit_info.models import GCP_Audit_Info

GCP_PROJECT_ID = "123456789012"


class Test_compute_serial_ports_in_use:
    def set_mocked_audit_info(self):
        audit_info = GCP_Audit_Info(
            credentials=None,
            project_id=GCP_PROJECT_ID,
            audit_resources=None,
            audit_metadata=None,
        )

        return audit_info

    def test_compute_no_instances(self):
        from prowler.providers.gcp.services.compute.compute_service import Compute

        gcp_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.gcp.lib.audit_info.audit_info.gcp_audit_info",
            new=gcp_audit_info,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.generate_client",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_zones__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_instances__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_networks__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use.compute_client",
            new=Compute(gcp_audit_info),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use.compute_client.instances",
            new=[],
        ):
            from prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use import (
                compute_serial_ports_in_use,
            )

            check = compute_serial_ports_in_use()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_instance_without_metadata(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            Compute,
            Instance,
        )

        gcp_audit_info = self.set_mocked_audit_info()

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            service_accounts=[],
        )

        with mock.patch(
            "prowler.providers.gcp.lib.audit_info.audit_info.gcp_audit_info",
            new=gcp_audit_info,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.generate_client",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_zones__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_instances__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_networks__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use.compute_client",
            new=Compute(gcp_audit_info),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use.compute_client.instances",
            new=[instance],
        ):
            from prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use import (
                compute_serial_ports_in_use,
            )

            check = compute_serial_ports_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"VM Instance {instance.name} have ‘Enable Connecting to Serial Ports’ off",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_compliant_instance_with_0(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            Compute,
            Instance,
        )

        gcp_audit_info = self.set_mocked_audit_info()

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={"items": [{"key": "serial-port-enabled", "value": "0"}]},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            service_accounts=[],
        )

        with mock.patch(
            "prowler.providers.gcp.lib.audit_info.audit_info.gcp_audit_info",
            new=gcp_audit_info,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.generate_client",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_zones__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_instances__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_networks__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use.compute_client",
            new=Compute(gcp_audit_info),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use.compute_client.instances",
            new=[instance],
        ):
            from prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use import (
                compute_serial_ports_in_use,
            )

            check = compute_serial_ports_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"VM Instance {instance.name} have ‘Enable Connecting to Serial Ports’ off",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_compliant_instance_with_false(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            Compute,
            Instance,
        )

        gcp_audit_info = self.set_mocked_audit_info()

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={"items": [{"key": "serial-port-enabled", "value": "false"}]},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            service_accounts=[],
        )

        with mock.patch(
            "prowler.providers.gcp.lib.audit_info.audit_info.gcp_audit_info",
            new=gcp_audit_info,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.generate_client",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_zones__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_instances__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_networks__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use.compute_client",
            new=Compute(gcp_audit_info),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use.compute_client.instances",
            new=[instance],
        ):
            from prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use import (
                compute_serial_ports_in_use,
            )

            check = compute_serial_ports_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"VM Instance {instance.name} have ‘Enable Connecting to Serial Ports’ off",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_instance_with_serial_ports_enable_1(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            Compute,
            Instance,
        )

        gcp_audit_info = self.set_mocked_audit_info()

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={"items": [{"key": "serial-port-enable", "value": "1"}]},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            service_accounts=[],
        )

        with mock.patch(
            "prowler.providers.gcp.lib.audit_info.audit_info.gcp_audit_info",
            new=gcp_audit_info,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.generate_client",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_zones__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_instances__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_networks__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use.compute_client",
            new=Compute(gcp_audit_info),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use.compute_client.instances",
            new=[instance],
        ):
            from prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use import (
                compute_serial_ports_in_use,
            )

            check = compute_serial_ports_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"VM Instance {instance.name} have ‘Enable Connecting to Serial Ports’ set to on",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id

    def test_one_instance_with_serial_ports_enable_true(self):
        from prowler.providers.gcp.services.compute.compute_service import (
            Compute,
            Instance,
        )

        gcp_audit_info = self.set_mocked_audit_info()

        instance = Instance(
            name="test",
            id="1234567890",
            zone="us-central1-a",
            public_ip=True,
            metadata={"items": [{"key": "serial-port-enable", "value": "true"}]},
            shielded_enabled_vtpm=True,
            shielded_enabled_integrity_monitoring=True,
            service_accounts=[],
        )

        with mock.patch(
            "prowler.providers.gcp.lib.audit_info.audit_info.gcp_audit_info",
            new=gcp_audit_info,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.generate_client",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_zones__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_instances__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_service.Compute.__get_networks__",
            new=lambda *args, **kwargs: None,
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use.compute_client",
            new=Compute(gcp_audit_info),
        ), mock.patch(
            "prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use.compute_client.instances",
            new=[instance],
        ):
            from prowler.providers.gcp.services.compute.compute_serial_ports_in_use.compute_serial_ports_in_use import (
                compute_serial_ports_in_use,
            )

            check = compute_serial_ports_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"VM Instance {instance.name} have ‘Enable Connecting to Serial Ports’ set to on",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
