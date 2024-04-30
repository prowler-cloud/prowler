from unittest.mock import patch

from prowler.providers.gcp.services.compute.compute_service import Compute
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestComputeService:
    def test_service(self):
        with patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ), patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=mock_api_client,
        ):
            compute_client = Compute(set_mocked_gcp_provider([GCP_PROJECT_ID]))
            assert compute_client.service == "compute"
            assert compute_client.project_ids == [GCP_PROJECT_ID]

            assert len(compute_client.regions) == 1
            assert "europe-west1-b" in compute_client.regions

            assert len(compute_client.zones) == 1
            assert "zone1" in compute_client.zones

            assert len(compute_client.projects) == 1
            assert compute_client.projects[0].id == GCP_PROJECT_ID
            assert compute_client.projects[0].enable_oslogin

            assert len(compute_client.instances) == 2
            assert compute_client.instances[0].name == "instance1"
            assert compute_client.instances[0].id.__class__.__name__ == "str"
            assert compute_client.instances[0].zone == "zone1"
            assert compute_client.instances[0].public_ip
            assert compute_client.instances[0].project_id == GCP_PROJECT_ID
            assert compute_client.instances[0].metadata == {}
            assert compute_client.instances[0].shielded_enabled_vtpm
            assert compute_client.instances[0].shielded_enabled_integrity_monitoring
            assert compute_client.instances[0].confidential_computing
            assert len(compute_client.instances[0].service_accounts) == 1
            assert (
                compute_client.instances[0].service_accounts[0]["email"]
                == "test@test.es"
            )
            assert compute_client.instances[0].service_accounts[0]["scopes"] == [
                "scope1",
                "scope2",
            ]
            assert compute_client.instances[0].ip_forward
            assert compute_client.instances[0].disks_encryption == [("disk1", True)]

            assert compute_client.instances[1].name == "instance2"
            assert compute_client.instances[1].id.__class__.__name__ == "str"
            assert compute_client.instances[1].zone == "zone1"
            assert not compute_client.instances[1].public_ip
            assert compute_client.instances[1].project_id == GCP_PROJECT_ID
            assert compute_client.instances[1].metadata == {}
            assert not compute_client.instances[1].shielded_enabled_vtpm
            assert not compute_client.instances[1].shielded_enabled_integrity_monitoring
            assert not compute_client.instances[1].confidential_computing
            assert len(compute_client.instances[1].service_accounts) == 1
            assert (
                compute_client.instances[1].service_accounts[0]["email"]
                == "test2@test.es"
            )
            assert compute_client.instances[1].service_accounts[0]["scopes"] == [
                "scope3"
            ]
            assert not compute_client.instances[1].ip_forward
            assert compute_client.instances[1].disks_encryption == [("disk2", False)]

            assert len(compute_client.networks) == 3
            assert compute_client.networks[0].name == "network1"
            assert compute_client.networks[0].id.__class__.__name__ == "str"
            assert compute_client.networks[0].subnet_mode == "auto"
            assert compute_client.networks[0].project_id == GCP_PROJECT_ID

            assert compute_client.networks[1].name == "network2"
            assert compute_client.networks[1].id.__class__.__name__ == "str"
            assert compute_client.networks[1].subnet_mode == "custom"
            assert compute_client.networks[1].project_id == GCP_PROJECT_ID

            assert compute_client.networks[2].name == "network3"
            assert compute_client.networks[2].id.__class__.__name__ == "str"
            assert compute_client.networks[2].subnet_mode == "legacy"
            assert compute_client.networks[2].project_id == GCP_PROJECT_ID

            assert len(compute_client.subnets) == 3
            assert compute_client.subnets[0].name == "subnetwork1"
            assert compute_client.subnets[0].id.__class__.__name__ == "str"
            assert compute_client.subnets[0].flow_logs
            assert compute_client.subnets[0].network == "network1"
            assert compute_client.subnets[0].project_id == GCP_PROJECT_ID

            assert compute_client.subnets[1].name == "subnetwork2"
            assert compute_client.subnets[1].id.__class__.__name__ == "str"
            assert not compute_client.subnets[1].flow_logs
            assert compute_client.subnets[1].network == "network1"
            assert compute_client.subnets[1].project_id == GCP_PROJECT_ID

            assert compute_client.subnets[2].name == "subnetwork3"
            assert compute_client.subnets[2].id.__class__.__name__ == "str"
            assert not compute_client.subnets[2].flow_logs
            assert compute_client.subnets[2].network == "network3"
            assert compute_client.subnets[2].project_id == GCP_PROJECT_ID

            assert len(compute_client.addresses) == 3

            assert compute_client.addresses[0].name == "address1"
            assert compute_client.addresses[0].id.__class__.__name__ == "str"
            assert compute_client.addresses[0].ip == "10.0.0.1"
            assert compute_client.addresses[0].type == "INTERNAL"
            assert compute_client.addresses[0].region == "europe-west1-b"
            assert compute_client.addresses[0].project_id == GCP_PROJECT_ID

            assert compute_client.addresses[1].name == "address2"
            assert compute_client.addresses[1].id.__class__.__name__ == "str"
            assert compute_client.addresses[1].ip == "10.0.0.2"
            assert compute_client.addresses[1].type == "INTERNAL"
            assert compute_client.addresses[1].region == "europe-west1-b"
            assert compute_client.addresses[1].project_id == GCP_PROJECT_ID

            assert compute_client.addresses[2].name == "address3"
            assert compute_client.addresses[2].id.__class__.__name__ == "str"
            assert compute_client.addresses[2].ip == "20.34.105.200"
            assert compute_client.addresses[2].type == "EXTERNAL"
            assert compute_client.addresses[2].region == "europe-west1-b"
            assert compute_client.addresses[2].project_id == GCP_PROJECT_ID

            assert len(compute_client.firewalls) == 3
            assert compute_client.firewalls[0].name == "firewall1"
            assert compute_client.firewalls[0].id.__class__.__name__ == "str"
            assert compute_client.firewalls[0].allowed_rules == [{"IPProtocol": "UDP"}]
            assert compute_client.firewalls[0].source_ranges == ["30.0.0.0/16"]
            assert compute_client.firewalls[0].direction == "INGRESS"
            assert compute_client.firewalls[0].project_id == GCP_PROJECT_ID

            assert compute_client.firewalls[1].name == "firewall2"
            assert compute_client.firewalls[1].id.__class__.__name__ == "str"
            assert compute_client.firewalls[1].allowed_rules == [{"IPProtocol": "TCP"}]
            assert compute_client.firewalls[1].source_ranges == ["0.0.0.0/0"]
            assert compute_client.firewalls[1].direction == "EGRESS"
            assert compute_client.firewalls[1].project_id == GCP_PROJECT_ID

            assert compute_client.firewalls[2].name == "firewall3"
            assert compute_client.firewalls[2].id.__class__.__name__ == "str"
            assert compute_client.firewalls[2].allowed_rules == [{"IPProtocol": "TCP"}]
            assert compute_client.firewalls[2].source_ranges == ["10.0.15.0/24"]
            assert compute_client.firewalls[2].direction == "INGRESS"
            assert compute_client.firewalls[2].project_id == GCP_PROJECT_ID

            assert len(compute_client.load_balancers) == 2
            assert compute_client.load_balancers[0].name == "url_map1"
            assert compute_client.load_balancers[0].id.__class__.__name__ == "str"
            assert compute_client.load_balancers[0].service == "service1"
            assert compute_client.load_balancers[0].project_id == GCP_PROJECT_ID

            assert compute_client.load_balancers[1].name == "url_map2"
            assert compute_client.load_balancers[1].id.__class__.__name__ == "str"
            assert compute_client.load_balancers[1].service == "service2"
            assert compute_client.load_balancers[1].project_id == GCP_PROJECT_ID

            assert len(compute_client.load_balancers) == 2

            assert compute_client.load_balancers[0].logging

            assert not compute_client.load_balancers[1].logging
