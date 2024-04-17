from unittest.mock import MagicMock, patch
from uuid import uuid4

from prowler.providers.gcp.services.compute.compute_service import Compute
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


def mock_api_client(_, __, ___, ____):
    client = MagicMock()

    # Mocking regions
    region1_id = str(uuid4())

    client.regions().list().execute.return_value = {
        "items": [
            {
                "name": "region1",
                "id": region1_id,
            }
        ]
    }
    client.regions().list_next.return_value = None

    # Mocking zones
    zone1_id = str(uuid4())

    client.zones().list().execute.return_value = {
        "items": [
            {
                "name": "zone1",
                "id": zone1_id,
            }
        ]
    }
    client.zones().list_next.return_value = None

    # Mocking projects
    client.projects().get().execute.return_value = {
        "commonInstanceMetadata": {
            "items": [
                {
                    "key": "enable-oslogin",
                    "value": "TRUE",
                },
                {
                    "key": "enable-oslogin",
                    "value": "FALSE",
                },
                {
                    "key": "testing-key",
                    "value": "TRUE",
                },
            ]
        }
    }
    client.projects().list_next.return_value = None

    # Mocking instances
    instance1_id = str(uuid4())
    instance2_id = str(uuid4())

    client.instances().list().execute.return_value = {
        "items": [
            {
                "name": "instance1",
                "id": instance1_id,
                "metadata": {},
                "networkInterfaces": [
                    {
                        "accessConfigs": [
                            {
                                "natIP": "nat_ip",
                                "type": "ONE_TO_ONE_NAT",
                            }
                        ],
                    }
                ],
                "shieldedInstanceConfig": {
                    "enableVtpm": True,
                    "enableIntegrityMonitoring": True,
                },
                "confidentialInstanceConfig": {"enableConfidentialCompute": True},
                "serviceAccounts": [
                    {
                        "email": "test@test.es",
                        "scopes": ["scope1", "scope2"],
                    }
                ],
                "canIpForward": True,
                "disks": [
                    {
                        "deviceName": "disk1",
                        "diskEncryptionKey": {"sha256": "sha256_key"},
                        "diskSizeGb": 10,
                        "diskType": "disk_type",
                    }
                ],
            },
            {
                "name": "instance2",
                "id": instance2_id,
                "metadata": {},
                "networkInterfaces": [],
                "shieldedInstanceConfig": {
                    "enableVtpm": False,
                    "enableIntegrityMonitoring": False,
                },
                "confidentialInstanceConfig": {"enableConfidentialCompute": False},
                "serviceAccounts": [
                    {
                        "email": "test2@test.es",
                        "scopes": ["scope3"],
                    }
                ],
                "canIpForward": False,
                "disks": [
                    {
                        "deviceName": "disk2",
                        "diskEncryptionKey": {"kmsKeyName": "kms_key"},
                        "diskSizeGb": 20,
                        "diskType": "disk_type",
                    }
                ],
            },
        ]
    }
    client.instances().list_next.return_value = None

    # Mocking networks
    network1_id = str(uuid4())
    network2_id = str(uuid4())
    network3_id = str(uuid4())

    client.networks().list().execute.return_value = {
        "items": [
            {
                "name": "network1",
                "id": network1_id,
                "autoCreateSubnetworks": True,
            },
            {
                "name": "network2",
                "id": network2_id,
                "autoCreateSubnetworks": False,
            },
            {"name": "network3", "id": network3_id},
        ]
    }
    client.networks().list_next.return_value = None

    # Mocking subnetworks
    subnetwork1_id = str(uuid4())
    subnetwork2_id = str(uuid4())
    subnetwork3_id = str(uuid4())

    client.subnetworks().list().execute.return_value = {
        "items": [
            {
                "name": "subnetwork1",
                "id": subnetwork1_id,
                "enableFlowLogs": True,
                "network": "region1/network1",
            },
            {
                "name": "subnetwork2",
                "id": subnetwork2_id,
                "enableFlowLogs": False,
                "network": "region1/network1",
            },
            {
                "name": "subnetwork3",
                "id": subnetwork3_id,
                "enableFlowLogs": False,
                "network": "region2/network3",
            },
        ]
    }
    client.subnetworks().list_next.return_value = None

    # Mocking addresses
    address1_id = str(uuid4())
    address2_id = str(uuid4())
    address3_id = str(uuid4())

    client.addresses().list().execute.return_value = {
        "items": [
            {
                "name": "address1",
                "id": address1_id,
                "address": "10.0.0.1",
                "addressType": "INTERNAL",
            },
            {
                "name": "address2",
                "id": address2_id,
                "address": "10.0.0.2",
                "addressType": "INTERNAL",
            },
            {
                "name": "address3",
                "id": address3_id,
                "address": "20.34.105.200",
                "addressType": "EXTERNAL",
            },
        ]
    }
    client.addresses().list_next.return_value = None

    # Mocking firewall rules
    firewall1_id = str(uuid4())
    firewall2_id = str(uuid4())
    firewall3_id = str(uuid4())

    client.firewalls().list().execute.return_value = {
        "items": [
            {
                "name": "firewall1",
                "id": firewall1_id,
                "allowed": [{"IPProtocol": "UDP"}],
                "sourceRanges": ["30.0.0.0/16"],
                "direction": "INGRESS",
            },
            {
                "name": "firewall2",
                "id": firewall2_id,
                "allowed": [{"IPProtocol": "TCP"}],
                "sourceRanges": ["0.0.0.0/0"],
                "direction": "EGRESS",
            },
            {
                "name": "firewall3",
                "id": firewall3_id,
                "allowed": [{"IPProtocol": "TCP"}],
                "sourceRanges": ["10.0.15.0/24"],
                "direction": "INGRESS",
            },
        ]
    }
    client.firewalls().list_next.return_value = None

    # Mocking URL maps
    url_map1_id = str(uuid4())
    url_map2_id = str(uuid4())

    client.urlMaps().list().execute.return_value = {
        "items": [
            {
                "name": "url_map1",
                "id": url_map1_id,
                "defaultService": "service1",
            },
            {
                "name": "url_map2",
                "id": url_map2_id,
                "defaultService": "service2",
            },
        ]
    }
    client.urlMaps().list_next.return_value = None

    client.backendServices().get().execute.side_effect = [
        {
            "logConfig": {"enable": True},
        },
        {
            "logConfig": {"enable": False},
        },
    ]

    return client


@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
    new=mock_is_api_active,
)
@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
    new=mock_api_client,
)
class Test_Compute_Service:
    def test__get_service__(self):
        compute_client = Compute(set_mocked_gcp_provider())
        assert compute_client.service == "compute"

    def test__get_project_ids__(self):
        compute_client = Compute(set_mocked_gcp_provider())
        assert compute_client.project_ids.__class__.__name__ == "list"

    def test__get_regions__(self):
        compute_client = Compute(set_mocked_gcp_provider([GCP_PROJECT_ID]))
        assert len(compute_client.regions) == 1

        assert "region1" in compute_client.regions

    def test__get_zones__(self):
        compute_client = Compute(set_mocked_gcp_provider([GCP_PROJECT_ID]))
        assert len(compute_client.zones) == 1

        assert "zone1" in compute_client.zones

    def test__get_projects__(self):
        compute_client = Compute(set_mocked_gcp_provider([GCP_PROJECT_ID]))
        assert len(compute_client.projects) == 1

        assert compute_client.projects[0].id == GCP_PROJECT_ID
        assert compute_client.projects[0].enable_oslogin

    def test__get_instances__(self):
        compute_client = Compute(set_mocked_gcp_provider([GCP_PROJECT_ID]))
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
            compute_client.instances[0].service_accounts[0]["email"] == "test@test.es"
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
            compute_client.instances[1].service_accounts[0]["email"] == "test2@test.es"
        )
        assert compute_client.instances[1].service_accounts[0]["scopes"] == ["scope3"]
        assert not compute_client.instances[1].ip_forward
        assert compute_client.instances[1].disks_encryption == [("disk2", False)]

    def test__get_networks__(self):
        compute_client = Compute(set_mocked_gcp_provider([GCP_PROJECT_ID]))
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

    def test__get_subnetworks__(self):
        compute_client = Compute(set_mocked_gcp_provider([GCP_PROJECT_ID]))
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

    def test__get_addresses__(self):
        compute_client = Compute(set_mocked_gcp_provider([GCP_PROJECT_ID]))
        assert len(compute_client.addresses) == 3

        assert compute_client.addresses[0].name == "address1"
        assert compute_client.addresses[0].id.__class__.__name__ == "str"
        assert compute_client.addresses[0].ip == "10.0.0.1"
        assert compute_client.addresses[0].type == "INTERNAL"
        assert compute_client.addresses[0].region == "region1"
        assert compute_client.addresses[0].project_id == GCP_PROJECT_ID

        assert compute_client.addresses[1].name == "address2"
        assert compute_client.addresses[1].id.__class__.__name__ == "str"
        assert compute_client.addresses[1].ip == "10.0.0.2"
        assert compute_client.addresses[1].type == "INTERNAL"
        assert compute_client.addresses[1].region == "region1"
        assert compute_client.addresses[1].project_id == GCP_PROJECT_ID

        assert compute_client.addresses[2].name == "address3"
        assert compute_client.addresses[2].id.__class__.__name__ == "str"
        assert compute_client.addresses[2].ip == "20.34.105.200"
        assert compute_client.addresses[2].type == "EXTERNAL"
        assert compute_client.addresses[2].region == "region1"
        assert compute_client.addresses[2].project_id == GCP_PROJECT_ID

    def test__get_firewalls__(self):
        compute_client = Compute(set_mocked_gcp_provider([GCP_PROJECT_ID]))
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

    def test__get_url_maps__(self):
        compute_client = Compute(set_mocked_gcp_provider([GCP_PROJECT_ID]))
        assert len(compute_client.load_balancers) == 2

        assert compute_client.load_balancers[0].name == "url_map1"
        assert compute_client.load_balancers[0].id.__class__.__name__ == "str"
        assert compute_client.load_balancers[0].service == "service1"
        assert compute_client.load_balancers[0].project_id == GCP_PROJECT_ID

        assert compute_client.load_balancers[1].name == "url_map2"
        assert compute_client.load_balancers[1].id.__class__.__name__ == "str"
        assert compute_client.load_balancers[1].service == "service2"
        assert compute_client.load_balancers[1].project_id == GCP_PROJECT_ID

    def test__get_backend_services__(self):
        compute_client = Compute(set_mocked_gcp_provider([GCP_PROJECT_ID]))
        assert len(compute_client.load_balancers) == 2

        assert compute_client.load_balancers[0].logging

        assert not compute_client.load_balancers[1].logging
