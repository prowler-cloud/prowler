"""Tests for network_security_group_ingress_from_internet_to_ssh_port."""

from datetime import datetime
from unittest import mock

import pytest

from tests.providers.oraclecloud.oci_fixtures import (
    OCI_COMPARTMENT_ID,
    OCI_REGION,
    set_mocked_oraclecloud_provider,
)

CHECK_MODULE = (
    "prowler.providers.oraclecloud.services.network."
    "network_security_group_ingress_from_internet_to_ssh_port."
    "network_security_group_ingress_from_internet_to_ssh_port"
)
SSH_PORT = 22


def build_network_security_group(security_rules):
    """Build a NetworkSecurityGroup model with the given security rules."""
    from prowler.providers.oraclecloud.services.network.network_service import (
        NetworkSecurityGroup,
    )

    return NetworkSecurityGroup(
        id="ocid1.nsg.oc1.iad.example",
        display_name="test-network-security-group",
        compartment_id=OCI_COMPARTMENT_ID,
        vcn_id="ocid1.vcn.oc1.iad.example",
        security_rules=security_rules,
        lifecycle_state="AVAILABLE",
        region=OCI_REGION,
        time_created=datetime(2024, 1, 1),
    )


def tcp_rule(source, port_min=None, port_max=None, protocol="6", direction="INGRESS"):
    """Build an OCI NSG rule dict matching `oci.util.to_dict` output."""
    rule = {
        "direction": direction,
        "source": source,
        "destination": "0.0.0.0/0",
        "protocol": protocol,
    }
    if port_min is not None or port_max is not None:
        rule["tcp_options"] = {
            "destination_port_range": {"min": port_min, "max": port_max}
        }
    return rule


def run_check(network_security_groups):
    """Execute the check against the given network security groups."""
    network_client = mock.MagicMock()
    network_client.network_security_groups = network_security_groups

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oraclecloud_provider(),
        ),
        mock.patch(f"{CHECK_MODULE}.network_client", new=network_client),
    ):
        from prowler.providers.oraclecloud.services.network.network_security_group_ingress_from_internet_to_ssh_port.network_security_group_ingress_from_internet_to_ssh_port import (
            network_security_group_ingress_from_internet_to_ssh_port,
        )

        return network_security_group_ingress_from_internet_to_ssh_port().execute()


class Test_network_security_group_ingress_from_internet_to_ssh_port:
    def test_no_resources(self):
        """network_security_group_ingress_from_internet_to_ssh_port: No resources to check"""
        assert run_check([]) == []

    @pytest.mark.parametrize(
        "security_rules",
        [
            pytest.param(
                [tcp_rule("10.0.0.0/8", SSH_PORT, SSH_PORT)],
                id="ssh-from-private-ipv4-range",
            ),
            pytest.param(
                [tcp_rule("::/0", 443, 443)],
                id="ipv6-any-but-only-https",
            ),
            pytest.param(
                [tcp_rule("0.0.0.0/0", 443, 443)],
                id="ipv4-any-but-only-https",
            ),
            pytest.param(
                [tcp_rule("::/0", SSH_PORT, SSH_PORT, direction="EGRESS")],
                id="ipv6-any-tcp-ssh-egress-only",
            ),
            pytest.param(
                [
                    {
                        "direction": "INGRESS",
                        "source": "::/0",
                        "protocol": "17",
                        "udp_options": {
                            "destination_port_range": {"min": SSH_PORT, "max": SSH_PORT}
                        },
                    }
                ],
                id="ipv6-any-udp-ssh",
            ),
        ],
    )
    def test_resource_compliant(self, security_rules):
        """network_security_group_ingress_from_internet_to_ssh_port: SSH ingress is not publicly reachable"""
        result = run_check([build_network_security_group(security_rules)])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "ocid1.nsg.oc1.iad.example"
        assert result[0].resource_name == "test-network-security-group"
        assert result[0].region == OCI_REGION
        assert result[0].compartment_id == OCI_COMPARTMENT_ID
        assert result[0].check_metadata.Provider == "oraclecloud"
        assert (
            result[0].check_metadata.CheckID
            == "network_security_group_ingress_from_internet_to_ssh_port"
        )
        assert result[0].check_metadata.ServiceName == "network"

    @pytest.mark.parametrize(
        "security_rules,expected_source",
        [
            pytest.param(
                [tcp_rule("0.0.0.0/0", SSH_PORT, SSH_PORT)],
                "0.0.0.0/0",
                id="ipv4-any-tcp-ssh",
            ),
            pytest.param(
                [tcp_rule("::/0", SSH_PORT, SSH_PORT)],
                "::/0",
                id="ipv6-any-tcp-ssh",
            ),
            pytest.param(
                [tcp_rule("::/0", 20, 30)],
                "::/0",
                id="ipv6-any-tcp-range-covering-ssh",
            ),
            pytest.param(
                [tcp_rule("::/0", None, None)],
                "::/0",
                id="ipv6-any-tcp-without-port-range",
            ),
            pytest.param(
                [{"direction": "INGRESS", "source": "::/0"}],
                "::/0",
                id="ipv6-any-without-protocol",
            ),
            pytest.param(
                [{"direction": "INGRESS", "source": "::/0", "protocol": "all"}],
                "::/0",
                id="ipv6-any-all-protocols",
            ),
            pytest.param(
                [
                    tcp_rule("::/0", 443, 443, direction="EGRESS"),
                    tcp_rule("::/0", SSH_PORT, SSH_PORT),
                ],
                "::/0",
                id="ipv6-any-tcp-ssh-among-other-rules",
            ),
        ],
    )
    def test_resource_non_compliant(self, security_rules, expected_source):
        """network_security_group_ingress_from_internet_to_ssh_port: SSH ingress is reachable from the internet"""
        result = run_check([build_network_security_group(security_rules)])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            f"Network security group test-network-security-group allows ingress from "
            f"{expected_source} to port {SSH_PORT} (SSH)." == result[0].status_extended
        )
        assert result[0].resource_id == "ocid1.nsg.oc1.iad.example"
        assert result[0].check_metadata.Provider == "oraclecloud"
        assert result[0].check_metadata.ServiceName == "network"
