"""Tests for network_security_list_ingress_from_internet_to_ssh_port."""

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
    "network_security_list_ingress_from_internet_to_ssh_port."
    "network_security_list_ingress_from_internet_to_ssh_port"
)


def build_security_list(ingress_rules):
    """Build a SecurityList model with the given ingress rules."""
    from prowler.providers.oraclecloud.services.network.network_service import (
        SecurityList,
    )

    return SecurityList(
        id="ocid1.securitylist.oc1.iad.example",
        display_name="test-security-list",
        compartment_id=OCI_COMPARTMENT_ID,
        vcn_id="ocid1.vcn.oc1.iad.example",
        ingress_security_rules=ingress_rules,
        egress_security_rules=[],
        lifecycle_state="AVAILABLE",
        region=OCI_REGION,
        time_created=datetime(2024, 1, 1),
    )


def tcp_rule(source, port_min=None, port_max=None, protocol="6"):
    """Build an OCI ingress rule dict matching `oci.util.to_dict` output."""
    rule = {"source": source, "protocol": protocol}
    if port_min is not None or port_max is not None:
        rule["tcp_options"] = {
            "destination_port_range": {"min": port_min, "max": port_max}
        }
    return rule


def run_check(security_lists):
    """Execute the check against the given security lists."""
    network_client = mock.MagicMock()
    network_client.security_lists = security_lists

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oraclecloud_provider(),
        ),
        mock.patch(f"{CHECK_MODULE}.network_client", new=network_client),
    ):
        from prowler.providers.oraclecloud.services.network.network_security_list_ingress_from_internet_to_ssh_port.network_security_list_ingress_from_internet_to_ssh_port import (
            network_security_list_ingress_from_internet_to_ssh_port,
        )

        return network_security_list_ingress_from_internet_to_ssh_port().execute()


class Test_network_security_list_ingress_from_internet_to_ssh_port:
    def test_no_resources(self):
        """network_security_list_ingress_from_internet_to_ssh_port: No resources to check"""
        assert run_check([]) == []

    @pytest.mark.parametrize(
        "ingress_rules",
        [
            pytest.param(
                [tcp_rule("10.0.0.0/8", 22, 22)],
                id="tcp-22-from-private-ipv4-range",
            ),
            pytest.param(
                [tcp_rule("0.0.0.0/0", 443, 443)],
                id="ipv4-any-but-only-https",
            ),
            pytest.param(
                [tcp_rule("::/0", 443, 443)],
                id="ipv6-any-but-only-https",
            ),
            pytest.param(
                [
                    {
                        "source": "0.0.0.0/0",
                        "protocol": "17",
                        "udp_options": {
                            "destination_port_range": {"min": 22, "max": 22}
                        },
                    }
                ],
                id="ipv4-any-udp-22",
            ),
            pytest.param(
                [
                    {
                        "source": "::/0",
                        "protocol": "17",
                        "udp_options": {
                            "destination_port_range": {"min": 22, "max": 22}
                        },
                    }
                ],
                id="ipv6-any-udp-22",
            ),
            pytest.param(
                [tcp_rule("0.0.0.0/0", 1, 21)],
                id="ipv4-any-tcp-range-ending-before-ssh",
            ),
        ],
    )
    def test_resource_compliant(self, ingress_rules):
        """network_security_list_ingress_from_internet_to_ssh_port: SSH is not publicly reachable"""
        result = run_check([build_security_list(ingress_rules)])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "ocid1.securitylist.oc1.iad.example"
        assert result[0].resource_name == "test-security-list"
        assert result[0].region == OCI_REGION
        assert result[0].compartment_id == OCI_COMPARTMENT_ID
        assert result[0].check_metadata.Provider == "oraclecloud"
        assert (
            result[0].check_metadata.CheckID
            == "network_security_list_ingress_from_internet_to_ssh_port"
        )
        assert result[0].check_metadata.ServiceName == "network"

    @pytest.mark.parametrize(
        "ingress_rules,expected_source",
        [
            pytest.param(
                [tcp_rule("0.0.0.0/0", 22, 22)],
                "0.0.0.0/0",
                id="ipv4-any-tcp-22",
            ),
            pytest.param(
                [tcp_rule("::/0", 22, 22)],
                "::/0",
                id="ipv6-any-tcp-22",
            ),
            pytest.param(
                [tcp_rule("::/0", 20, 30)],
                "::/0",
                id="ipv6-any-tcp-range-covering-22",
            ),
            pytest.param(
                [tcp_rule("::/0", None, None)],
                "::/0",
                id="ipv6-any-tcp-without-port-range",
            ),
            pytest.param(
                [{"source": "::/0"}],
                "::/0",
                id="ipv6-any-without-protocol",
            ),
            pytest.param(
                [{"source": "::/0", "protocol": "all"}],
                "::/0",
                id="ipv6-any-all-protocols",
            ),
            pytest.param(
                [tcp_rule("0.0.0.0/0", 1, 65535)],
                "0.0.0.0/0",
                id="ipv4-any-tcp-every-port",
            ),
            pytest.param(
                [
                    tcp_rule("10.0.0.0/8", 22, 22),
                    tcp_rule("::/0", 22, 22),
                ],
                "::/0",
                id="ipv6-any-among-restricted-rules",
            ),
        ],
    )
    def test_resource_non_compliant(self, ingress_rules, expected_source):
        """network_security_list_ingress_from_internet_to_ssh_port: SSH is reachable from the internet"""
        result = run_check([build_security_list(ingress_rules)])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        # The finding names the CIDR that actually exposed the port.
        assert (
            f"Security list test-security-list allows ingress from {expected_source} "
            "to port 22 (SSH)." == result[0].status_extended
        )
        assert result[0].resource_id == "ocid1.securitylist.oc1.iad.example"
        assert result[0].check_metadata.Provider == "oraclecloud"
        assert result[0].check_metadata.ServiceName == "network"
