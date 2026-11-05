"""Regression and characterization tests for OCI default-list source evaluation.

The expected results for local TCP and service CIDR sources are characterization
of current behavior, not a statement of desired security policy.
"""

from datetime import datetime, timezone
from unittest import mock

import pytest

from prowler.providers.oraclecloud.services.network.network_service import (
    VCN,
    SecurityList,
)
from tests.providers.oraclecloud.oci_fixtures import (
    OCI_COMPARTMENT_ID,
    OCI_REGION,
    set_mocked_oraclecloud_provider,
)

CHECK_MODULE = (
    "prowler.providers.oraclecloud.services.network."
    "network_default_security_list_restricts_traffic."
    "network_default_security_list_restricts_traffic"
)


def run_check(
    cidrs, source, source_type="CIDR_BLOCK", extra_rules=None, include_vcn=True
):
    now = datetime.now(timezone.utc)
    vcn = VCN(
        id="vcn-test",
        display_name="test-vcn",
        compartment_id=OCI_COMPARTMENT_ID,
        cidr_blocks=cidrs,
        lifecycle_state="AVAILABLE",
        default_security_list_id="sl-test",
        region=OCI_REGION,
        time_created=now,
    )
    security_list = SecurityList(
        id="sl-test",
        display_name="test-list",
        compartment_id=OCI_COMPARTMENT_ID,
        vcn_id="vcn-test",
        ingress_security_rules=[
            {
                "protocol": "6",
                "source": source,
                "source_type": source_type,
            }
        ],
        egress_security_rules=[],
        lifecycle_state="AVAILABLE",
        is_default=True,
        region=OCI_REGION,
        time_created=now,
    )
    client = mock.MagicMock()
    if extra_rules:
        security_list.ingress_security_rules.extend(extra_rules)
    client.vcns = [vcn] if include_vcn else []
    client.security_lists = [security_list]
    client.audited_compartments = {OCI_COMPARTMENT_ID: mock.MagicMock()}
    with (
        mock.patch(
            "socket.socket.connect",
            side_effect=AssertionError("Unexpected network access"),
        ),
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oraclecloud_provider(),
        ),
        mock.patch(
            "prowler.providers.oraclecloud.services.network.network_service.Network",
            return_value=client,
        ),
        mock.patch(f"{CHECK_MODULE}.network_client", new=client),
    ):
        from prowler.providers.oraclecloud.services.network.network_default_security_list_restricts_traffic.network_default_security_list_restricts_traffic import (
            network_default_security_list_restricts_traffic,
        )

        findings = network_default_security_list_restricts_traffic().execute()
    assert len(findings) == 1
    return findings[0]


@pytest.mark.parametrize(
    "cidrs,source",
    [
        (["10.0.0.0/16"], "10.0.0.0/8"),
        (["10.0.0.0/16"], "192.168.1.0/24"),
        (["172.16.0.0/16", "10.0.0.0/16"], "10.0.0.0/8"),
        (["10.0.0.0/16"], "2001:db8::/32"),
    ],
    ids=[
        "broader-source",
        "external-source",
        "multiple-vcn-cidrs",
        "different-ip-family",
    ],
)
def test_external_tcp_sources_fail(cidrs, source):
    """Prowler metadata identifies non-ICMP ingress from outside a VCN as permissive."""
    finding = run_check(cidrs, source)
    assert finding.status == "FAIL"
    assert finding.status_extended == (
        f"Default security list test-list has permissive rules: ingress from {source} with protocol 6."
    )


@pytest.mark.parametrize(
    "source,expected_status,expected_message",
    [
        (
            "10.0.1.0/24",
            "PASS",
            "Default security list test-list restricts all traffic except ICMP within VCN.",
        ),
        (
            "10.0.0.0/16",
            "PASS",
            "Default security list test-list restricts all traffic except ICMP within VCN.",
        ),
    ],
    ids=["local-subnet", "equal-vcn"],
)
def test_local_tcp_characterization(source, expected_status, expected_message):
    """Characterize containment behavior; the internal TCP policy remains unresolved."""
    finding = run_check(["10.0.0.0/16"], source)
    assert finding.status == expected_status
    assert finding.status_extended == expected_message


def test_contained_source_in_second_vcn_cidr():
    """Characterize the existing treatment of a VCN-local TCP source."""
    finding = run_check(["172.16.0.0/16", "10.0.0.0/16"], "10.0.1.0/24")
    assert finding.status == "PASS"
    assert finding.status_extended == (
        "Default security list test-list restricts all traffic except ICMP within VCN."
    )


@pytest.mark.parametrize(
    "cidrs,source,source_type,include_vcn",
    [
        (["10.0.0.0/16"], "10.0.0.0/invalid", "CIDR_BLOCK", True),
        (["10.0.0.0/99"], "10.0.0.0/8", "CIDR_BLOCK", True),
        (["10.0.0.0/16"], "10.0.0.0/8", "UNKNOWN_ENUM_VALUE", True),
        (["10.0.0.0/16"], "oci-phx-objectstorage", "SERVICE_CIDR_BLOCK", True),
        (["10.0.0.0/16"], None, "CIDR_BLOCK", True),
        (["10.0.0.0/16"], ["not-a-cidr"], "CIDR_BLOCK", True),
        ([], "10.0.0.0/8", "CIDR_BLOCK", True),
        (["10.0.0.0/16"], "10.0.0.0/8", "CIDR_BLOCK", False),
    ],
    ids=[
        "invalid-source",
        "invalid-vcn",
        "unknown-type",
        "service-cidr",
        "missing-source",
        "non-string-source",
        "empty-vcn",
        "missing-vcn",
    ],
)
def test_unverifiable_sources_are_manual(cidrs, source, source_type, include_vcn):
    finding = run_check(cidrs, source, source_type, include_vcn=include_vcn)
    assert finding.status == "MANUAL"
    assert "test-list" in finding.status_extended
    assert "verify" in finding.status_extended.lower()


def test_known_permissive_rule_takes_precedence_over_unknown():
    finding = run_check(
        ["10.0.0.0/16"],
        "not-a-cidr",
        extra_rules=[{"source": "0.0.0.0/0", "protocol": "6"}],
    )
    assert finding.status == "FAIL"
    assert "0.0.0.0/0" in finding.status_extended
    assert "Verify unassessed" in finding.status_extended


def test_missing_source_type_uses_cidr_default():
    finding = run_check(["10.0.0.0/16"], "10.0.0.0/8", None)
    assert finding.status == "FAIL"
    assert "10.0.0.0/8" in finding.status_extended


def test_invalid_vcn_cidr_and_proven_containment():
    finding = run_check(["invalid-cidr", "10.0.0.0/16"], "10.0.1.0/24")
    assert finding.status == "PASS"
    assert "test-list" in finding.status_extended
