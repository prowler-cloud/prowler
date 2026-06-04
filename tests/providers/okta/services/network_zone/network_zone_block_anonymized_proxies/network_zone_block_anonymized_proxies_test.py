from unittest import mock

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.network_zone.network_zone_fixtures import (
    build_network_zone_client,
    network_zone,
)

CHECK_PATH = (
    "prowler.providers.okta.services.network."
    "network_zone_block_anonymized_proxies."
    "network_zone_block_anonymized_proxies.network_zone_client"
)


def _run_check(network_zone_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=network_zone_client),
    ):
        from prowler.providers.okta.services.network.network_zone_block_anonymized_proxies.network_zone_block_anonymized_proxies import (
            network_zone_block_anonymized_proxies,
        )

        return network_zone_block_anonymized_proxies().execute()


class Test_network_zone_block_anonymized_proxies:
    def test_no_zones_fails(self):
        findings = _run_check(build_network_zone_client({}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No active Okta Network Zone blocklist" in findings[0].status_extended

    def test_pass_with_active_ip_blocklist_gateway(self):
        zone = network_zone(gateways=["198.51.100.10/32"])
        findings = _run_check(build_network_zone_client({zone.id: zone}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_id == zone.id
        assert "gateway" in findings[0].status_extended

    def test_pass_with_active_enhanced_dynamic_anonymizer_blocklist(self):
        zone = network_zone(
            zone_id="nzo-enhanced",
            name="DefaultEnhancedDynamicZone",
            zone_type="DYNAMIC_V2",
            system=True,
            ip_service_categories=["ANONYMIZER"],
        )
        findings = _run_check(build_network_zone_client({zone.id: zone}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "Enhanced Dynamic" in findings[0].status_extended

    def test_existing_zones_without_anonymized_proxy_blocklist_fail(self):
        policy_zone = network_zone(
            zone_id="nzo-policy",
            name="Corporate Policy Zone",
            usage="POLICY",
            gateways=["10.0.0.0/8"],
        )
        inactive_blocklist = network_zone(
            zone_id="nzo-inactive",
            name="Inactive Blocklist",
            status="INACTIVE",
            gateways=["203.0.113.0/24"],
        )
        findings = _run_check(
            build_network_zone_client(
                {policy_zone.id: policy_zone, inactive_blocklist.id: inactive_blocklist}
            )
        )
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "do not actively block" in findings[0].status_extended
