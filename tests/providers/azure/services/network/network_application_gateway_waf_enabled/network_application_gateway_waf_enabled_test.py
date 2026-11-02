from unittest import mock

from prowler.providers.azure.services.network.network_service import (
    ApplicationGateway,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "network_application_gateway_waf_enabled"
CHECK_PATH = f"prowler.providers.azure.services.network.{CHECK}.{CHECK}"
GATEWAY_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Network/applicationGateways/agw1"
POLICY_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf1"
PREFIX = f"Application Gateway agw1 in subscription {AZURE_SUBSCRIPTION_DISPLAY}"
GATEWAYS_UNLISTED = f"Cannot evaluate the WAF policy association of the Application Gateways in subscription {AZURE_SUBSCRIPTION_DISPLAY}: they could not be listed completely. Check the scan log for the error, and verify that Microsoft.Network/applicationGateways/read (included in Reader) is granted to the scanning identity."
POLICIES_UNLISTED = f"Cannot evaluate the WAF policy association of the Application Gateways in subscription {AZURE_SUBSCRIPTION_DISPLAY}: the WAF policies associated with them could not be listed or read completely. Check the scan log for the error, and verify that Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read (included in Reader) is granted to the scanning identity."
BOTH_UNLISTED = f"Cannot evaluate the WAF policy association of the Application Gateways in subscription {AZURE_SUBSCRIPTION_DISPLAY}: they could not be listed completely, and the WAF policies associated with them could not be listed or read completely. Check the scan log for the errors, and verify that Microsoft.Network/applicationGateways/read and Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read (both included in Reader) are granted to the scanning identity."


def build_gateway(**settings) -> ApplicationGateway:
    return ApplicationGateway(
        id=GATEWAY_ID, name="agw1", location="westeurope", **settings
    )


def run_check(
    gateways,
    gateways_lookup_failed=(),
    policies_lookup_failed=(),
    policy_reads_failed=(),
):
    network_client = mock.MagicMock()
    network_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    network_client.application_gateways = gateways
    network_client.application_gateways_lookup_failed = set(gateways_lookup_failed)
    network_client.waf_policies_lookup_failed = set(policies_lookup_failed)
    network_client.waf_policy_reads_failed = set(policy_reads_failed)
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.network_client", new=network_client),
    ):
        from prowler.providers.azure.services.network.network_application_gateway_waf_enabled.network_application_gateway_waf_enabled import (
            network_application_gateway_waf_enabled,
        )

        return network_application_gateway_waf_enabled().execute()


def single(gateway):
    return run_check({AZURE_SUBSCRIPTION_ID: {gateway.id: gateway}})


def assert_gateway_finding(finding, status, status_extended):
    assert finding.status == status
    assert finding.status_extended == status_extended
    assert finding.subscription == AZURE_SUBSCRIPTION_ID
    assert finding.resource_id == GATEWAY_ID
    assert finding.resource_name == "agw1"
    assert finding.location == "westeurope"


def assert_subscription_finding(finding, status_extended):
    assert finding.status == "MANUAL"
    assert finding.status_extended == status_extended
    assert finding.subscription == AZURE_SUBSCRIPTION_ID
    assert finding.resource_id == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
    assert finding.resource_name == AZURE_SUBSCRIPTION_ID
    assert finding.location == "global"


class Test_network_application_gateway_waf_enabled:
    def test_no_gateways(self):
        assert run_check({}) == []
        assert run_check({AZURE_SUBSCRIPTION_ID: {}}) == []

    def test_enabled_waf_policy_associated(self):
        result = single(
            build_gateway(firewall_policy_id=POLICY_ID, firewall_policy_enabled=True)
        )
        assert len(result) == 1
        assert_gateway_finding(
            result[0], "PASS", f"{PREFIX} has an enabled WAF policy associated."
        )

    def test_disabled_waf_policy_associated(self):
        result = single(
            build_gateway(firewall_policy_id=POLICY_ID, firewall_policy_enabled=False)
        )
        assert len(result) == 1
        assert_gateway_finding(
            result[0],
            "FAIL",
            f"{PREFIX} has a WAF policy associated, but the policy is disabled.",
        )

    def test_waf_policy_state_unknown(self):
        result = single(build_gateway(firewall_policy_id=POLICY_ID))
        assert len(result) == 1
        assert_gateway_finding(
            result[0],
            "MANUAL",
            f"{PREFIX} has a WAF policy associated, but the state of that policy could not be determined. Check the scan log for the error.",
        )

    def test_legacy_waf_configuration(self):
        result = single(build_gateway(waf_configuration_enabled=True))
        assert len(result) == 1
        assert_gateway_finding(
            result[0],
            "FAIL",
            f"{PREFIX} uses the legacy WAF configuration instead of a WAF policy.",
        )

    def test_no_waf(self):
        result = single(build_gateway())
        assert len(result) == 1
        assert_gateway_finding(
            result[0], "FAIL", f"{PREFIX} has no gateway-level WAF policy associated."
        )

    def test_gateways_lookup_failed_is_manual(self):
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: {}}, gateways_lookup_failed={AZURE_SUBSCRIPTION_ID}
        )
        assert len(result) == 1
        assert_subscription_finding(result[0], GATEWAYS_UNLISTED)

    def test_partial_gateways_lookup_still_reports_listed_gateways(self):
        gateway = build_gateway(
            firewall_policy_id=POLICY_ID, firewall_policy_enabled=True
        )
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: {GATEWAY_ID: gateway}},
            gateways_lookup_failed={AZURE_SUBSCRIPTION_ID},
        )
        assert len(result) == 2
        assert_subscription_finding(result[0], GATEWAYS_UNLISTED)
        assert_gateway_finding(
            result[1], "PASS", f"{PREFIX} has an enabled WAF policy associated."
        )

    def test_policies_lookup_failed_reports_unknown_states_once(self):
        other_id = GATEWAY_ID.replace("agw1", "agw2")
        gateways = {
            GATEWAY_ID: build_gateway(firewall_policy_id=POLICY_ID),
            other_id: ApplicationGateway(
                id=other_id,
                name="agw2",
                location="westeurope",
                firewall_policy_id=POLICY_ID,
            ),
        }
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: gateways},
            policies_lookup_failed={AZURE_SUBSCRIPTION_ID},
        )
        assert len(result) == 1
        assert_subscription_finding(result[0], POLICIES_UNLISTED)

    def test_policies_lookup_failed_keeps_gateways_with_known_states(self):
        other_id = GATEWAY_ID.replace("agw1", "agw2")
        gateways = {
            GATEWAY_ID: build_gateway(
                firewall_policy_id=POLICY_ID, firewall_policy_enabled=False
            ),
            other_id: ApplicationGateway(
                id=other_id,
                name="agw2",
                location="westeurope",
                firewall_policy_id=POLICY_ID.replace("waf1", "waf2"),
            ),
        }
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: gateways},
            policies_lookup_failed={AZURE_SUBSCRIPTION_ID},
        )
        assert len(result) == 2
        assert_subscription_finding(result[0], POLICIES_UNLISTED)
        assert_gateway_finding(
            result[1],
            "FAIL",
            f"{PREFIX} has a WAF policy associated, but the policy is disabled.",
        )

    def test_policies_lookup_failed_without_unknown_states_adds_nothing(self):
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    GATEWAY_ID: build_gateway(
                        firewall_policy_id=POLICY_ID, firewall_policy_enabled=True
                    )
                }
            },
            policies_lookup_failed={AZURE_SUBSCRIPTION_ID},
        )
        assert len(result) == 1
        assert_gateway_finding(
            result[0], "PASS", f"{PREFIX} has an enabled WAF policy associated."
        )

    def test_failed_policy_read_reports_unknown_states_once(self):
        other_id = GATEWAY_ID.replace("agw1", "agw2")
        gateways = {
            GATEWAY_ID: build_gateway(firewall_policy_id=POLICY_ID),
            other_id: ApplicationGateway(
                id=other_id,
                name="agw2",
                location="westeurope",
                firewall_policy_id=POLICY_ID,
            ),
        }
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: gateways},
            policy_reads_failed={POLICY_ID.casefold()},
        )
        assert len(result) == 1
        assert_subscription_finding(result[0], POLICIES_UNLISTED)

    def test_failed_policy_read_keeps_gateway_with_missing_policy(self):
        other_id = GATEWAY_ID.replace("agw1", "agw2")
        gateways = {
            GATEWAY_ID: build_gateway(firewall_policy_id=POLICY_ID),
            other_id: ApplicationGateway(
                id=other_id,
                name="agw2",
                location="westeurope",
                firewall_policy_id=POLICY_ID.replace("waf1", "waf2"),
            ),
        }
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: gateways},
            policy_reads_failed={POLICY_ID.upper().casefold()},
        )
        assert len(result) == 2
        assert_subscription_finding(result[0], POLICIES_UNLISTED)
        assert result[1].resource_id == other_id
        assert result[1].status == "MANUAL"
        assert result[1].status_extended == (
            f"Application Gateway agw2 in subscription {AZURE_SUBSCRIPTION_DISPLAY} has a WAF policy associated, but the state of that policy could not be determined. Check the scan log for the error."
        )

    def test_unlisted_gateways_and_policies_give_one_finding(self):
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    GATEWAY_ID: build_gateway(firewall_policy_id=POLICY_ID)
                }
            },
            gateways_lookup_failed={AZURE_SUBSCRIPTION_ID},
            policies_lookup_failed={AZURE_SUBSCRIPTION_ID},
        )
        assert len(result) == 1
        assert_subscription_finding(result[0], BOTH_UNLISTED)
