from unittest import mock

import pytest

from prowler.providers.azure.services.network.network_service import (
    ApplicationGateway,
    SslPolicy,
    SslProfile,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "network_application_gateway_minimum_tls_version_12"
CHECK_PATH = f"prowler.providers.azure.services.network.{CHECK}.{CHECK}"
# Patching the check's client imports network_client, which builds Network
# against the global provider at module level. Stubbing the class first keeps
# that import from reaching Azure when this file runs on its own.
SERVICE_MODULE = "prowler.providers.azure.services.network.network_service"
GATEWAY_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Network/applicationGateways/agw1"
PREFIX = f"Application Gateway agw1 in subscription {AZURE_SUBSCRIPTION_DISPLAY}"
DEFAULT_POLICY = "AppGwSslPolicy20220101"
UNKNOWN_ONE = (
    f"{PREFIX} has an SSL policy whose minimum TLS version could not be determined"
)
NO_POLICY = f"{PREFIX} sets no SSL policy and Azure reports no default policy for it, so its minimum TLS version could not be determined. Set an explicit SSL policy, such as AppGwSslPolicy20220101."
UNLISTED = f"Cannot evaluate the minimum TLS version of the Application Gateways in subscription {AZURE_SUBSCRIPTION_DISPLAY}: they could not be listed completely. Check the scan log for the error, and verify that Microsoft.Network/applicationGateways/read (included in Reader) is granted to the scanning identity."


def run_check(gateways, lookup_failed=()):
    network_client = mock.MagicMock()
    network_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    network_client.application_gateways = gateways
    network_client.application_gateways_lookup_failed = set(lookup_failed)
    with (
        mock.patch(f"{SERVICE_MODULE}.Network", new=mock.MagicMock()),
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.network_client", new=network_client),
    ):
        from prowler.providers.azure.services.network.network_application_gateway_minimum_tls_version_12.network_application_gateway_minimum_tls_version_12 import (
            network_application_gateway_minimum_tls_version_12,
        )

        return network_application_gateway_minimum_tls_version_12().execute()


def build_gateway(**settings):
    return ApplicationGateway(
        id=GATEWAY_ID, name="agw1", location="westeurope", **settings
    )


def assert_single_finding(result, status, status_extended):
    assert len(result) == 1
    assert_gateway_finding(result[0], status, status_extended)


def assert_gateway_finding(finding, status, status_extended):
    assert finding.status == status
    assert finding.status_extended == status_extended
    assert finding.subscription == AZURE_SUBSCRIPTION_ID
    assert finding.resource_id == GATEWAY_ID
    assert finding.resource_name == "agw1"
    assert finding.location == "westeurope"


def single(**settings):
    return run_check({AZURE_SUBSCRIPTION_ID: {GATEWAY_ID: build_gateway(**settings)}})


def custom(**settings):
    return SslPolicy(policy_type="Custom", **settings)


def predefined(policy_name):
    return SslPolicy(policy_type="Predefined", policy_name=policy_name)


class Test_network_application_gateway_minimum_tls_version_12:
    def test_no_gateways(self):
        assert run_check({}) == []
        assert run_check({AZURE_SUBSCRIPTION_ID: {}}) == []

    def test_default_policy_pass(self):
        assert_single_finding(
            single(default_ssl_policy_name=DEFAULT_POLICY),
            "PASS",
            f"{PREFIX} requires TLS 1.2 or higher: default SSL policy {DEFAULT_POLICY} (TLSv1_2).",
        )

    def test_weak_default_policy_fail(self):
        assert_single_finding(
            single(default_ssl_policy_name="AppGwSslPolicy20150501"),
            "FAIL",
            f"{PREFIX} has a minimum TLS version below 1.2: default SSL policy AppGwSslPolicy20150501 (TLSv1_0).",
        )

    def test_unknown_default_policy_manual(self):
        assert_single_finding(
            single(default_ssl_policy_name="AppGwSslPolicy20990101"),
            "MANUAL",
            f"{UNKNOWN_ONE}: default SSL policy AppGwSslPolicy20990101.",
        )

    def test_old_predefined_policy_fail(self):
        assert_single_finding(
            single(ssl_policy=predefined("AppGwSslPolicy20150501")),
            "FAIL",
            f"{PREFIX} has a minimum TLS version below 1.2: gateway SSL policy AppGwSslPolicy20150501 (TLSv1_0).",
        )

    def test_explicit_policy_takes_precedence_over_default(self):
        assert_single_finding(
            single(
                ssl_policy=predefined("AppGwSslPolicy20170401"),
                default_ssl_policy_name=DEFAULT_POLICY,
            ),
            "FAIL",
            f"{PREFIX} has a minimum TLS version below 1.2: gateway SSL policy AppGwSslPolicy20170401 (TLSv1_1).",
        )

    def test_custom_v2_tls13_pass(self):
        assert_single_finding(
            single(
                ssl_policy=SslPolicy(
                    policy_type="CustomV2", min_protocol_version="TLSv1_3"
                )
            ),
            "PASS",
            f"{PREFIX} requires TLS 1.2 or higher: gateway SSL policy (TLSv1_3).",
        )

    @pytest.mark.parametrize(
        "ssl_policy, status, status_extended",
        [
            (
                SslPolicy(policy_type="customv2", min_protocol_version="tlsv1_2"),
                "PASS",
                f"{PREFIX} requires TLS 1.2 or higher: gateway SSL policy (TLSv1_2).",
            ),
            (
                SslPolicy(
                    policy_type="predefined", policy_name="appgwsslpolicy20150501"
                ),
                "FAIL",
                f"{PREFIX} has a minimum TLS version below 1.2: gateway SSL policy appgwsslpolicy20150501 (TLSv1_0).",
            ),
            (
                SslPolicy(policy_name="APPGWSSLPOLICY20220101S"),
                "PASS",
                f"{PREFIX} requires TLS 1.2 or higher: gateway SSL policy APPGWSSLPOLICY20220101S (TLSv1_2).",
            ),
        ],
        ids=["custom_v2_lower_case", "predefined_lower_case", "name_upper_case"],
    )
    def test_values_are_matched_without_regard_to_case(
        self, ssl_policy, status, status_extended
    ):
        assert_single_finding(single(ssl_policy=ssl_policy), status, status_extended)

    def test_policy_name_without_type_pass(self):
        assert_single_finding(
            single(ssl_policy=SslPolicy(policy_name="AppGwSslPolicy20170401S")),
            "PASS",
            f"{PREFIX} requires TLS 1.2 or higher: gateway SSL policy AppGwSslPolicy20170401S (TLSv1_2).",
        )

    def test_custom_policy_with_disabled_protocols_fail(self):
        assert_single_finding(
            single(ssl_policy=custom(disabled_ssl_protocols=["TLSv1_0"])),
            "FAIL",
            f"{PREFIX} has a minimum TLS version below 1.2: gateway SSL policy (TLSv1_1).",
        )

    def test_custom_policy_disabling_tls10_and_tls11_pass(self):
        assert_single_finding(
            single(ssl_policy=custom(disabled_ssl_protocols=["tlsv1_0", "TLSv1_1"])),
            "PASS",
            f"{PREFIX} requires TLS 1.2 or higher: gateway SSL policy (TLSv1_2).",
        )

    def test_weak_listener_ssl_profile_fail(self):
        assert_single_finding(
            single(
                default_ssl_policy_name=DEFAULT_POLICY,
                listener_ssl_profiles=[
                    SslProfile(
                        name="weak", ssl_policy=custom(min_protocol_version="TLSv1_1")
                    )
                ],
            ),
            "FAIL",
            f"{PREFIX} has a minimum TLS version below 1.2: SSL profile weak (TLSv1_1).",
        )

    def test_weak_predefined_profile_names_its_policy(self):
        assert_single_finding(
            single(
                ssl_policy=predefined(DEFAULT_POLICY),
                listener_ssl_profiles=[
                    SslProfile(
                        name="legacy", ssl_policy=predefined("AppGwSslPolicy20170401")
                    )
                ],
            ),
            "FAIL",
            f"{PREFIX} has a minimum TLS version below 1.2: SSL profile legacy with AppGwSslPolicy20170401 (TLSv1_1).",
        )

    def test_profile_without_own_policy_uses_gateway_policy(self):
        assert_single_finding(
            single(
                default_ssl_policy_name=DEFAULT_POLICY,
                listener_ssl_profiles=[SslProfile(name="inherits")],
            ),
            "PASS",
            f"{PREFIX} requires TLS 1.2 or higher: default SSL policy {DEFAULT_POLICY} (TLSv1_2).",
        )

    def test_empty_profile_policy_uses_gateway_policy(self):
        assert_single_finding(
            single(
                ssl_policy=SslPolicy(
                    policy_type="CustomV2", min_protocol_version="TLSv1_2"
                ),
                default_ssl_policy_name="AppGwSslPolicy20150501",
                listener_ssl_profiles=[
                    SslProfile(name="empty", ssl_policy=SslPolicy())
                ],
            ),
            "PASS",
            f"{PREFIX} requires TLS 1.2 or higher: gateway SSL policy (TLSv1_2).",
        )

    def test_empty_gateway_policy_uses_default_policy(self):
        assert_single_finding(
            single(
                ssl_policy=SslPolicy(),
                default_ssl_policy_name="AppGwSslPolicy20150501",
            ),
            "FAIL",
            f"{PREFIX} has a minimum TLS version below 1.2: default SSL policy AppGwSslPolicy20150501 (TLSv1_0).",
        )

    def test_pass_names_gateway_policy_and_profiles(self):
        assert_single_finding(
            single(
                ssl_policy=predefined("AppGwSslPolicy20220101S"),
                listener_ssl_profiles=[
                    SslProfile(
                        name="strict",
                        ssl_policy=SslPolicy(
                            policy_type="CustomV2", min_protocol_version="TLSv1_3"
                        ),
                    )
                ],
            ),
            "PASS",
            f"{PREFIX} requires TLS 1.2 or higher: gateway SSL policy AppGwSslPolicy20220101S (TLSv1_2), SSL profile strict (TLSv1_3).",
        )

    def test_no_policy_and_no_default_manual(self):
        assert_single_finding(single(), "MANUAL", NO_POLICY)

    def test_empty_policy_and_no_default_manual(self):
        assert_single_finding(single(ssl_policy=SslPolicy()), "MANUAL", NO_POLICY)

    def test_no_policy_and_unknown_profile_manual(self):
        assert_single_finding(
            single(
                listener_ssl_profiles=[SslProfile(name="p1", ssl_policy=custom())],
            ),
            "MANUAL",
            f"{PREFIX} has SSL policies whose minimum TLS version could not be determined: gateway SSL policy (none set and no default reported), SSL profile p1.",
        )

    def test_unknown_predefined_policy_manual(self):
        assert_single_finding(
            single(ssl_policy=predefined("AppGwSslPolicy2099")),
            "MANUAL",
            f"{UNKNOWN_ONE}: gateway SSL policy AppGwSslPolicy2099.",
        )

    def test_unknown_tls_version_manual(self):
        assert_single_finding(
            single(
                ssl_policy=SslPolicy(
                    policy_type="CustomV2", min_protocol_version="TLSv1_4"
                )
            ),
            "MANUAL",
            f"{UNKNOWN_ONE}: gateway SSL policy.",
        )

    def test_custom_policy_without_versions_manual(self):
        assert_single_finding(
            single(ssl_policy=custom()), "MANUAL", f"{UNKNOWN_ONE}: gateway SSL policy."
        )

    def test_custom_policy_disabling_every_version_manual(self):
        assert_single_finding(
            single(
                ssl_policy=custom(
                    disabled_ssl_protocols=["TLSv1_0", "TLSv1_1", "TLSv1_2", "TLSv1_3"]
                )
            ),
            "MANUAL",
            f"{UNKNOWN_ONE}: gateway SSL policy.",
        )

    def test_weak_and_unknown_policies_fail_and_name_both(self):
        assert_single_finding(
            single(
                ssl_policy=predefined("AppGwSslPolicy20170401"),
                listener_ssl_profiles=[
                    SslProfile(
                        name="unknown", ssl_policy=predefined("AppGwSslPolicy2099")
                    )
                ],
            ),
            "FAIL",
            f"{PREFIX} has a minimum TLS version below 1.2: gateway SSL policy AppGwSslPolicy20170401 (TLSv1_1). The minimum TLS version of SSL profile unknown with AppGwSslPolicy2099 could not be determined.",
        )

    def test_gateways_lookup_failed_is_manual(self):
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: {}}, lookup_failed={AZURE_SUBSCRIPTION_ID}
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == UNLISTED
        assert result[0].resource_id == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
        assert result[0].resource_name == AZURE_SUBSCRIPTION_ID
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID
        assert result[0].location == "global"

    def test_partial_lookup_still_reports_listed_gateways(self):
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    GATEWAY_ID: build_gateway(default_ssl_policy_name=DEFAULT_POLICY)
                }
            },
            lookup_failed={AZURE_SUBSCRIPTION_ID},
        )
        assert len(result) == 2
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == UNLISTED
        assert result[0].resource_id == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
        assert_gateway_finding(
            result[1],
            "PASS",
            f"{PREFIX} requires TLS 1.2 or higher: default SSL policy {DEFAULT_POLICY} (TLSv1_2).",
        )
