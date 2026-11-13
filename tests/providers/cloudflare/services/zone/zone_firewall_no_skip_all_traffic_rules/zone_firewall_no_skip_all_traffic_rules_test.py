from unittest import mock

import pytest

from prowler.providers.cloudflare.services.zone.zone_rules_expressions import (
    matches_all_traffic,
)
from prowler.providers.cloudflare.services.zone.zone_service import (
    CloudflareFirewallRule,
    CloudflareZone,
    CloudflareZoneSettings,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ZONE_ID,
    ZONE_NAME,
    set_mocked_cloudflare_provider,
)

CHECK = "zone_firewall_no_skip_all_traffic_rules"
MODULE = f"prowler.providers.cloudflare.services.zone.{CHECK}.{CHECK}"


def _run(rules, failed_zones=None):
    zone_client = mock.MagicMock()
    zone_client.firewall_rules_failed_zones = set(failed_zones or [])
    zone_client.zones = (
        {}
        if rules is None
        else {
            ZONE_ID: CloudflareZone(
                id=ZONE_ID,
                name=ZONE_NAME,
                status="active",
                paused=False,
                settings=CloudflareZoneSettings(),
                firewall_rules=rules,
            )
        }
    )
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_cloudflare_provider(),
        ),
        mock.patch(f"{MODULE}.zone_client", new=zone_client),
    ):
        from prowler.providers.cloudflare.services.zone.zone_firewall_no_skip_all_traffic_rules.zone_firewall_no_skip_all_traffic_rules import (
            zone_firewall_no_skip_all_traffic_rules,
        )

        return zone_firewall_no_skip_all_traffic_rules().execute()


def _rule(
    expression,
    action="skip",
    enabled=True,
    phase="http_request_firewall_custom",
    description="Bypass",
    skip_targets=None,
):
    return CloudflareFirewallRule(
        skip_targets=skip_targets or [],
        id="rule-1",
        name=description,
        description=description,
        action=action,
        enabled=enabled,
        expression=expression,
        phase=phase,
    )


@pytest.mark.parametrize(
    "expression",
    [
        "true",
        "(true)",
        "  ( TRUE )  ",
        "not false",
        # every HTTPS request (all traffic with Always Use HTTPS)
        "ssl",
        "(ssl)",
        'http.request.uri.path wildcard "*"',
        'http.request.full_uri wildcard "*"',
        'http.host matches ".*"',
        'http.request.uri.path matches "^.*$"',
        'http.request.uri.path starts_with "/"',
        'http.request.uri.path contains "/"',
        "ip.src in {0.0.0.0/0 ::/0}",
        "(ip.src in {0.0.0.0/0})",
        "",
        None,
        "true or ip.src in {192.0.2.0/24}",
        "ip.src in {192.0.2.0/24} or true",
        'http.host eq "a.example.com" || (true)',
        'true or http.host eq "a.example.com" and ip.src in {192.0.2.0/24}',
        '(http.host eq "a.example.com") or (ssl)',
    ],
)
def test_matches_all_traffic(expression):
    assert matches_all_traffic(expression) is True


@pytest.mark.parametrize(
    "expression",
    [
        'http.request.uri.path eq "/health"',
        "ip.src in $trusted_monitoring",
        "ip.src in {192.0.2.0/24}",
        'http.host eq "api.example.com"',
        '(http.request.uri.path eq "/a") or (http.request.uri.path eq "/b")',
        'http.request.uri.path wildcard "/static/*"',
        "true and ip.src in {192.0.2.0/24}",
        "not ssl",
        'ssl and http.request.uri.path eq "/health"',
        '(true or ip.src in {192.0.2.0/24}) and http.host eq "a.example.com"',
        'http.host eq "true or x" or http.host eq "b.example.com"',
    ],
)
def test_does_not_match_all_traffic(expression):
    assert matches_all_traffic(expression) is False


class Test_zone_firewall_no_skip_all_traffic_rules:
    def test_no_zones(self):
        assert _run(None) == []

    def test_no_rules_pass(self):
        result = _run([])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == ZONE_ID
        assert result[0].resource_name == ZONE_NAME
        assert (
            result[0].status_extended
            == f"Zone {ZONE_NAME} has no firewall skip rules that match all traffic."
        )

    def test_scoped_skip_rule_pass(self):
        result = _run([_rule('http.request.uri.path eq "/health"')])
        assert result[0].status == "PASS"

    def test_skip_all_traffic_fail(self):
        result = _run([_rule("true", description="Debug bypass")])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Zone {ZONE_NAME} has firewall skip rules that match all traffic and bypass security features: Debug bypass (http_request_firewall_custom)."
        )

    def test_skip_managed_waf_for_all_https_traffic_fail(self):
        # mirrors a real rule: skips the whole managed WAF phase for every HTTPS request
        result = _run(
            [
                _rule(
                    "(ssl)",
                    description="test_waf",
                    skip_targets=["http_request_firewall_managed"],
                )
            ]
        )
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            f"Zone {ZONE_NAME} has firewall skip rules that match all traffic and bypass "
            "security features: test_waf (http_request_firewall_custom, skips "
            "http_request_firewall_managed)."
        )

    def test_managed_rule_exception_for_all_traffic_fail(self):
        result = _run(
            [_rule("(true)", phase="http_request_firewall_managed", description="")]
        )
        assert result[0].status == "FAIL"
        assert "rule-1 (http_request_firewall_managed)" in result[0].status_extended

    def test_disabled_skip_rule_pass(self):
        assert _run([_rule("true", enabled=False)])[0].status == "PASS"

    def test_blocking_rule_matching_all_traffic_pass(self):
        # matching everything is fine for non-skip actions
        assert _run([_rule("true", action="managed_challenge")])[0].status == "PASS"

    def test_rules_not_retrieved_manual(self):
        result = _run([], failed_zones=[ZONE_ID])
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"Cannot evaluate firewall skip rules for zone {ZONE_NAME}: its rulesets "
            "could not be retrieved. Verify that the scanning token has the Zone WAF "
            "Read permission."
        )

    def test_partial_rules_with_bypass_still_fail(self):
        result = _run([_rule("true")], failed_zones=[ZONE_ID])
        assert result[0].status == "FAIL"
