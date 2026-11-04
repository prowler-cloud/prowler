from prowler.providers.cloudflare.services.zone.zone_service import (
    CloudflareZone,
    CloudflareZoneSettings,
    StrictTransportSecurity,
)
from tests.providers.cloudflare.cloudflare_fixtures import ZONE_ID, ZONE_NAME


class TestZoneService:
    def test_cloudflare_zone_model(self):
        zone = CloudflareZone(
            id=ZONE_ID,
            name=ZONE_NAME,
            status="active",
            paused=False,
            plan="Free",
        )

        assert zone.id == ZONE_ID
        assert zone.name == ZONE_NAME
        assert zone.status == "active"
        assert zone.paused is False
        assert zone.plan == "Free"

    def test_cloudflare_zone_settings_model(self):
        settings = CloudflareZoneSettings(
            always_use_https="on",
            min_tls_version="1.2",
            ssl_encryption_mode="full",
            tls_1_3="on",
            automatic_https_rewrites="on",
            universal_ssl="on",
            waf="on",
            security_level="high",
        )

        assert settings.always_use_https == "on"
        assert settings.min_tls_version == "1.2"
        assert settings.ssl_encryption_mode == "full"
        assert settings.tls_1_3 == "on"

    def test_strict_transport_security_model(self):
        sts = StrictTransportSecurity(
            enabled=True,
            max_age=31536000,
            include_subdomains=True,
            preload=True,
            nosniff=True,
        )

        assert sts.enabled is True
        assert sts.max_age == 31536000
        assert sts.include_subdomains is True
        assert sts.preload is True
        assert sts.nosniff is True

    def test_strict_transport_security_defaults(self):
        sts = StrictTransportSecurity()

        assert sts.enabled is False
        assert sts.max_age == 0
        assert sts.include_subdomains is False
        assert sts.preload is False
        assert sts.nosniff is False


class TestSkipTargets:
    def test_skip_targets_describe_bypassed_features(self):
        from types import SimpleNamespace

        from prowler.providers.cloudflare.services.zone.zone_service import (
            _skip_targets,
        )

        assert _skip_targets(None) == []
        assert _skip_targets(
            SimpleNamespace(
                phases=["http_request_firewall_managed", "http_ratelimit"],
                products=["bic"],
                ruleset="current",
                rulesets=["a", "b"],
                rules={"a": ["r1"]},
            )
        ) == [
            "http_request_firewall_managed",
            "http_ratelimit",
            "bic",
            "remaining custom rules",
            "2 managed ruleset(s)",
            "specific managed rules",
        ]


class TestZoneFirewallRules:
    def _zone_service(self, client):
        from prowler.providers.cloudflare.services.zone.zone_service import Zone

        service = Zone.__new__(Zone)
        service.client = client
        service.firewall_rules_failed_zones = set()
        return service

    def _zone(self):
        return CloudflareZone(
            id=ZONE_ID,
            name=ZONE_NAME,
            status="active",
            paused=False,
            settings=CloudflareZoneSettings(),
        )

    def test_ruleset_listing_failure_marks_zone_failed(self):
        from unittest import mock

        client = mock.MagicMock()
        client.rulesets.list.side_effect = Exception("forbidden")
        service = self._zone_service(client)
        zone = self._zone()

        service._get_zone_firewall_rules(zone)

        assert zone.firewall_rules == []
        assert service.firewall_rules_failed_zones == {ZONE_ID}

    def test_ruleset_detail_failure_marks_zone_failed(self):
        from types import SimpleNamespace
        from unittest import mock

        client = mock.MagicMock()
        client.rulesets.list.return_value = [
            SimpleNamespace(id="rs-1", phase="http_request_firewall_custom")
        ]
        client.rulesets.get.side_effect = Exception("forbidden")
        service = self._zone_service(client)
        zone = self._zone()

        service._get_zone_firewall_rules(zone)

        assert service.firewall_rules_failed_zones == {ZONE_ID}

    def test_successful_retrieval_does_not_mark_zone_failed(self):
        from types import SimpleNamespace
        from unittest import mock

        client = mock.MagicMock()
        client.rulesets.list.return_value = [
            SimpleNamespace(id="rs-1", phase="http_request_firewall_custom")
        ]
        client.rulesets.get.return_value = SimpleNamespace(
            rules=[
                SimpleNamespace(
                    id="rule-1",
                    description="Bypass",
                    action="skip",
                    enabled=True,
                    expression="true",
                    action_parameters=None,
                )
            ]
        )
        service = self._zone_service(client)
        zone = self._zone()

        service._get_zone_firewall_rules(zone)

        assert [rule.id for rule in zone.firewall_rules] == ["rule-1"]
        assert service.firewall_rules_failed_zones == set()
