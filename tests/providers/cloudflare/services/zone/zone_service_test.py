from types import SimpleNamespace

import httpx
from cloudflare import NotFoundError, PermissionDeniedError

from prowler.providers.cloudflare.services.zone.zone_service import (
    ZONE_SETTING_IDS,
    CloudflareZone,
    CloudflareZoneSettings,
    StrictTransportSecurity,
    Zone,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
    ZONE_ID,
    ZONE_NAME,
    set_mocked_cloudflare_provider,
)


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


def _permission_denied():
    request = httpx.Request("GET", "https://api.cloudflare.com/client/v4/zones")
    return PermissionDeniedError(
        "Authentication error",
        response=httpx.Response(403, request=request),
        body=None,
    )


def _not_found():
    request = httpx.Request("GET", "https://api.cloudflare.com/client/v4/zones")
    return NotFoundError(
        "Not found", response=httpx.Response(404, request=request), body=None
    )


def _provider_with_one_zone():
    provider = set_mocked_cloudflare_provider()
    provider.session.client.zones.list.return_value = [
        SimpleNamespace(
            id=ZONE_ID,
            name=ZONE_NAME,
            status="active",
            paused=False,
            account=SimpleNamespace(id=ACCOUNT_ID, name="Test Account", type=None),
            plan=None,
        )
    ]
    return provider


class TestZoneServiceReadErrors:
    def test_forbidden_reads_are_recorded_per_zone(self):
        provider = _provider_with_one_zone()
        client = provider.session.client
        client.zones.settings.get.side_effect = _permission_denied()
        client.dns.dnssec.get.side_effect = _permission_denied()
        client.ssl.universal.settings.get.side_effect = _permission_denied()
        client.bot_management.get.side_effect = _permission_denied()
        client.rulesets.list.side_effect = _permission_denied()

        zone = Zone(provider).zones[ZONE_ID]

        assert set(zone.read_errors) == {
            *ZONE_SETTING_IDS,
            "dnssec",
            "universal_ssl",
            "bot_management",
            "rulesets",
        }
        assert zone.read_errors["ssl"] == "PermissionDeniedError"

    def test_successful_reads_record_no_errors(self):
        provider = _provider_with_one_zone()
        client = provider.session.client
        client.zones.settings.get.side_effect = lambda setting_id, zone_id: (
            SimpleNamespace(value=1800 if setting_id == "challenge_ttl" else "on")
        )
        client.dns.dnssec.get.return_value = SimpleNamespace(status="active")
        client.ssl.universal.settings.get.return_value = SimpleNamespace(enabled=True)
        client.bot_management.get.return_value = SimpleNamespace(fight_mode=True)
        client.rulesets.list.return_value = []

        zone = Zone(provider).zones[ZONE_ID]

        assert zone.read_errors == {}
        assert zone.settings.ssl_encryption_mode == "on"

    def test_unexpected_setting_value_only_loses_that_setting(self):
        provider = _provider_with_one_zone()
        client = provider.session.client
        client.zones.settings.get.side_effect = lambda setting_id, zone_id: (
            SimpleNamespace(value=True)
            if setting_id == "always_use_https"
            else SimpleNamespace(value="strict")
        )
        client.rulesets.list.return_value = []

        zone = Zone(provider).zones[ZONE_ID]

        assert zone.read_errors["always_use_https"] == "UnexpectedValue"
        assert "ssl" not in zone.read_errors
        assert zone.settings.ssl_encryption_mode == "strict"

    def test_forbidden_ruleset_detail_is_recorded(self):
        provider = _provider_with_one_zone()
        client = provider.session.client
        client.zones.settings.get.return_value = SimpleNamespace(value="on")
        client.rulesets.list.return_value = [
            SimpleNamespace(
                id="ruleset-1", name="default", kind="zone", phase="http_ratelimit"
            )
        ]
        client.rulesets.get.side_effect = _permission_denied()

        zone = Zone(provider).zones[ZONE_ID]

        assert zone.rate_limit_rules == []
        assert zone.read_errors["rulesets"] == "PermissionDeniedError"

    def test_not_found_is_not_a_read_error(self):
        provider = _provider_with_one_zone()
        client = provider.session.client
        client.zones.settings.get.side_effect = _not_found()
        client.dns.dnssec.get.side_effect = _not_found()
        client.rulesets.list.return_value = []

        zone = Zone(provider).zones[ZONE_ID]

        assert "ssl" not in zone.read_errors
        assert "dnssec" not in zone.read_errors
        assert zone.settings.ssl_encryption_mode is None
