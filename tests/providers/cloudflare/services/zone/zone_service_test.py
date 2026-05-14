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
