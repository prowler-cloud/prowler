from unittest import mock

from prowler.providers.cloudflare.lib.read_errors import split_unreadable_zones
from prowler.providers.cloudflare.models import CloudflareAccount
from prowler.providers.cloudflare.services.zone.zone_service import CloudflareZone

ACCOUNT = CloudflareAccount(id="account-1", name="Main Account")
OTHER_ACCOUNT = CloudflareAccount(id="account-2", name="Other Account")
FORBIDDEN = "PermissionDeniedError"


def _zone(zone_id, account=ACCOUNT, error=None):
    return CloudflareZone(
        id=zone_id,
        name=f"{zone_id}.com",
        account=account,
        read_errors={"ssl": error} if error else {},
    )


def _split(zones):
    check = mock.MagicMock()
    check.metadata.return_value = {}
    with mock.patch(
        "prowler.providers.cloudflare.lib.read_errors.CheckReportCloudflare"
    ) as report_cls:
        report_cls.side_effect = lambda metadata, resource: mock.MagicMock(
            resource=resource
        )
        return split_unreadable_zones(
            check,
            zones,
            read_error=lambda zone: zone.read_errors.get("ssl"),
            requirement="the SSL/TLS encryption mode",
            permission="Zone Settings Read",
        )


class TestSplitUnreadableZones:
    def test_readable_zones_produce_no_manual_findings(self):
        zones = [_zone("a"), _zone("b")]

        findings, readable = _split(zones)

        assert findings == []
        assert readable == zones

    def test_all_zones_of_an_account_failing_alike_yield_one_account_finding(self):
        zones = [_zone("a", error=FORBIDDEN), _zone("b", error=FORBIDDEN)]

        findings, readable = _split(zones)

        assert readable == []
        assert len(findings) == 1
        assert findings[0].status == "MANUAL"
        assert findings[0].resource.id == "account-1"
        assert findings[0].resource.account_id == "account-1"
        assert findings[0].resource.zone_name == "global"
        assert findings[0].status_extended == (
            "Cannot evaluate the SSL/TLS encryption mode for any of the 2 zones "
            "in account Main Account: the API token is missing the Zone Settings "
            "Read permission."
        )

    def test_partially_failing_account_yields_one_finding_per_failing_zone(self):
        failing = _zone("a", error=FORBIDDEN)
        healthy = _zone("b")

        findings, readable = _split([failing, healthy])

        assert readable == [healthy]
        assert len(findings) == 1
        assert findings[0].resource is failing
        assert findings[0].status_extended == (
            "Cannot evaluate the SSL/TLS encryption mode for zone a.com: the API "
            "token is missing the Zone Settings Read permission."
        )

    def test_single_zone_account_keeps_the_zone_as_resource(self):
        zone = _zone("a", error=FORBIDDEN)

        findings, _ = _split([zone])

        assert findings[0].resource is zone

    def test_accounts_are_grouped_independently(self):
        zones = [
            _zone("a", error=FORBIDDEN),
            _zone("b", error=FORBIDDEN),
            _zone("c", account=OTHER_ACCOUNT, error=FORBIDDEN),
            _zone("d", account=OTHER_ACCOUNT),
        ]

        findings, readable = _split(zones)

        assert [f.resource.id for f in findings] == ["account-1", "c"]
        assert [z.id for z in readable] == ["d"]

    def test_non_permission_error_is_reported_by_its_type(self):
        zone = _zone("a", error="APITimeoutError")

        findings, _ = _split([zone])

        assert findings[0].status_extended == (
            "Cannot evaluate the SSL/TLS encryption mode for zone a.com: the "
            "Cloudflare API returned APITimeoutError."
        )
