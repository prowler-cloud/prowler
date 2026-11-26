from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_dns_public_zones_exposed:
    def test_no_public_zones(self):
        dns_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.dns.dns_public_zones_exposed.dns_public_zones_exposed.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.dns.dns_public_zones_exposed.dns_public_zones_exposed import (
                dns_public_zones_exposed,
            )

            dns_client.public_zones = []
            dns_client.audited_account = "123456789012"

            check = dns_public_zones_exposed()
            findings = check.execute()
            assert findings == []

    def test_public_zones_exposed(self):
        dns_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.dns.dns_public_zones_exposed.dns_public_zones_exposed.dns_client",
                new=dns_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.dns.dns_service import (
                PublicZone,
            )
            from prowler.providers.huaweicloud.services.dns.dns_public_zones_exposed.dns_public_zones_exposed import (
                dns_public_zones_exposed,
            )

            dns_client.public_zones = [
                PublicZone(
                    id="zone-001",
                    name="example.com.",
                    record_num=5,
                    status="ACTIVE",
                    region="la-south-2",
                ),
                PublicZone(
                    id="zone-002",
                    name="internal.example.com.",
                    record_num=10,
                    status="ACTIVE",
                    region="la-south-2",
                ),
            ]
            dns_client.audited_account = "123456789012"

            check = dns_public_zones_exposed()
            findings = check.execute()
            assert len(findings) == 2
            assert findings[0].status == "FAIL"
            assert "zone-001" in findings[0].resource_id
            assert "example.com." in findings[0].status_extended
            assert findings[1].status == "FAIL"
            assert "zone-002" in findings[1].resource_id
            assert "internal.example.com." in findings[1].status_extended
