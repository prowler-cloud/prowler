from re import search
from unittest import mock

GCP_PROJECT_ID = "123456789012"


class Test_dns_rsasha1_in_use_to_zone_sign_in_dnssec:
    def test_dns_no_managed_zones(self):
        dns_client = mock.MagicMock
        dns_client.managed_zones = []

        with mock.patch(
            "prowler.providers.gcp.services.dns.dns_rsasha1_in_use_to_zone_sign_in_dnssec.dns_rsasha1_in_use_to_zone_sign_in_dnssec.dns_client",
            new=dns_client,
        ):
            from prowler.providers.gcp.services.dns.dns_rsasha1_in_use_to_zone_sign_in_dnssec.dns_rsasha1_in_use_to_zone_sign_in_dnssec import (
                dns_rsasha1_in_use_to_zone_sign_in_dnssec,
            )

            check = dns_rsasha1_in_use_to_zone_sign_in_dnssec()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_managed_zone(self):
        from prowler.providers.gcp.services.dns.dns_service import ManagedZone

        managed_zone = ManagedZone(
            name="test",
            id="1234567890",
            dnssec=True,
            key_specs=[
                {
                    "keyType": "keySigning",
                    "algorithm": "rsasha1",
                    "keyLength": 2048,
                    "kind": "dns#dnsKeySpec",
                },
                {
                    "keyType": "zoneSigning",
                    "algorithm": "rsasha256",
                    "keyLength": 1024,
                    "kind": "dns#dnsKeySpec",
                },
            ],
            project_id=GCP_PROJECT_ID,
        )

        dns_client = mock.MagicMock
        dns_client.project_ids = [GCP_PROJECT_ID]
        dns_client.managed_zones = [managed_zone]

        with mock.patch(
            "prowler.providers.gcp.services.dns.dns_rsasha1_in_use_to_zone_sign_in_dnssec.dns_rsasha1_in_use_to_zone_sign_in_dnssec.dns_client",
            new=dns_client,
        ):
            from prowler.providers.gcp.services.dns.dns_rsasha1_in_use_to_zone_sign_in_dnssec.dns_rsasha1_in_use_to_zone_sign_in_dnssec import (
                dns_rsasha1_in_use_to_zone_sign_in_dnssec,
            )

            check = dns_rsasha1_in_use_to_zone_sign_in_dnssec()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Cloud DNS {managed_zone.name} is not using RSASHA1 algorithm as zone signing.",
                result[0].status_extended,
            )
            assert result[0].resource_id == managed_zone.id

    def test_managed_zone_with_dnssec_disabled(self):
        from prowler.providers.gcp.services.dns.dns_service import ManagedZone

        managed_zone = ManagedZone(
            name="test",
            id="1234567890",
            dnssec=False,
            key_specs=[
                {
                    "keyType": "keySigning",
                    "algorithm": "rsasha256",
                    "keyLength": 2048,
                    "kind": "dns#dnsKeySpec",
                },
                {
                    "keyType": "zoneSigning",
                    "algorithm": "rsasha1",
                    "keyLength": 1024,
                    "kind": "dns#dnsKeySpec",
                },
            ],
            project_id=GCP_PROJECT_ID,
        )

        dns_client = mock.MagicMock
        dns_client.project_ids = [GCP_PROJECT_ID]
        dns_client.managed_zones = [managed_zone]

        with mock.patch(
            "prowler.providers.gcp.services.dns.dns_rsasha1_in_use_to_zone_sign_in_dnssec.dns_rsasha1_in_use_to_zone_sign_in_dnssec.dns_client",
            new=dns_client,
        ):
            from prowler.providers.gcp.services.dns.dns_rsasha1_in_use_to_zone_sign_in_dnssec.dns_rsasha1_in_use_to_zone_sign_in_dnssec import (
                dns_rsasha1_in_use_to_zone_sign_in_dnssec,
            )

            check = dns_rsasha1_in_use_to_zone_sign_in_dnssec()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Cloud DNS {managed_zone.name} is using RSASHA1 algorithm as zone signing.",
                result[0].status_extended,
            )
            assert result[0].resource_id == managed_zone.id
