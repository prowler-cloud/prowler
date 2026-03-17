from unittest import mock

from prowler.providers.vercel.services.domain.domain_service import VercelDomain
from tests.providers.vercel.vercel_fixtures import (
    DOMAIN_NAME,
    TEAM_ID,
    set_mocked_vercel_provider,
)

DOMAIN_ID = "dom_test001"


class Test_domain_no_wildcard_dns_exposure:
    def test_no_domains(self):
        domain_client = mock.MagicMock
        domain_client.domains = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.domain.domain_no_wildcard_dns_exposure.domain_no_wildcard_dns_exposure.domain_client",
                new=domain_client,
            ),
        ):
            from prowler.providers.vercel.services.domain.domain_no_wildcard_dns_exposure.domain_no_wildcard_dns_exposure import (
                domain_no_wildcard_dns_exposure,
            )

            check = domain_no_wildcard_dns_exposure()
            result = check.execute()
            assert len(result) == 0

    def test_no_wildcard_records(self):
        domain_client = mock.MagicMock
        domain_client.domains = {
            DOMAIN_NAME: VercelDomain(
                name=DOMAIN_NAME,
                id=DOMAIN_ID,
                dns_records=[
                    {"name": "www", "type": "CNAME", "value": "cname.vercel-dns.com"}
                ],
                team_id=TEAM_ID,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.domain.domain_no_wildcard_dns_exposure.domain_no_wildcard_dns_exposure.domain_client",
                new=domain_client,
            ),
        ):
            from prowler.providers.vercel.services.domain.domain_no_wildcard_dns_exposure.domain_no_wildcard_dns_exposure import (
                domain_no_wildcard_dns_exposure,
            )

            check = domain_no_wildcard_dns_exposure()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == DOMAIN_ID
            assert result[0].resource_name == DOMAIN_NAME
            assert result[0].status == "PASS"
            assert "no wildcard DNS records" in result[0].status_extended

    def test_has_wildcard_records(self):
        domain_client = mock.MagicMock
        domain_client.domains = {
            DOMAIN_NAME: VercelDomain(
                name=DOMAIN_NAME,
                id=DOMAIN_ID,
                dns_records=[
                    {
                        "name": "*.example.com",
                        "type": "CNAME",
                        "value": "cname.vercel-dns.com",
                    },
                ],
                team_id=TEAM_ID,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.domain.domain_no_wildcard_dns_exposure.domain_no_wildcard_dns_exposure.domain_client",
                new=domain_client,
            ),
        ):
            from prowler.providers.vercel.services.domain.domain_no_wildcard_dns_exposure.domain_no_wildcard_dns_exposure import (
                domain_no_wildcard_dns_exposure,
            )

            check = domain_no_wildcard_dns_exposure()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == DOMAIN_ID
            assert result[0].resource_name == DOMAIN_NAME
            assert result[0].status == "FAIL"
            assert "wildcard DNS" in result[0].status_extended
