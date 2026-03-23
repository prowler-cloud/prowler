from unittest import mock

from prowler.providers.vercel.services.domain.domain_service import VercelDomain
from tests.providers.vercel.vercel_fixtures import (
    DOMAIN_NAME,
    TEAM_ID,
    set_mocked_vercel_provider,
)

DOMAIN_ID = "dom_test001"


class Test_domain_dns_properly_configured:
    def test_no_domains(self):
        domain_client = mock.MagicMock
        domain_client.domains = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.domain.domain_dns_properly_configured.domain_dns_properly_configured.domain_client",
                new=domain_client,
            ),
        ):
            from prowler.providers.vercel.services.domain.domain_dns_properly_configured.domain_dns_properly_configured import (
                domain_dns_properly_configured,
            )

            check = domain_dns_properly_configured()
            result = check.execute()
            assert len(result) == 0

    def test_configured(self):
        domain_client = mock.MagicMock
        domain_client.domains = {
            DOMAIN_NAME: VercelDomain(
                name=DOMAIN_NAME,
                id=DOMAIN_ID,
                configured=True,
                team_id=TEAM_ID,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.domain.domain_dns_properly_configured.domain_dns_properly_configured.domain_client",
                new=domain_client,
            ),
        ):
            from prowler.providers.vercel.services.domain.domain_dns_properly_configured.domain_dns_properly_configured import (
                domain_dns_properly_configured,
            )

            check = domain_dns_properly_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == DOMAIN_ID
            assert result[0].resource_name == DOMAIN_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Domain {DOMAIN_NAME} has DNS properly configured."
            )
            assert result[0].team_id == TEAM_ID

    def test_not_configured(self):
        domain_client = mock.MagicMock
        domain_client.domains = {
            DOMAIN_NAME: VercelDomain(
                name=DOMAIN_NAME,
                id=DOMAIN_ID,
                configured=False,
                team_id=TEAM_ID,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.domain.domain_dns_properly_configured.domain_dns_properly_configured.domain_client",
                new=domain_client,
            ),
        ):
            from prowler.providers.vercel.services.domain.domain_dns_properly_configured.domain_dns_properly_configured import (
                domain_dns_properly_configured,
            )

            check = domain_dns_properly_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == DOMAIN_ID
            assert result[0].resource_name == DOMAIN_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Domain {DOMAIN_NAME} does not have DNS properly configured. The domain may not be resolving to Vercel's infrastructure."
            )
            assert result[0].team_id == TEAM_ID
