from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.vercel.services.domain.domain_service import (
    VercelDomain,
    VercelSSLCertificate,
)
from tests.providers.vercel.vercel_fixtures import (
    DOMAIN_NAME,
    TEAM_ID,
    set_mocked_vercel_provider,
)


class Test_domain_ssl_certificate_valid:
    def test_no_domains(self):
        domain_client = mock.MagicMock
        domain_client.audit_config = {"days_to_expire_threshold": 7}
        domain_client.domains = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.domain.domain_ssl_certificate_valid.domain_ssl_certificate_valid.domain_client",
                new=domain_client,
            ),
        ):
            from prowler.providers.vercel.services.domain.domain_ssl_certificate_valid.domain_ssl_certificate_valid import (
                domain_ssl_certificate_valid,
            )

            check = domain_ssl_certificate_valid()
            result = check.execute()
            assert len(result) == 0

    def test_ssl_valid_not_expiring_soon(self):
        domain_client = mock.MagicMock
        domain_client.audit_config = {"days_to_expire_threshold": 7}
        domain_client.domains = {
            DOMAIN_NAME: VercelDomain(
                name=DOMAIN_NAME,
                id="dom_test",
                verified=True,
                ssl_certificate=VercelSSLCertificate(
                    id="cert_1",
                    expires_at=datetime.now(timezone.utc) + timedelta(days=90),
                    auto_renew=True,
                ),
                team_id=TEAM_ID,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.domain.domain_ssl_certificate_valid.domain_ssl_certificate_valid.domain_client",
                new=domain_client,
            ),
        ):
            from prowler.providers.vercel.services.domain.domain_ssl_certificate_valid.domain_ssl_certificate_valid import (
                domain_ssl_certificate_valid,
            )

            check = domain_ssl_certificate_valid()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == "dom_test"
            assert result[0].resource_name == DOMAIN_NAME
            assert result[0].status == "PASS"
            assert "valid SSL certificate" in result[0].status_extended
            assert result[0].team_id == TEAM_ID

    def test_ssl_missing(self):
        domain_client = mock.MagicMock
        domain_client.audit_config = {"days_to_expire_threshold": 7}
        domain_client.domains = {
            DOMAIN_NAME: VercelDomain(
                name=DOMAIN_NAME,
                id="dom_test",
                verified=True,
                ssl_certificate=None,
                team_id=TEAM_ID,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.domain.domain_ssl_certificate_valid.domain_ssl_certificate_valid.domain_client",
                new=domain_client,
            ),
        ):
            from prowler.providers.vercel.services.domain.domain_ssl_certificate_valid.domain_ssl_certificate_valid import (
                domain_ssl_certificate_valid,
            )

            check = domain_ssl_certificate_valid()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == "dom_test"
            assert result[0].resource_name == DOMAIN_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Domain {DOMAIN_NAME} does not have an SSL certificate provisioned."
            )
            assert result[0].team_id == TEAM_ID

    def test_ssl_expired(self):
        domain_client = mock.MagicMock
        domain_client.audit_config = {"days_to_expire_threshold": 7}
        domain_client.domains = {
            DOMAIN_NAME: VercelDomain(
                name=DOMAIN_NAME,
                id="dom_test",
                verified=True,
                ssl_certificate=VercelSSLCertificate(
                    id="cert_1",
                    expires_at=datetime.now(timezone.utc) - timedelta(days=10),
                    auto_renew=False,
                ),
                team_id=TEAM_ID,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.domain.domain_ssl_certificate_valid.domain_ssl_certificate_valid.domain_client",
                new=domain_client,
            ),
        ):
            from prowler.providers.vercel.services.domain.domain_ssl_certificate_valid.domain_ssl_certificate_valid import (
                domain_ssl_certificate_valid,
            )

            check = domain_ssl_certificate_valid()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == "dom_test"
            assert result[0].resource_name == DOMAIN_NAME
            assert result[0].status == "FAIL"
            assert "expired" in result[0].status_extended
            assert result[0].team_id == TEAM_ID

    def test_ssl_expiring_soon(self):
        domain_client = mock.MagicMock
        domain_client.audit_config = {"days_to_expire_threshold": 7}
        domain_client.domains = {
            DOMAIN_NAME: VercelDomain(
                name=DOMAIN_NAME,
                id="dom_test",
                verified=True,
                ssl_certificate=VercelSSLCertificate(
                    id="cert_1",
                    expires_at=datetime.now(timezone.utc) + timedelta(days=3),
                    auto_renew=False,
                ),
                team_id=TEAM_ID,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.domain.domain_ssl_certificate_valid.domain_ssl_certificate_valid.domain_client",
                new=domain_client,
            ),
        ):
            from prowler.providers.vercel.services.domain.domain_ssl_certificate_valid.domain_ssl_certificate_valid import (
                domain_ssl_certificate_valid,
            )

            check = domain_ssl_certificate_valid()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == "dom_test"
            assert result[0].resource_name == DOMAIN_NAME
            assert result[0].status == "FAIL"
            assert "expiring" in result[0].status_extended
            assert result[0].team_id == TEAM_ID

    def test_ssl_no_expiry_date(self):
        domain_client = mock.MagicMock
        domain_client.audit_config = {"days_to_expire_threshold": 7}
        domain_client.domains = {
            DOMAIN_NAME: VercelDomain(
                name=DOMAIN_NAME,
                id="dom_test",
                verified=True,
                ssl_certificate=VercelSSLCertificate(
                    id="cert_1",
                    expires_at=None,
                    auto_renew=True,
                ),
                team_id=TEAM_ID,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.domain.domain_ssl_certificate_valid.domain_ssl_certificate_valid.domain_client",
                new=domain_client,
            ),
        ):
            from prowler.providers.vercel.services.domain.domain_ssl_certificate_valid.domain_ssl_certificate_valid import (
                domain_ssl_certificate_valid,
            )

            check = domain_ssl_certificate_valid()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == "dom_test"
            assert result[0].resource_name == DOMAIN_NAME
            assert result[0].status == "PASS"
            assert "provisioned" in result[0].status_extended
            assert result[0].team_id == TEAM_ID
