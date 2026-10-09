from datetime import datetime, timedelta, timezone
from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    AppRegistration,
    KeyCredential,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_app_registration_certificate_lifetime_restricted."
    "entra_app_registration_certificate_lifetime_restricted"
)


class Test_entra_app_registration_certificate_lifetime_restricted:
    """Tests for the entra_app_registration_certificate_lifetime_restricted check."""

    def test_no_app_registrations(self):
        """No app registrations in tenant: no findings."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {}

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 0

    def test_app_without_certificates_skipped(self):
        """App with no key credentials produces no finding."""
        app_id = str(uuid4())
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name="No Certs App",
                    key_credentials=[],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 0

    def test_certificate_within_limit_pass(self):
        """Certificate with validity <= max_days: expected PASS."""
        app_id = str(uuid4())
        app_name = "Short Lived App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="short-cert",
                            start_date_time=now - timedelta(days=30),
                            end_date_time=now + timedelta(days=300),
                            custom_key_identifier="aabb",
                            usage="Verify",
                            type_="AsymmetricX509Cert",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "within 365 days" in result[0].status_extended
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_certificate_exceeding_limit_fail(self):
        """Certificate with validity > max_days: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Payroll Sync"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="payroll-prod",
                            start_date_time=now - timedelta(days=30),
                            end_date_time=now + timedelta(days=700),
                            custom_key_identifier="ccdd",
                            usage="Verify",
                            type_="AsymmetricX509Cert",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "1 certificate(s) valid for longer than 365 days"
                in result[0].status_extended
            )
            assert "'payroll-prod'" in result[0].status_extended
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_expired_certificate_pass(self):
        """All certificates expired: expected PASS."""
        app_id = str(uuid4())
        app_name = "Legacy App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="old-cert",
                            start_date_time=now - timedelta(days=1000),
                            end_date_time=now - timedelta(days=10),
                            custom_key_identifier="eeff",
                            usage="Verify",
                            type_="AsymmetricX509Cert",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_deduplication_sign_verify_pair(self):
        """Sign and Verify entries for the same cert are counted once."""
        app_id = str(uuid4())
        app_name = "Dedup App"
        now = datetime.now(timezone.utc)
        thumbprint = "aabbccdd"
        key_id_sign = str(uuid4())
        key_id_verify = str(uuid4())
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=key_id_sign,
                            display_name="my-cert",
                            start_date_time=now - timedelta(days=30),
                            end_date_time=now + timedelta(days=700),
                            custom_key_identifier=thumbprint,
                            usage="Sign",
                            type_="AsymmetricX509Cert",
                        ),
                        KeyCredential(
                            key_id=key_id_verify,
                            display_name="my-cert",
                            start_date_time=now - timedelta(days=30),
                            end_date_time=now + timedelta(days=700),
                            custom_key_identifier=thumbprint,
                            usage="Verify",
                            type_="AsymmetricX509Cert",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Only 1 certificate should be reported, not 2
            assert "1 certificate(s)" in result[0].status_extended

    def test_missing_end_date_manual(self):
        """Certificate with missing end_date_time: expected MANUAL."""
        app_id = str(uuid4())
        app_name = "Unknown Expiry App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="mystery-cert",
                            start_date_time=now - timedelta(days=30),
                            end_date_time=None,
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "could not be determined" in result[0].status_extended
            assert "'mystery-cert'" in result[0].status_extended

    def test_missing_start_date_non_expired_manual(self):
        """Non-expired certificate with missing start_date_time: expected MANUAL."""
        app_id = str(uuid4())
        app_name = "No Start App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="no-start-cert",
                            start_date_time=None,
                            end_date_time=now + timedelta(days=100),
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "'no-start-cert'" in result[0].status_extended

    def test_fail_takes_precedence_over_manual(self):
        """One cert FAILs, another is undeterminable: FAIL with mention of both."""
        app_id = str(uuid4())
        app_name = "Mixed App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="long-cert",
                            start_date_time=now - timedelta(days=30),
                            end_date_time=now + timedelta(days=700),
                            custom_key_identifier="1111",
                        ),
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="unknown-cert",
                            start_date_time=None,
                            end_date_time=None,
                            custom_key_identifier="2222",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "'long-cert'" in result[0].status_extended
            assert "'unknown-cert'" in result[0].status_extended
            assert "could not be determined" in result[0].status_extended

    def test_api_error_manual(self):
        """API error fetching app registrations: single MANUAL finding."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = "Insufficient privileges"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {}

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_name == "App registrations"
            assert result[0].resource_id == "applications"
            assert "Insufficient privileges" in result[0].status_extended

    def test_fractional_days_not_rounded_before_comparing(self):
        """Certificate valid for 365.4 days with max 365 must FAIL."""
        app_id = str(uuid4())
        app_name = "Fractional App"
        now = datetime.now(timezone.utc)
        # Create a certificate that is valid for exactly 365 days + 10 hours
        start = now - timedelta(days=10)
        end = start + timedelta(days=365, hours=10)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="borderline-cert",
                            start_date_time=start,
                            end_date_time=end,
                            custom_key_identifier="ff00",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Display should round UP: 365.4 -> 366
            assert "366 days" in result[0].status_extended

    def test_exactly_max_days_pass(self):
        """Certificate valid for exactly max_days: expected PASS."""
        app_id = str(uuid4())
        app_name = "Exact App"
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=10)
        end = start + timedelta(days=365)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="exact-cert",
                            start_date_time=start,
                            end_date_time=end,
                            custom_key_identifier="aa11",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_not_yet_valid_certificate_evaluated(self):
        """Certificate not yet valid (start > now) is still evaluated."""
        app_id = str(uuid4())
        app_name = "Future App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="future-cert",
                            start_date_time=now + timedelta(days=30),
                            end_date_time=now + timedelta(days=800),
                            custom_key_identifier="bb22",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "'future-cert'" in result[0].status_extended

    def test_custom_max_days_config(self):
        """Custom max_days of 180: certificate with 200 days should FAIL."""
        app_id = str(uuid4())
        app_name = "Custom Config App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 180
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="medium-cert",
                            start_date_time=now - timedelta(days=10),
                            end_date_time=now + timedelta(days=190),
                            custom_key_identifier="cc33",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "longer than 180 days" in result[0].status_extended

    def test_multiple_apps_mixed_results(self):
        """Multiple apps: one with compliant cert (PASS), one with long cert (FAIL)."""
        app_id_pass = str(uuid4())
        app_name_pass = "Compliant App"
        app_id_fail = str(uuid4())
        app_name_fail = "Non-Compliant App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id_pass: AppRegistration(
                    id=app_id_pass,
                    app_id=str(uuid4()),
                    name=app_name_pass,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="good-cert",
                            start_date_time=now - timedelta(days=10),
                            end_date_time=now + timedelta(days=200),
                            custom_key_identifier="aaaa",
                        ),
                    ],
                ),
                app_id_fail: AppRegistration(
                    id=app_id_fail,
                    app_id=str(uuid4()),
                    name=app_name_fail,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="bad-cert",
                            start_date_time=now - timedelta(days=10),
                            end_date_time=now + timedelta(days=800),
                            custom_key_identifier="bbbb",
                        ),
                    ],
                ),
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 2

            result_pass = next(r for r in result if r.resource_id == app_id_pass)
            result_fail = next(r for r in result if r.resource_id == app_id_fail)

            assert result_pass.status == "PASS"
            assert result_pass.resource_name == app_name_pass
            assert result_fail.status == "FAIL"
            assert result_fail.resource_name == app_name_fail
            assert "'bad-cert'" in result_fail.status_extended

    def test_multiple_failing_certs_on_same_app(self):
        """App with two distinct failing certificates: both listed in status_extended."""
        app_id = str(uuid4())
        app_name = "Multi Fail App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="long-cert-1",
                            start_date_time=now - timedelta(days=10),
                            end_date_time=now + timedelta(days=500),
                            custom_key_identifier="aaaa",
                        ),
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="long-cert-2",
                            start_date_time=now - timedelta(days=5),
                            end_date_time=now + timedelta(days=900),
                            custom_key_identifier="bbbb",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "2 certificate(s)" in result[0].status_extended
            assert "'long-cert-1'" in result[0].status_extended
            assert "'long-cert-2'" in result[0].status_extended

    def test_dedup_fallback_to_key_id_when_no_thumbprint(self):
        """When custom_key_identifier is None, key_id is used for deduplication."""
        app_id = str(uuid4())
        app_name = "No Thumbprint App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            # Two entries with no custom_key_identifier but different key_ids
            # -> each treated as a separate certificate
            key_id_1 = str(uuid4())
            key_id_2 = str(uuid4())

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=key_id_1,
                            display_name="cert-a",
                            start_date_time=now - timedelta(days=10),
                            end_date_time=now + timedelta(days=500),
                            custom_key_identifier=None,
                        ),
                        KeyCredential(
                            key_id=key_id_2,
                            display_name="cert-b",
                            start_date_time=now - timedelta(days=10),
                            end_date_time=now + timedelta(days=600),
                            custom_key_identifier=None,
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Both distinct certs should be reported
            assert "2 certificate(s)" in result[0].status_extended
            assert "'cert-a'" in result[0].status_extended
            assert "'cert-b'" in result[0].status_extended

    def test_label_fallback_to_key_id_when_no_display_name(self):
        """When display_name is None, key_id is used as the certificate label."""
        app_id = str(uuid4())
        app_name = "No DisplayName App"
        now = datetime.now(timezone.utc)
        key_id = str(uuid4())
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=key_id,
                            display_name=None,
                            start_date_time=now - timedelta(days=10),
                            end_date_time=now + timedelta(days=500),
                            custom_key_identifier="dddd",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # key_id should be used as the label
            assert f"'{key_id}'" in result[0].status_extended

    def test_naive_datetime_treated_as_utc(self):
        """Naive datetimes (no tzinfo) should be normalised to UTC and evaluated."""
        app_id = str(uuid4())
        app_name = "Naive DT App"
        # Create naive datetimes (no timezone)
        # Dates relative to now so the certificate is never already expired.
        now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
        start_naive = now_naive - timedelta(days=100)
        end_naive = now_naive + timedelta(days=812)  # ~912 days
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="naive-cert",
                            start_date_time=start_naive,
                            end_date_time=end_naive,
                            custom_key_identifier="eeee",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "'naive-cert'" in result[0].status_extended

    def test_mixed_expired_and_compliant_pass(self):
        """App with one expired long-lived cert and one compliant non-expired cert: PASS."""
        app_id = str(uuid4())
        app_name = "Mixed Expired App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        # Expired cert with 730 days validity - should be ignored
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="expired-long-cert",
                            start_date_time=now - timedelta(days=1000),
                            end_date_time=now - timedelta(days=270),
                            custom_key_identifier="1111",
                        ),
                        # Non-expired cert within limit
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="good-cert",
                            start_date_time=now - timedelta(days=30),
                            end_date_time=now + timedelta(days=200),
                            custom_key_identifier="2222",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "within 365 days" in result[0].status_extended

    def test_resource_name_fallback_to_app_id(self):
        """When app name is empty, resource_name falls back to app_id."""
        app_id = str(uuid4())
        app_app_id = str(uuid4())
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=app_app_id,
                    name="",
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="some-cert",
                            start_date_time=now - timedelta(days=10),
                            end_date_time=now + timedelta(days=200),
                            custom_key_identifier="ff11",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            # Empty name -> fallback to app_id
            assert result[0].resource_name == app_app_id

    def test_not_yet_valid_certificate_within_limit_pass(self):
        """Future certificate with short validity period: PASS."""
        app_id = str(uuid4())
        app_name = "Future Short App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="future-short-cert",
                            start_date_time=now + timedelta(days=30),
                            end_date_time=now + timedelta(days=200),
                            custom_key_identifier="cc44",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_default_max_days_when_config_key_missing(self):
        """When the config key is absent, default 365 days is used."""
        app_id = str(uuid4())
        app_name = "Default Config App"
        now = datetime.now(timezone.utc)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        # Empty audit_config: the key is missing
        entra_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            # Certificate valid for 400 days (> 365 default)
            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="long-cert",
                            start_date_time=now - timedelta(days=10),
                            end_date_time=now + timedelta(days=400),
                            custom_key_identifier="dd55",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Should use default 365
            assert "longer than 365 days" in result[0].status_extended

    def test_expiry_date_in_status_extended(self):
        """Status extended includes the expiry date formatted as YYYY-MM-DD."""
        app_id = str(uuid4())
        app_name = "Expiry Date App"
        start = datetime.now(timezone.utc) - timedelta(days=100)
        end = start + timedelta(days=895)
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_max_validity_days": 365
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_lifetime_restricted.entra_app_registration_certificate_lifetime_restricted import (
                entra_app_registration_certificate_lifetime_restricted,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="dated-cert",
                            start_date_time=start,
                            end_date_time=end,
                            custom_key_identifier="ee66",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_lifetime_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert f"expires {end.strftime('%Y-%m-%d')}" in result[0].status_extended
