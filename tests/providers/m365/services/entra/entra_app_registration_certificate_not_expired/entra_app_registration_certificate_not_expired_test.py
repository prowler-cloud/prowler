from datetime import datetime, timedelta, timezone
from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    AppRegistration,
    KeyCredential,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_app_registration_certificate_not_expired:
    def test_no_app_registrations(self):
        """No app registrations in tenant: no findings."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": 30
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            entra_client.app_registrations = {}

            check = entra_app_registration_certificate_not_expired()
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
            "app_registration_certificate_expiration_threshold_days": 30
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name="No Certs App",
                    key_credentials=[],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 0

    def test_all_certificates_valid_pass(self):
        """All certificates valid beyond threshold: expected PASS."""
        app_id = str(uuid4())
        app_name = "Healthy App"
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": 30
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            future = datetime.now(timezone.utc) + timedelta(days=365)
            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=good-cert",
                            end_date_time=future,
                            custom_key_identifier="AABB1122",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "valid beyond 30 days" in result[0].status_extended
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_expired_certificate_fail(self):
        """Certificate already expired: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Legacy App"
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": 30
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            expired = datetime.now(timezone.utc) - timedelta(days=60)
            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=old-cert",
                            end_date_time=expired,
                            custom_key_identifier="CCDD3344",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "expired" in result[0].status_extended
            assert "CN=old-cert" in result[0].status_extended
            assert result[0].resource_name == app_name

    def test_expiring_soon_certificate_fail(self):
        """Certificate expiring within threshold: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Expiring App"
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": 30
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            expiring_soon = datetime.now(timezone.utc) + timedelta(days=15)
            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=soon-cert",
                            end_date_time=expiring_soon,
                            custom_key_identifier="EEFF5566",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "expires" in result[0].status_extended
            assert "CN=soon-cert" in result[0].status_extended

    def test_deduplicate_sign_verify_certificates(self):
        """Same certificate with Sign/Verify usage is counted once."""
        app_id = str(uuid4())
        app_name = "Dedup App"
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": 30
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            expired = datetime.now(timezone.utc) - timedelta(days=10)
            thumbprint = "AABB1122"
            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=dup-cert",
                            end_date_time=expired,
                            custom_key_identifier=thumbprint,
                            usage="Sign",
                        ),
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=dup-cert",
                            end_date_time=expired,
                            custom_key_identifier=thumbprint,
                            usage="Verify",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Only 1 certificate reported despite 2 keyCredential entries
            assert "1 certificate(s)" in result[0].status_extended

    def test_mixed_expired_and_valid_certificates(self):
        """App with one expired and one valid certificate: FAIL for the expired one."""
        app_id = str(uuid4())
        app_name = "Mixed App"
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": 30
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            expired = datetime.now(timezone.utc) - timedelta(days=100)
            valid = datetime.now(timezone.utc) + timedelta(days=365)
            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=old-cert",
                            end_date_time=expired,
                            custom_key_identifier="AAAA",
                        ),
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=new-cert",
                            end_date_time=valid,
                            custom_key_identifier="BBBB",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "1 certificate(s)" in result[0].status_extended
            assert "CN=old-cert" in result[0].status_extended
            assert "CN=new-cert" not in result[0].status_extended

    def test_missing_end_date_manual(self):
        """Certificate with missing endDateTime and no other FAIL: MANUAL."""
        app_id = str(uuid4())
        app_name = "Null Date App"
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": 30
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=mystery-cert",
                            end_date_time=None,
                            custom_key_identifier="CCCC",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "missing expiry date" in result[0].status_extended

    def test_fail_takes_precedence_over_manual(self):
        """FAIL takes precedence when one cert is expired and another has missing date."""
        app_id = str(uuid4())
        app_name = "Precedence App"
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": 30
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            expired = datetime.now(timezone.utc) - timedelta(days=5)
            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=expired-cert",
                            end_date_time=expired,
                            custom_key_identifier="DDDD",
                        ),
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=null-cert",
                            end_date_time=None,
                            custom_key_identifier="EEEE",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "CN=expired-cert" in result[0].status_extended

    def test_api_error_manual(self):
        """API error when fetching app registrations: single MANUAL finding."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = "ODataError: Insufficient privileges"
        entra_client.app_registrations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_name == "App registrations"
            assert result[0].resource_id == "applications"
            assert "Insufficient privileges" in result[0].status_extended

    def test_threshold_zero_only_expired_reported(self):
        """Threshold 0: only expired certificates are reported, not expiring ones."""
        app_id = str(uuid4())
        app_name = "Threshold Zero App"
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": 0
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            # Certificate expiring in 15 days - not expired yet
            expiring = datetime.now(timezone.utc) + timedelta(days=15)
            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=soon-cert",
                            end_date_time=expiring,
                            custom_key_identifier="FFFF",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_multiple_expired_and_expiring_certificates(self):
        """App with both expired and expiring soon certificates: FAIL with all details."""
        app_id = str(uuid4())
        app_name = "Payroll Sync"
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": 30
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            expired = datetime.now(timezone.utc) - timedelta(days=200)
            expiring_soon = datetime.now(timezone.utc) + timedelta(days=12)
            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=old-cert",
                            end_date_time=expired,
                            custom_key_identifier="1111",
                        ),
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=prod-cert",
                            end_date_time=expiring_soon,
                            custom_key_identifier="2222",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "2 certificate(s)" in result[0].status_extended
            assert "CN=old-cert" in result[0].status_extended
            assert "CN=prod-cert" in result[0].status_extended
            assert "expired" in result[0].status_extended
            assert "expires" in result[0].status_extended

    def test_fallback_to_key_id_when_no_display_name(self):
        """Certificate without displayName uses keyId as label."""
        app_id = str(uuid4())
        key_id = str(uuid4())
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": 30
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            expired = datetime.now(timezone.utc) - timedelta(days=10)
            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name="Unnamed Cert App",
                    key_credentials=[
                        KeyCredential(
                            key_id=key_id,
                            display_name=None,
                            end_date_time=expired,
                            custom_key_identifier="GGGG",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert key_id in result[0].status_extended

    def test_naive_datetime_normalized_to_utc(self):
        """Naive datetime is treated as UTC and evaluated correctly."""
        app_id = str(uuid4())
        app_name = "Naive Date App"
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": 30
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            # Naive datetime (no tzinfo) that is expired
            expired_naive = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
                days=5
            )
            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=naive-cert",
                            end_date_time=expired_naive,
                            custom_key_identifier="HHHH",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "CN=naive-cert" in result[0].status_extended

    def test_expired_certificate_fail_with_unset_threshold(self):
        """Unset threshold falls back to the default. Certificate already expired: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Legacy App"
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.app_registrations_error = None
        entra_client.audit_config = {
            "app_registration_certificate_expiration_threshold_days": None
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_certificate_not_expired.entra_app_registration_certificate_not_expired import (
                entra_app_registration_certificate_not_expired,
            )

            expired = datetime.now(timezone.utc) - timedelta(days=60)
            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    key_credentials=[
                        KeyCredential(
                            key_id=str(uuid4()),
                            display_name="CN=old-cert",
                            end_date_time=expired,
                            custom_key_identifier="CCDD3344",
                        ),
                    ],
                )
            }

            check = entra_app_registration_certificate_not_expired()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "expired" in result[0].status_extended
            assert "CN=old-cert" in result[0].status_extended
            assert result[0].resource_name == app_name
