from datetime import datetime, timedelta, timezone
from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    AppRegistration,
    PasswordCredential,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_app_registration_no_password_credentials:
    def test_no_app_registrations(self):
        """No app registrations in tenant: no findings."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_password_credentials.entra_app_registration_no_password_credentials.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_password_credentials.entra_app_registration_no_password_credentials import (
                entra_app_registration_no_password_credentials,
            )

            entra_client.app_registrations = {}

            check = entra_app_registration_no_password_credentials()
            result = check.execute()

            assert len(result) == 0

    def test_app_no_password_credentials(self):
        """App with no password credentials: expected PASS."""
        app_id = str(uuid4())
        app_name = "Test App Clean"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_password_credentials.entra_app_registration_no_password_credentials.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_password_credentials.entra_app_registration_no_password_credentials import (
                entra_app_registration_no_password_credentials,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    password_credentials=[],
                )
            }

            check = entra_app_registration_no_password_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"App registration {app_name} does not use password credentials."
            )
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_app_with_one_password_credential(self):
        """App with one password credential: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Test App With Secret"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_password_credentials.entra_app_registration_no_password_credentials.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_password_credentials.entra_app_registration_no_password_credentials import (
                entra_app_registration_no_password_credentials,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    password_credentials=[
                        PasswordCredential(
                            key_id=str(uuid4()),
                            display_name="My Secret",
                            start_date_time="2024-01-01T00:00:00Z",
                            end_date_time="2025-01-01T00:00:00Z",
                        ),
                    ],
                )
            }

            check = entra_app_registration_no_password_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "1 password credential(s)" in result[0].status_extended
            assert "My Secret" in result[0].status_extended
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_app_with_expired_password_credential_still_fails(self):
        """App with an expired password credential: still expected FAIL."""
        app_id = str(uuid4())
        app_name = "Legacy App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        expired = datetime.now(timezone.utc) - timedelta(days=30)

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_password_credentials.entra_app_registration_no_password_credentials.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_password_credentials.entra_app_registration_no_password_credentials import (
                entra_app_registration_no_password_credentials,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    password_credentials=[
                        PasswordCredential(
                            key_id=str(uuid4()),
                            display_name="old-secret",
                            end_date_time=expired,
                        ),
                    ],
                )
            }

            check = entra_app_registration_no_password_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "1 password credential(s)" in result[0].status_extended
            assert result[0].resource_name == app_name

    def test_app_with_multiple_password_credentials(self):
        """App with multiple password credentials: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Test App Multiple Secrets"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_password_credentials.entra_app_registration_no_password_credentials.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_password_credentials.entra_app_registration_no_password_credentials import (
                entra_app_registration_no_password_credentials,
            )

            entra_client.app_registrations = {
                app_id: AppRegistration(
                    id=app_id,
                    app_id=str(uuid4()),
                    name=app_name,
                    password_credentials=[
                        PasswordCredential(
                            key_id=str(uuid4()),
                            display_name="Secret 1",
                            end_date_time="2025-06-01T00:00:00Z",
                        ),
                        PasswordCredential(
                            key_id=str(uuid4()),
                            display_name="Secret 2",
                            end_date_time="2025-12-01T00:00:00Z",
                        ),
                    ],
                )
            }

            check = entra_app_registration_no_password_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "2 password credential(s)" in result[0].status_extended
            assert result[0].resource_name == app_name

    def test_multiple_apps_mixed(self):
        """Multiple apps: one clean, one with secrets."""
        app_id_pass = str(uuid4())
        app_name_pass = "Clean App"
        app_id_fail = str(uuid4())
        app_name_fail = "App With Secret"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_password_credentials.entra_app_registration_no_password_credentials.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_password_credentials.entra_app_registration_no_password_credentials import (
                entra_app_registration_no_password_credentials,
            )

            entra_client.app_registrations = {
                app_id_pass: AppRegistration(
                    id=app_id_pass,
                    app_id=str(uuid4()),
                    name=app_name_pass,
                    password_credentials=[],
                ),
                app_id_fail: AppRegistration(
                    id=app_id_fail,
                    app_id=str(uuid4()),
                    name=app_name_fail,
                    password_credentials=[
                        PasswordCredential(
                            key_id=str(uuid4()),
                            display_name="Legacy Secret",
                        ),
                    ],
                ),
            }

            check = entra_app_registration_no_password_credentials()
            result = check.execute()

            assert len(result) == 2

            result_pass = next(r for r in result if r.resource_id == app_id_pass)
            result_fail = next(r for r in result if r.resource_id == app_id_fail)

            assert result_pass.status == "PASS"
            assert result_fail.status == "FAIL"
            assert "Legacy Secret" in result_fail.status_extended
