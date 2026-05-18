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

    def test_app_registration_no_secrets(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        obj_id = str(uuid4())
        app_id = str(uuid4())

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
                obj_id: AppRegistration(
                    id=obj_id,
                    app_id=app_id,
                    name="CleanApp",
                    password_credentials=[],
                )
            }

            check = entra_app_registration_no_password_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not use password credentials" in result[0].status_extended
            assert result[0].resource_id == obj_id
            assert result[0].resource_name == "CleanApp"

    def test_app_registration_with_active_secret(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        obj_id = str(uuid4())
        app_id = str(uuid4())
        future = datetime.now(timezone.utc) + timedelta(days=180)

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
                obj_id: AppRegistration(
                    id=obj_id,
                    app_id=app_id,
                    name="SecretApp",
                    password_credentials=[
                        PasswordCredential(
                            key_id=str(uuid4()),
                            display_name="prod-secret",
                            end_date_time=future,
                        )
                    ],
                )
            }

            check = entra_app_registration_no_password_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "1 password credential(s)" in result[0].status_extended
            assert result[0].resource_id == obj_id
            assert result[0].resource_name == "SecretApp"

    def test_app_registration_with_expired_secret_still_fails(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        obj_id = str(uuid4())
        app_id = str(uuid4())
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
                obj_id: AppRegistration(
                    id=obj_id,
                    app_id=app_id,
                    name="LegacyApp",
                    password_credentials=[
                        PasswordCredential(
                            key_id=str(uuid4()),
                            display_name="old-secret",
                            end_date_time=expired,
                        )
                    ],
                )
            }

            check = entra_app_registration_no_password_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "1 password credential(s)" in result[0].status_extended

    def test_app_registration_with_multiple_secrets(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        obj_id = str(uuid4())
        app_id = str(uuid4())

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
                obj_id: AppRegistration(
                    id=obj_id,
                    app_id=app_id,
                    name="MultiSecretApp",
                    password_credentials=[
                        PasswordCredential(key_id=str(uuid4()), display_name="secret1"),
                        PasswordCredential(key_id=str(uuid4()), display_name="secret2"),
                        PasswordCredential(key_id=str(uuid4()), display_name="secret3"),
                    ],
                )
            }

            check = entra_app_registration_no_password_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "3 password credential(s)" in result[0].status_extended

    def test_multiple_apps_mixed(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        clean_id = str(uuid4())
        dirty_id = str(uuid4())

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
                clean_id: AppRegistration(
                    id=clean_id,
                    app_id=str(uuid4()),
                    name="CleanApp",
                    password_credentials=[],
                ),
                dirty_id: AppRegistration(
                    id=dirty_id,
                    app_id=str(uuid4()),
                    name="DirtyApp",
                    password_credentials=[
                        PasswordCredential(key_id=str(uuid4()), display_name="secret1")
                    ],
                ),
            }

            check = entra_app_registration_no_password_credentials()
            result = check.execute()

            assert len(result) == 2
            statuses = {r.resource_id: r.status for r in result}
            assert statuses[clean_id] == "PASS"
            assert statuses[dirty_id] == "FAIL"
