from datetime import datetime, timezone, timedelta
from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import DOMAIN, set_mocked_azure_provider


class Test_entra_app_registration_credential_not_expired:
    def test_entra_no_tenants(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired import (
                entra_app_registration_credential_not_expired,
            )

            entra_client.app_registrations = {}

            check = entra_app_registration_credential_not_expired()
            result = check.execute()
            assert len(result) == 0

    def test_entra_app_no_credentials(self):
        entra_client = mock.MagicMock
        app_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired import (
                entra_app_registration_credential_not_expired,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AppRegistration,
            )

            app = AppRegistration(id=app_id, name="no-creds-app", credentials=[])
            entra_client.app_registrations = {DOMAIN: {app_id: app}}

            check = entra_app_registration_credential_not_expired()
            result = check.execute()
            assert len(result) == 0

    def test_entra_app_credential_expired(self):
        entra_client = mock.MagicMock
        app_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired import (
                entra_app_registration_credential_not_expired,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AppCredential,
                AppRegistration,
            )

            app = AppRegistration(
                id=app_id,
                name="expired-app",
                credentials=[
                    AppCredential(
                        display_name="old-secret",
                        credential_type="password",
                        end_date_time=datetime.now(timezone.utc) - timedelta(days=30),
                    )
                ],
            )
            entra_client.app_registrations = {DOMAIN: {app_id: app}}

            check = entra_app_registration_credential_not_expired()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "expired" in result[0].status_extended

    def test_entra_app_credential_expiring_soon(self):
        entra_client = mock.MagicMock
        app_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired import (
                entra_app_registration_credential_not_expired,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AppCredential,
                AppRegistration,
            )

            app = AppRegistration(
                id=app_id,
                name="expiring-soon-app",
                credentials=[
                    AppCredential(
                        display_name="expiring-cert",
                        credential_type="certificate",
                        end_date_time=datetime.now(timezone.utc) + timedelta(days=15),
                    )
                ],
            )
            entra_client.app_registrations = {DOMAIN: {app_id: app}}

            check = entra_app_registration_credential_not_expired()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "expiring in" in result[0].status_extended

    def test_entra_app_credential_no_expiration(self):
        entra_client = mock.MagicMock
        app_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired import (
                entra_app_registration_credential_not_expired,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AppCredential,
                AppRegistration,
            )

            app = AppRegistration(
                id=app_id,
                name="no-expiry-app",
                credentials=[
                    AppCredential(
                        display_name="forever-secret",
                        credential_type="password",
                        end_date_time=None,
                    )
                ],
            )
            entra_client.app_registrations = {DOMAIN: {app_id: app}}

            check = entra_app_registration_credential_not_expired()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "no expiration" in result[0].status_extended

    def test_entra_app_credential_valid(self):
        entra_client = mock.MagicMock
        app_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired import (
                entra_app_registration_credential_not_expired,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AppCredential,
                AppRegistration,
            )

            app = AppRegistration(
                id=app_id,
                name="healthy-app",
                credentials=[
                    AppCredential(
                        display_name="good-secret",
                        credential_type="password",
                        end_date_time=datetime.now(timezone.utc) + timedelta(days=180),
                    )
                ],
            )
            entra_client.app_registrations = {DOMAIN: {app_id: app}}

            check = entra_app_registration_credential_not_expired()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "more days" in result[0].status_extended

    def test_entra_app_multiple_credentials_mixed(self):
        entra_client = mock.MagicMock
        app_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_app_registration_credential_not_expired.entra_app_registration_credential_not_expired import (
                entra_app_registration_credential_not_expired,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AppCredential,
                AppRegistration,
            )

            app = AppRegistration(
                id=app_id,
                name="mixed-app",
                credentials=[
                    AppCredential(
                        display_name="expired-one",
                        credential_type="password",
                        end_date_time=datetime.now(timezone.utc) - timedelta(days=10),
                    ),
                    AppCredential(
                        display_name="valid-one",
                        credential_type="certificate",
                        end_date_time=datetime.now(timezone.utc) + timedelta(days=200),
                    ),
                ],
            )
            entra_client.app_registrations = {DOMAIN: {app_id: app}}

            check = entra_app_registration_credential_not_expired()
            result = check.execute()
            assert len(result) == 2
            statuses = {r.status for r in result}
            assert "FAIL" in statuses
            assert "PASS" in statuses
