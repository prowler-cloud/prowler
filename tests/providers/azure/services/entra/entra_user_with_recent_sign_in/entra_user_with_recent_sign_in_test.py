from datetime import datetime, timezone, timedelta
from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import DOMAIN, set_mocked_azure_provider


class Test_entra_user_with_recent_sign_in:
    def test_entra_no_tenants(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )

            entra_client.users = {}

            check = entra_user_with_recent_sign_in()
            result = check.execute()
            assert len(result) == 0

    def test_entra_user_disabled(self):
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )
            from prowler.providers.azure.services.entra.entra_service import User

            user = User(
                id=user_id,
                name="disabled-user",
                account_enabled=False,
                last_sign_in=None,
            )

            entra_client.users = {DOMAIN: {f"disabled-user@{DOMAIN}": user}}

            check = entra_user_with_recent_sign_in()
            result = check.execute()
            assert len(result) == 0

    def test_entra_user_never_signed_in(self):
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )
            from prowler.providers.azure.services.entra.entra_service import User

            user = User(
                id=user_id,
                name="never-signed-in",
                account_enabled=True,
                last_sign_in=None,
            )

            entra_client.users = {DOMAIN: {f"never-signed-in@{DOMAIN}": user}}

            check = entra_user_with_recent_sign_in()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "never signed in" in result[0].status_extended

    def test_entra_user_stale_sign_in(self):
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )
            from prowler.providers.azure.services.entra.entra_service import User

            user = User(
                id=user_id,
                name="stale-user",
                account_enabled=True,
                last_sign_in=datetime.now(timezone.utc) - timedelta(days=120),
            )

            entra_client.users = {DOMAIN: {f"stale-user@{DOMAIN}": user}}

            check = entra_user_with_recent_sign_in()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "120 days" in result[0].status_extended

    def test_entra_user_recent_sign_in(self):
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )
            from prowler.providers.azure.services.entra.entra_service import User

            user = User(
                id=user_id,
                name="active-user",
                account_enabled=True,
                last_sign_in=datetime.now(timezone.utc) - timedelta(days=10),
            )

            entra_client.users = {DOMAIN: {f"active-user@{DOMAIN}": user}}

            check = entra_user_with_recent_sign_in()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "10 days ago" in result[0].status_extended

    def test_entra_user_boundary_90_days(self):
        entra_client = mock.MagicMock
        user_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )
            from prowler.providers.azure.services.entra.entra_service import User

            user = User(
                id=user_id,
                name="boundary-user",
                account_enabled=True,
                last_sign_in=datetime.now(timezone.utc) - timedelta(days=90),
            )

            entra_client.users = {DOMAIN: {f"boundary-user@{DOMAIN}": user}}

            check = entra_user_with_recent_sign_in()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "90 days ago" in result[0].status_extended
