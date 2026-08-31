from datetime import datetime, timedelta, timezone
from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    DOMAIN,
    TENANT_IDS,
    set_mocked_azure_provider,
)

TENANT_ID = TENANT_IDS[0]


class Test_entra_user_with_recent_sign_in:
    def test_entra_no_tenants(self):
        entra_client = mock.MagicMock
        entra_client.sign_in_activity_errors = {}
        entra_client.tenant_ids = [TENANT_ID]

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
        entra_client.sign_in_activity_errors = {}
        entra_client.tenant_ids = [TENANT_ID]
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
            from prowler.providers.azure.services.entra.entra_service import User
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )

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
        entra_client.sign_in_activity_errors = {}
        entra_client.tenant_ids = [TENANT_ID]
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
            from prowler.providers.azure.services.entra.entra_service import User
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )

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
            assert "no recorded sign-in activity" in result[0].status_extended

    def test_entra_single_user_no_sign_in_data_fails(self):
        entra_client = mock.MagicMock
        entra_client.sign_in_activity_errors = {}
        entra_client.tenant_ids = [TENANT_ID]
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
            from prowler.providers.azure.services.entra.entra_service import User
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )

            user = User(
                id=user_id,
                name="single-user",
                account_enabled=True,
                last_sign_in=None,
            )

            entra_client.users = {DOMAIN: {f"single-user@{DOMAIN}": user}}

            check = entra_user_with_recent_sign_in()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "no recorded sign-in activity" in result[0].status_extended

    def test_entra_user_stale_sign_in(self):
        entra_client = mock.MagicMock
        entra_client.sign_in_activity_errors = {}
        entra_client.tenant_ids = [TENANT_ID]
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
            from prowler.providers.azure.services.entra.entra_service import User
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )

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
        entra_client.sign_in_activity_errors = {}
        entra_client.tenant_ids = [TENANT_ID]
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
            from prowler.providers.azure.services.entra.entra_service import User
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )

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

    def test_entra_all_users_no_sign_in_data_fail(self):
        entra_client = mock.MagicMock
        entra_client.sign_in_activity_errors = {}
        entra_client.tenant_ids = [TENANT_ID]

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
            from prowler.providers.azure.services.entra.entra_service import User
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )

            # Multiple enabled users, ALL with no sign-in data = license issue
            users = {}
            for i in range(5):
                uid = str(uuid4())
                users[f"user{i}@{DOMAIN}"] = User(
                    id=uid,
                    name=f"user{i}",
                    account_enabled=True,
                    last_sign_in=None,
                )

            entra_client.users = {DOMAIN: users}

            check = entra_user_with_recent_sign_in()
            result = check.execute()
            # Graph returned the users without any sign-in: every one is stale
            assert len(result) == 5
            assert all(r.status == "FAIL" for r in result)

    def test_entra_sign_in_activity_errors_reports_single_manual(self):
        """Graph refused signInActivity (no P1/P2 or AuditLog.Read.All) -> one tenant MANUAL."""
        entra_client = mock.MagicMock
        entra_client.tenant_ids = [TENANT_ID]
        entra_client.sign_in_activity_errors = {
            DOMAIN: "ODataError HTTP 403 Authentication_RequestFromNonPremiumTenantOrB2CTenant"
        }

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
            from prowler.providers.azure.services.entra.entra_service import User
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )

            # Users were re-fetched without signInActivity, so they exist but
            # must not be evaluated individually.
            entra_client.users = {
                DOMAIN: {
                    str(uuid4()): User(
                        id=str(uuid4()), name="user", account_enabled=True
                    )
                }
            }

            result = entra_user_with_recent_sign_in().execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Entra ID P1/P2" in result[0].status_extended
            assert "AuditLog.Read.All" in result[0].status_extended
            assert (
                "Authentication_RequestFromNonPremiumTenantOrB2CTenant"
                in result[0].status_extended
            )
            assert result[0].resource_id == TENANT_ID
            assert result[0].resource_name == DOMAIN
            assert result[0].subscription == f"Tenant: {DOMAIN}"

    def test_entra_user_never_signed_in_when_telemetry_exists_for_tenant(self):
        entra_client = mock.MagicMock
        entra_client.sign_in_activity_errors = {}
        entra_client.tenant_ids = [TENANT_ID]

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
            from prowler.providers.azure.services.entra.entra_service import User
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )

            active_user = User(
                id=str(uuid4()),
                name="active-user",
                account_enabled=True,
                last_sign_in=datetime.now(timezone.utc) - timedelta(days=5),
            )
            never_user = User(
                id=str(uuid4()),
                name="never-user",
                account_enabled=True,
                last_sign_in=None,
            )

            entra_client.users = {
                DOMAIN: {
                    f"active-user@{DOMAIN}": active_user,
                    f"never-user@{DOMAIN}": never_user,
                }
            }

            check = entra_user_with_recent_sign_in()
            result = check.execute()
            assert len(result) == 2
            assert any(
                r.status == "PASS" and "5 days ago" in r.status_extended for r in result
            )
            assert any(
                r.status == "FAIL"
                and "no recorded sign-in activity" in r.status_extended
                for r in result
            )

    def test_entra_user_boundary_90_days(self):
        entra_client = mock.MagicMock
        entra_client.sign_in_activity_errors = {}
        entra_client.tenant_ids = [TENANT_ID]
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
            from prowler.providers.azure.services.entra.entra_service import User
            from prowler.providers.azure.services.entra.entra_user_with_recent_sign_in.entra_user_with_recent_sign_in import (
                entra_user_with_recent_sign_in,
            )

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
