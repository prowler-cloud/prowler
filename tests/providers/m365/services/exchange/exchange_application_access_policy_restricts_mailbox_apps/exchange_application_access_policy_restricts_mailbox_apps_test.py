import importlib
from unittest import mock

from prowler.providers.m365.services.entra import entra_service
from prowler.providers.m365.services.exchange import exchange_service
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE = (
    "prowler.providers.m365.services.exchange."
    "exchange_application_access_policy_restricts_mailbox_apps."
    "exchange_application_access_policy_restricts_mailbox_apps"
)


class Test_exchange_application_access_policy_restricts_mailbox_apps:
    def test_powershell_unavailable_returns_manual(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.organization_config = None
        exchange_client.application_access_policies = None

        entra_client = mock.MagicMock()
        entra_client.exchange_mailbox_permission_service_principals = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_application_access_policy_restricts_mailbox_apps.exchange_application_access_policy_restricts_mailbox_apps.exchange_client",
                new=exchange_client,
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_application_access_policy_restricts_mailbox_apps.exchange_application_access_policy_restricts_mailbox_apps.entra_client",
                new=entra_client,
            ),
        ):
            check_module = importlib.import_module(CHECK_MODULE)

            result = (
                check_module.exchange_application_access_policy_restricts_mailbox_apps().execute()
            )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "ExchangeOnlineTenant"
        assert "Exchange Online PowerShell is unavailable" in result[0].status_extended

    def test_no_resources(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.organization_config = None
        exchange_client.application_access_policies = []

        entra_client = mock.MagicMock()
        entra_client.exchange_mailbox_permission_service_principals = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_application_access_policy_restricts_mailbox_apps.exchange_application_access_policy_restricts_mailbox_apps.exchange_client",
                new=exchange_client,
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_application_access_policy_restricts_mailbox_apps.exchange_application_access_policy_restricts_mailbox_apps.entra_client",
                new=entra_client,
            ),
        ):
            check_module = importlib.import_module(CHECK_MODULE)

            result = (
                check_module.exchange_application_access_policy_restricts_mailbox_apps().execute()
            )

        assert len(result) == 0

    def test_graph_collection_unavailable_returns_manual(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.organization_config = None
        exchange_client.application_access_policies = []

        entra_client = mock.MagicMock()
        entra_client.exchange_mailbox_permission_service_principals = {}
        entra_client.exchange_mailbox_permission_service_principals_error = (
            "RuntimeError: Graph unavailable"
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_application_access_policy_restricts_mailbox_apps.exchange_application_access_policy_restricts_mailbox_apps.exchange_client",
                new=exchange_client,
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_application_access_policy_restricts_mailbox_apps.exchange_application_access_policy_restricts_mailbox_apps.entra_client",
                new=entra_client,
            ),
        ):
            check_module = importlib.import_module(CHECK_MODULE)

            result = (
                check_module.exchange_application_access_policy_restricts_mailbox_apps().execute()
            )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "ExchangeOnlineTenant"
        assert (
            "Microsoft Graph mailbox permission collection failed"
            in result[0].status_extended
        )

    def test_service_principal_without_policy_fails(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.organization_config = None
        exchange_client.application_access_policies = []

        entra_client = mock.MagicMock()
        entra_client.exchange_mailbox_permission_service_principals = {
            "sp-id": entra_service.ServicePrincipal(
                id="sp-id",
                name="Mailbox App",
                app_id="app-id",
                exchange_mailbox_permissions=["Mail.Read", "Mail.Send"],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_application_access_policy_restricts_mailbox_apps.exchange_application_access_policy_restricts_mailbox_apps.exchange_client",
                new=exchange_client,
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_application_access_policy_restricts_mailbox_apps.exchange_application_access_policy_restricts_mailbox_apps.entra_client",
                new=entra_client,
            ),
        ):
            check_module = importlib.import_module(CHECK_MODULE)

            result = (
                check_module.exchange_application_access_policy_restricts_mailbox_apps().execute()
            )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == "sp-id"
        assert result[0].resource_name == "Mailbox App"
        assert "app-id" in result[0].status_extended
        assert "Mail.Read, Mail.Send" in result[0].status_extended

    def test_service_principal_with_policy_passes(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.organization_config = None
        exchange_client.application_access_policies = [
            exchange_service.ApplicationAccessPolicy(
                identity="policy-id",
                app_id="app-id",
                access_right="RestrictAccess",
                description="Restrict mailbox access",
            )
        ]

        entra_client = mock.MagicMock()
        entra_client.exchange_mailbox_permission_service_principals = {
            "sp-id": entra_service.ServicePrincipal(
                id="sp-id",
                name="Mailbox App",
                app_id="app-id",
                exchange_mailbox_permissions=["Mail.Read"],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_application_access_policy_restricts_mailbox_apps.exchange_application_access_policy_restricts_mailbox_apps.exchange_client",
                new=exchange_client,
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_application_access_policy_restricts_mailbox_apps.exchange_application_access_policy_restricts_mailbox_apps.entra_client",
                new=entra_client,
            ),
        ):
            check_module = importlib.import_module(CHECK_MODULE)

            result = (
                check_module.exchange_application_access_policy_restricts_mailbox_apps().execute()
            )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "sp-id"
        assert (
            "is restricted using an Application Access Policy"
            in result[0].status_extended
        )

    def test_service_principal_with_deny_access_policy_fails(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN
        exchange_client.organization_config = None
        exchange_client.application_access_policies = [
            exchange_service.ApplicationAccessPolicy(
                identity="policy-id",
                app_id="app-id",
                access_right="DenyAccess",
                description="Deny mailbox access",
            )
        ]

        entra_client = mock.MagicMock()
        entra_client.exchange_mailbox_permission_service_principals = {
            "sp-id": entra_service.ServicePrincipal(
                id="sp-id",
                name="Mailbox App",
                app_id="app-id",
                exchange_mailbox_permissions=["Mail.Read"],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_application_access_policy_restricts_mailbox_apps.exchange_application_access_policy_restricts_mailbox_apps.exchange_client",
                new=exchange_client,
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_application_access_policy_restricts_mailbox_apps.exchange_application_access_policy_restricts_mailbox_apps.entra_client",
                new=entra_client,
            ),
        ):
            check_module = importlib.import_module(CHECK_MODULE)

            result = (
                check_module.exchange_application_access_policy_restricts_mailbox_apps().execute()
            )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == "sp-id"
        assert result[0].resource_name == "Mailbox App"
        assert (
            "is not restricted using an Application Access Policy"
            in result[0].status_extended
        )
