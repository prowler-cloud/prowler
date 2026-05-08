from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import ServicePrincipal
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

TENANT = "audited_tenant"


class Test_entra_service_principal_privileged_role_no_owners:
    def test_no_privileged_service_principals(self):
        """No privileged SPs found in tenant (empty dict): expected PASS."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = TENANT
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.__init__",
                return_value=None,
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {TENANT: {}}

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No service principals with privileged directory roles were found."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Service Principals"
            assert result[0].resource_id == "servicePrincipals"

    def test_permissions_error(self):
        """Role assignments could not be fetched (None): expected MANUAL."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = TENANT
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.__init__",
                return_value=None,
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {TENANT: None}

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == "Could not retrieve role assignments or service principal owners. "
                "Please ensure Directory.Read.All is granted to the Prowler application."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Service Principals"
            assert result[0].resource_id == "servicePrincipals"

    def test_privileged_sp_no_owners(self):
        """Privileged SP with no owners: expected PASS."""
        sp_id = str(uuid4())
        sp_name = "My Automation App"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = TENANT
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.__init__",
                return_value=None,
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {
                TENANT: {
                    sp_id: ServicePrincipal(
                        id=sp_id,
                        name=sp_name,
                        app_id=str(uuid4()),
                        privileged_roles=["GLOBAL_ADMINISTRATOR"],
                        sp_owner_ids=[],
                        app_owner_ids=[],
                    )
                }
            }

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Service principal {sp_name} holds privileged role(s) [GLOBAL_ADMINISTRATOR] "
                f"and has no owners on either the service principal or its parent app registration."
            )
            assert result[0].resource_name == sp_name
            assert result[0].resource_id == sp_id

    def test_privileged_sp_with_sp_owners(self):
        """Privileged SP with owners on the service principal itself: expected FAIL."""
        sp_id = str(uuid4())
        sp_name = "Dangerous App"
        owner_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = TENANT
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.__init__",
                return_value=None,
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {
                TENANT: {
                    sp_id: ServicePrincipal(
                        id=sp_id,
                        name=sp_name,
                        app_id=str(uuid4()),
                        privileged_roles=["GLOBAL_ADMINISTRATOR"],
                        sp_owner_ids=[owner_id],
                        app_owner_ids=[],
                    )
                }
            }

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Service principal {sp_name} holds privileged role(s) [GLOBAL_ADMINISTRATOR] "
                f"and has 1 owner(s) "
                f"(SP owners: 1, app registration owners: 0)."
            )
            assert result[0].resource_name == sp_name
            assert result[0].resource_id == sp_id

    def test_privileged_sp_with_app_owners(self):
        """Privileged SP with owners on the parent app registration: expected FAIL."""
        sp_id = str(uuid4())
        sp_name = "Risky App"
        app_owner_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = TENANT
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.__init__",
                return_value=None,
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {
                TENANT: {
                    sp_id: ServicePrincipal(
                        id=sp_id,
                        name=sp_name,
                        app_id=str(uuid4()),
                        privileged_roles=["PRIVILEGED_ROLE_ADMINISTRATOR"],
                        sp_owner_ids=[],
                        app_owner_ids=[app_owner_id],
                    )
                }
            }

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Service principal {sp_name} holds privileged role(s) [PRIVILEGED_ROLE_ADMINISTRATOR] "
                f"and has 1 owner(s) "
                f"(SP owners: 0, app registration owners: 1)."
            )
            assert result[0].resource_name == sp_name
            assert result[0].resource_id == sp_id

    def test_privileged_sp_with_both_owners(self):
        """Privileged SP with owners on both SP and app registration: expected FAIL."""
        sp_id = str(uuid4())
        sp_name = "Very Risky App"
        sp_owner_id = str(uuid4())
        app_owner_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = TENANT
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.__init__",
                return_value=None,
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {
                TENANT: {
                    sp_id: ServicePrincipal(
                        id=sp_id,
                        name=sp_name,
                        app_id=str(uuid4()),
                        privileged_roles=["GLOBAL_ADMINISTRATOR", "SECURITY_ADMINISTRATOR"],
                        sp_owner_ids=[sp_owner_id],
                        app_owner_ids=[app_owner_id],
                    )
                }
            }

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Service principal {sp_name} holds privileged role(s) [GLOBAL_ADMINISTRATOR, SECURITY_ADMINISTRATOR] "
                f"and has 2 owner(s) "
                f"(SP owners: 1, app registration owners: 1)."
            )
            assert result[0].resource_name == sp_name
            assert result[0].resource_id == sp_id