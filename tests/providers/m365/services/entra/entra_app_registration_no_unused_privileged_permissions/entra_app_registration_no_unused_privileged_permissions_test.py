from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    OAuthApp,
    OAuthAppPermission,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_app_registration_no_unused_privileged_permissions:
    def test_no_oauth_apps(self):
        """No OAuth apps registered in tenant (empty dict): expected PASS."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {}

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No OAuth applications are registered in the tenant."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "OAuth Applications"
            assert result[0].resource_id == "oauthApps"

    def test_no_oauth_apps_none(self):
        """OAuth apps is None (App Governance not enabled): expected FAIL."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = None

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "OAuth App Governance data is unavailable. Enable App Governance in Microsoft Defender for Cloud Apps and grant ThreatHunting.Read.All to evaluate unused privileged permissions."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "OAuth Applications"
            assert result[0].resource_id == "oauthApps"

    def test_app_no_permissions(self):
        """App with no permissions: expected PASS."""
        app_id = str(uuid4())
        app_name = "Test App No Permissions"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {
                app_id: OAuthApp(
                    id=app_id,
                    name=app_name,
                    status="Enabled",
                    privilege_level="Low",
                    permissions=[],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=False,
                    last_used_time=None,
                    app_origin="Internal",
                )
            }

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"App registration {app_name} has no unused privileged permissions."
            )
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_app_all_permissions_in_use(self):
        """App with all privileged permissions in use: expected PASS."""
        app_id = str(uuid4())
        app_name = "Test App All In Use"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {
                app_id: OAuthApp(
                    id=app_id,
                    name=app_name,
                    status="Enabled",
                    privilege_level="High",
                    permissions=[
                        OAuthAppPermission(
                            name="Mail.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="InUse",
                        ),
                        OAuthAppPermission(
                            name="User.Read.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="InUse",
                        ),
                    ],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=True,
                    last_used_time="2024-01-15T10:30:00Z",
                    app_origin="Internal",
                )
            }

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"App registration {app_name} has no unused privileged permissions."
            )
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_app_low_privilege_unused(self):
        """App with unused low privilege permissions (not high): expected PASS."""
        app_id = str(uuid4())
        app_name = "Test App Low Privilege Unused"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {
                app_id: OAuthApp(
                    id=app_id,
                    name=app_name,
                    status="Enabled",
                    privilege_level="Low",
                    permissions=[
                        OAuthAppPermission(
                            name="User.Read",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Delegated",
                            privilege_level="Low",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="openid",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Delegated",
                            privilege_level="Low",
                            usage_status="NotInUse",
                        ),
                    ],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=False,
                    last_used_time=None,
                    app_origin="External",
                )
            }

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"App registration {app_name} has no unused privileged permissions."
            )
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_app_medium_privilege_unused(self):
        """App with unused medium privilege permissions (not high): expected PASS."""
        app_id = str(uuid4())
        app_name = "Test App Medium Privilege Unused"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {
                app_id: OAuthApp(
                    id=app_id,
                    name=app_name,
                    status="Enabled",
                    privilege_level="Medium",
                    permissions=[
                        OAuthAppPermission(
                            name="Files.Read",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Delegated",
                            privilege_level="Medium",
                            usage_status="NotInUse",
                        ),
                    ],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=False,
                    last_used_time=None,
                    app_origin="External",
                )
            }

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"App registration {app_name} has no unused privileged permissions."
            )
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_app_one_unused_high_privilege_permission(self):
        """App with one unused high privilege permission: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Test App One Unused High"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {
                app_id: OAuthApp(
                    id=app_id,
                    name=app_name,
                    status="Enabled",
                    privilege_level="High",
                    permissions=[
                        OAuthAppPermission(
                            name="Mail.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="User.Read",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Delegated",
                            privilege_level="Low",
                            usage_status="InUse",
                        ),
                    ],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=True,
                    last_used_time="2024-01-15T10:30:00Z",
                    app_origin="Internal",
                )
            }

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"App registration {app_name} has 1 unused privileged permission(s): Mail.ReadWrite.All."
            )
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_app_multiple_unused_high_privilege_permissions(self):
        """App with multiple unused high privilege permissions: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Test App Multiple Unused High"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {
                app_id: OAuthApp(
                    id=app_id,
                    name=app_name,
                    status="Enabled",
                    privilege_level="High",
                    permissions=[
                        OAuthAppPermission(
                            name="Mail.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="Directory.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="User.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                    ],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=True,
                    last_used_time="2024-01-15T10:30:00Z",
                    app_origin="External",
                )
            }

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"App registration {app_name} has 3 unused privileged permission(s): Mail.ReadWrite.All, Directory.ReadWrite.All, User.ReadWrite.All."
            )
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_app_more_than_five_unused_high_privilege_permissions(self):
        """App with more than 5 unused high privilege permissions: expected FAIL with truncated list."""
        app_id = str(uuid4())
        app_name = "Test App Many Unused High"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {
                app_id: OAuthApp(
                    id=app_id,
                    name=app_name,
                    status="Enabled",
                    privilege_level="High",
                    permissions=[
                        OAuthAppPermission(
                            name="Mail.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="Directory.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="User.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="Group.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="Sites.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="RoleManagement.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="Application.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                    ],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=True,
                    last_used_time="2024-01-15T10:30:00Z",
                    app_origin="External",
                )
            }

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"App registration {app_name} has 7 unused privileged permission(s): Mail.ReadWrite.All, Directory.ReadWrite.All, User.ReadWrite.All, Group.ReadWrite.All, Sites.ReadWrite.All (and 2 more)."
            )
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_app_unused_with_not_in_use_status(self):
        """App with unused permission using 'not_in_use' status variant: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Test App NotInUse Variant"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {
                app_id: OAuthApp(
                    id=app_id,
                    name=app_name,
                    status="Enabled",
                    privilege_level="High",
                    permissions=[
                        OAuthAppPermission(
                            name="Mail.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="not_in_use",
                        ),
                    ],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=True,
                    last_used_time=None,
                    app_origin="Internal",
                )
            }

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"App registration {app_name} has 1 unused privileged permission(s): Mail.ReadWrite.All."
            )
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_multiple_apps_mixed_results(self):
        """Multiple apps with mixed results: one PASS and one FAIL."""
        app_id_pass = str(uuid4())
        app_name_pass = "Test App Pass"
        app_id_fail = str(uuid4())
        app_name_fail = "Test App Fail"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {
                app_id_pass: OAuthApp(
                    id=app_id_pass,
                    name=app_name_pass,
                    status="Enabled",
                    privilege_level="High",
                    permissions=[
                        OAuthAppPermission(
                            name="Mail.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="InUse",
                        ),
                    ],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=True,
                    last_used_time="2024-01-15T10:30:00Z",
                    app_origin="Internal",
                ),
                app_id_fail: OAuthApp(
                    id=app_id_fail,
                    name=app_name_fail,
                    status="Enabled",
                    privilege_level="High",
                    permissions=[
                        OAuthAppPermission(
                            name="Directory.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                    ],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=True,
                    last_used_time="2024-01-15T10:30:00Z",
                    app_origin="External",
                ),
            }

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 2

            # Find results by app ID
            result_pass = next(r for r in result if r.resource_id == app_id_pass)
            result_fail = next(r for r in result if r.resource_id == app_id_fail)

            assert result_pass.status == "PASS"
            assert (
                result_pass.status_extended
                == f"App registration {app_name_pass} has no unused privileged permissions."
            )
            assert result_pass.resource_name == app_name_pass

            assert result_fail.status == "FAIL"
            assert (
                result_fail.status_extended
                == f"App registration {app_name_fail} has 1 unused privileged permission(s): Directory.ReadWrite.All."
            )
            assert result_fail.resource_name == app_name_fail

    def test_app_mixed_privilege_levels_unused(self):
        """App with mixed privilege levels (High and Low) unused: only High triggers FAIL."""
        app_id = str(uuid4())
        app_name = "Test App Mixed Privileges"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {
                app_id: OAuthApp(
                    id=app_id,
                    name=app_name,
                    status="Enabled",
                    privilege_level="High",
                    permissions=[
                        OAuthAppPermission(
                            name="Mail.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="User.Read",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Delegated",
                            privilege_level="Low",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="Files.Read",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Delegated",
                            privilege_level="Medium",
                            usage_status="NotInUse",
                        ),
                    ],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=True,
                    last_used_time="2024-01-15T10:30:00Z",
                    app_origin="Internal",
                )
            }

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Only the High privilege permission should be reported
            assert (
                result[0].status_extended
                == f"App registration {app_name} has 1 unused privileged permission(s): Mail.ReadWrite.All."
            )
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_app_high_privilege_in_use_and_unused(self):
        """App with some high privilege permissions in use and some unused: expected FAIL."""
        app_id = str(uuid4())
        app_name = "Test App Partial Usage"
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {
                app_id: OAuthApp(
                    id=app_id,
                    name=app_name,
                    status="Enabled",
                    privilege_level="High",
                    permissions=[
                        OAuthAppPermission(
                            name="Mail.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="InUse",
                        ),
                        OAuthAppPermission(
                            name="Directory.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="NotInUse",
                        ),
                        OAuthAppPermission(
                            name="User.ReadWrite.All",
                            target_app_id="00000003-0000-0000-c000-000000000000",
                            target_app_name="Microsoft Graph",
                            permission_type="Application",
                            privilege_level="High",
                            usage_status="InUse",
                        ),
                    ],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=True,
                    last_used_time="2024-01-15T10:30:00Z",
                    app_origin="Internal",
                )
            }

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"App registration {app_name} has 1 unused privileged permission(s): Directory.ReadWrite.All."
            )
            assert result[0].resource_name == app_name
            assert result[0].resource_id == app_id

    def test_app_without_name_uses_id(self):
        """App without a name should use app_id as resource_name."""
        app_id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_app_registration_no_unused_privileged_permissions.entra_app_registration_no_unused_privileged_permissions import (
                entra_app_registration_no_unused_privileged_permissions,
            )

            entra_client.oauth_apps = {
                app_id: OAuthApp(
                    id=app_id,
                    name="",
                    status="Enabled",
                    privilege_level="Low",
                    permissions=[],
                    service_principal_id=str(uuid4()),
                    is_admin_consented=False,
                    last_used_time=None,
                    app_origin="Internal",
                )
            }

            check = entra_app_registration_no_unused_privileged_permissions()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            # When app name is empty, the check uses the app_id as the resource_name
            assert result[0].resource_name == app_id
            assert result[0].resource_id == app_id
