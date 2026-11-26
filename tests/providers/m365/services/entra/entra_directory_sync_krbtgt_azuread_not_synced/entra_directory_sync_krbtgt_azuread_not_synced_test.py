from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    Organization,
    User,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_directory_sync_krbtgt_azuread_not_synced."
    "entra_directory_sync_krbtgt_azuread_not_synced"
)


def _hybrid_org():
    return Organization(
        id="org-001",
        name="Hybrid Org",
        on_premises_sync_enabled=True,
    )


def _cloud_only_org():
    return Organization(
        id="org-001",
        name="Cloud Only Org",
        on_premises_sync_enabled=False,
    )


def _krbtgt_user(**overrides):
    """Return a synced user that matches krbtgt_AzureAD by default."""
    defaults = dict(
        id="user-krbtgt-001",
        name="krbtgt_AzureAD",
        on_premises_sync_enabled=True,
        user_principal_name="krbtgt_AzureAD@contoso.com",
        mail_nickname="krbtgt_AzureAD",
        on_premises_sam_account_name="krbtgt_AzureAD",
        on_premises_distinguished_name="CN=krbtgt_AzureAD,CN=Users,DC=contoso,DC=com",
    )
    defaults.update(overrides)
    return User(**defaults)


def _normal_synced_user():
    """Return a regular synced user that should NOT match."""
    return User(
        id="user-normal-001",
        name="John Doe",
        on_premises_sync_enabled=True,
        user_principal_name="john.doe@contoso.com",
        mail_nickname="john.doe",
        on_premises_sam_account_name="john.doe",
        on_premises_distinguished_name="CN=John Doe,CN=Users,DC=contoso,DC=com",
    )


class Test_entra_directory_sync_krbtgt_azuread_not_synced:
    def test_cloud_only_tenant(self):
        """PASS when the tenant is cloud-only."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            entra_client.organizations = [_cloud_only_org()]
            entra_client.users = {}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "cloud-only" in result[0].status_extended
            assert result[0].resource_id == "org-001"
            assert result[0].resource_name == "Cloud Only Org"

    def test_hybrid_no_krbtgt_synced(self):
        """PASS when the tenant is hybrid but krbtgt_AzureAD is not synced."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            normal_user = _normal_synced_user()
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {normal_user.id: normal_user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not have the krbtgt_AzureAD" in result[0].status_extended
            assert result[0].resource_id == "org-001"
            assert result[0].resource_name == "Hybrid Org"

    def test_hybrid_krbtgt_synced_display_name(self):
        """FAIL when a synced user matches krbtgt_AzureAD by displayName."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            user = _krbtgt_user()
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "displayName" in result[0].status_extended
            assert result[0].resource_id == "user-krbtgt-001"
            assert result[0].resource_name == "krbtgt_AzureAD"

    def test_hybrid_krbtgt_synced_mail_nickname(self):
        """FAIL when a synced user matches only by mailNickname."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            user = _krbtgt_user(
                name="Some Other Name",
                mail_nickname="krbtgt_AzureAD",
                on_premises_sam_account_name="other",
                user_principal_name="other@contoso.com",
                on_premises_distinguished_name="CN=Other,CN=Users,DC=contoso,DC=com",
            )
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "mailNickname" in result[0].status_extended

    def test_hybrid_krbtgt_synced_sam_account_name(self):
        """FAIL when a synced user matches only by onPremisesSamAccountName."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            user = _krbtgt_user(
                name="Some Other Name",
                mail_nickname="other",
                on_premises_sam_account_name="KRBTGT_AZUREAD",
                user_principal_name="other@contoso.com",
                on_premises_distinguished_name="CN=Other,CN=Users,DC=contoso,DC=com",
            )
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "onPremisesSamAccountName" in result[0].status_extended

    def test_hybrid_krbtgt_synced_upn_prefix(self):
        """FAIL when a synced user matches only by UPN prefix."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            user = _krbtgt_user(
                name="Some Other Name",
                mail_nickname="other",
                on_premises_sam_account_name="other",
                user_principal_name="krbtgt_AzureAD@contoso.com",
                on_premises_distinguished_name="CN=Other,CN=Users,DC=contoso,DC=com",
            )
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "userPrincipalName" in result[0].status_extended

    def test_hybrid_krbtgt_synced_distinguished_name(self):
        """FAIL when a synced user matches only by onPremisesDistinguishedName."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            user = _krbtgt_user(
                name="Some Other Name",
                mail_nickname="other",
                on_premises_sam_account_name="other",
                user_principal_name="other@contoso.com",
                on_premises_distinguished_name="CN=krbtgt_AzureAD,CN=Users,DC=contoso,DC=com",
            )
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "onPremisesDistinguishedName" in result[0].status_extended

    def test_case_insensitive_matching(self):
        """FAIL with case-insensitive display name match."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            user = _krbtgt_user(name="KRBTGT_AZUREAD")
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "displayName" in result[0].status_extended

    def test_case_insensitive_matching_mixed_case(self):
        """FAIL with mixed-case display name (e.g. Krbtgt_azuread)."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            user = _krbtgt_user(name="Krbtgt_azuread")
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_cloud_only_user_named_krbtgt_not_matched(self):
        """PASS when a cloud-only user is named krbtgt_AzureAD but is not synced."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            # User is named krbtgt_AzureAD but on_premises_sync_enabled is False.
            user = User(
                id="user-cloud-001",
                name="krbtgt_AzureAD",
                on_premises_sync_enabled=False,
                user_principal_name="krbtgt_AzureAD@contoso.com",
                mail_nickname="krbtgt_AzureAD",
            )
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_rodc_krbtgt_not_matched(self):
        """PASS when a synced user is krbtgt_12345 (RODC), not krbtgt_AzureAD."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            user = User(
                id="user-rodc-001",
                name="krbtgt_12345",
                on_premises_sync_enabled=True,
                user_principal_name="krbtgt_12345@contoso.com",
                mail_nickname="krbtgt_12345",
                on_premises_sam_account_name="krbtgt_12345",
                on_premises_distinguished_name="CN=krbtgt_12345,CN=Users,DC=contoso,DC=com",
            )
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_users_error_hybrid(self):
        """MANUAL when users could not be read on a hybrid tenant."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {}
            entra_client.users_error = "Insufficient privileges to read users"

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Cannot evaluate" in result[0].status_extended
            assert "Insufficient privileges" in result[0].status_extended

    def test_no_organizations(self):
        """MANUAL when organizations are unavailable (empty list)."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            entra_client.organizations = []
            entra_client.users = {}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Directory.Read.All" in result[0].status_extended

    def test_organizations_none(self):
        """MANUAL when organizations attribute is None (fallback to empty)."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            entra_client.organizations = None
            entra_client.users = {}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Directory.Read.All" in result[0].status_extended

    def test_hybrid_no_synced_users_at_all(self):
        """PASS when the tenant is hybrid but has no synced users at all."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not have the krbtgt_AzureAD" in result[0].status_extended

    def test_dn_regex_mid_string(self):
        """FAIL when krbtgt_AzureAD appears mid-DN with comma prefix."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            user = _krbtgt_user(
                name="Some Other Name",
                mail_nickname="other",
                on_premises_sam_account_name="other",
                user_principal_name="other@contoso.com",
                on_premises_distinguished_name="OU=Special,CN=krbtgt_AzureAD,CN=Users,DC=contoso,DC=com",
            )
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "onPremisesDistinguishedName" in result[0].status_extended

    def test_dn_no_match_when_not_cn(self):
        """PASS when DN contains krbtgt_AzureAD but not as a CN= component."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            # krbtgt_AzureAD appears in an OU, not as CN= — should NOT match regex.
            user = _krbtgt_user(
                name="Some Other Name",
                mail_nickname="other",
                on_premises_sam_account_name="other",
                user_principal_name="other@contoso.com",
                on_premises_distinguished_name="CN=SomeUser,OU=krbtgt_AzureAD,DC=contoso,DC=com",
            )
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_multiple_krbtgt_users_multiple_fails(self):
        """FAIL for each matching user when multiple krbtgt_AzureAD users exist."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            user1 = _krbtgt_user(id="user-krbtgt-001", name="krbtgt_AzureAD")
            user2 = _krbtgt_user(
                id="user-krbtgt-002",
                name="krbtgt_AzureAD",
                user_principal_name="krbtgt_AzureAD@fabrikam.com",
            )
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user1.id: user1, user2.id: user2}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 2
            assert all(r.status == "FAIL" for r in result)
            resource_ids = {r.resource_id for r in result}
            assert resource_ids == {"user-krbtgt-001", "user-krbtgt-002"}

    def test_mixed_users_only_krbtgt_fails(self):
        """Only the matching user FAILs; normal synced users do not produce findings."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            krbtgt = _krbtgt_user()
            normal = _normal_synced_user()
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {krbtgt.id: krbtgt, normal.id: normal}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "user-krbtgt-001"

    def test_status_extended_includes_upn_and_dn(self):
        """FAIL status_extended message includes UPN and DN when available."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            user = _krbtgt_user()
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert "krbtgt_AzureAD@contoso.com" in result[0].status_extended
            assert (
                "CN=krbtgt_AzureAD,CN=Users,DC=contoso,DC=com"
                in result[0].status_extended
            )
            assert (
                "Microsoft Entra Kerberos krbtgt account" in result[0].status_extended
            )

    def test_user_with_none_optional_fields(self):
        """PASS when synced user has None for all optional name fields."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            # Synced user with minimal fields — should not match krbtgt_AzureAD.
            user = User(
                id="user-minimal-001",
                name="Minimal User",
                on_premises_sync_enabled=True,
                user_principal_name=None,
                mail_nickname=None,
                on_premises_sam_account_name=None,
                on_premises_distinguished_name=None,
            )
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_upn_case_insensitive_match(self):
        """FAIL when UPN prefix matches case-insensitively."""
        entra_client = mock.MagicMock()

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
            from prowler.providers.m365.services.entra.entra_directory_sync_krbtgt_azuread_not_synced.entra_directory_sync_krbtgt_azuread_not_synced import (
                entra_directory_sync_krbtgt_azuread_not_synced,
            )

            user = _krbtgt_user(
                name="Some Other Name",
                mail_nickname="other",
                on_premises_sam_account_name="other",
                user_principal_name="KRBTGT_AZUREAD@contoso.com",
                on_premises_distinguished_name="CN=Other,CN=Users,DC=contoso,DC=com",
            )
            entra_client.organizations = [_hybrid_org()]
            entra_client.users = {user.id: user}
            entra_client.users_error = None

            check = entra_directory_sync_krbtgt_azuread_not_synced()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "userPrincipalName" in result[0].status_extended
