from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


def _make_policy(
    *,
    display_name="Test Policy",
    state=ConditionalAccessPolicyState.ENABLED,
    included_users=None,
    excluded_users=None,
    included_groups=None,
    excluded_groups=None,
    included_roles=None,
    excluded_roles=None,
):
    """Build a ConditionalAccessPolicy with the minimum fields required by the model."""
    policy_id = str(uuid4())
    policy = ConditionalAccessPolicy(
        id=policy_id,
        display_name=display_name,
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=[],
                excluded_applications=[],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_users=included_users or [],
                excluded_users=excluded_users or [],
                included_groups=included_groups or [],
                excluded_groups=excluded_groups or [],
                included_roles=included_roles or [],
                excluded_roles=excluded_roles or [],
            ),
            client_app_types=[],
        ),
        grant_controls=GrantControls(
            built_in_controls=[],
            operator=GrantControlOperator.OR,
            authentication_strength=None,
        ),
        session_controls=SessionControls(
            persistent_browser=PersistentBrowser(is_enabled=False, mode=""),
            sign_in_frequency=SignInFrequency(
                is_enabled=False, frequency=None, type=None, interval=None
            ),
        ),
        state=state,
    )
    return policy_id, policy


def _entra_client_mock():
    client = mock.MagicMock
    client.audited_tenant = "audited_tenant"
    client.audited_domain = DOMAIN
    return client


CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_conditional_access_policy_no_deleted_object_references."
    "entra_conditional_access_policy_no_deleted_object_references.entra_client"
)


class Test_entra_conditional_access_policy_no_deleted_object_references:
    def test_no_policies(self):
        """No Conditional Access policies in tenant: no findings."""
        entra_client = _entra_client_mock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_no_deleted_object_references.entra_conditional_access_policy_no_deleted_object_references import (
                entra_conditional_access_policy_no_deleted_object_references,
            )

            entra_client.conditional_access_policies = {}
            entra_client.unresolved_directory_object_references = set()

            check = entra_conditional_access_policy_no_deleted_object_references()
            result = check.execute()

            assert len(result) == 0

    def test_sentinel_only_references_pass(self):
        """Policy with only sentinel values ('All', 'GuestsOrExternalUsers') passes."""
        entra_client = _entra_client_mock()
        policy_id, policy = _make_policy(
            display_name="MFA For All",
            included_users=["All"],
            excluded_users=["GuestsOrExternalUsers"],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_no_deleted_object_references.entra_conditional_access_policy_no_deleted_object_references import (
                entra_conditional_access_policy_no_deleted_object_references,
            )

            entra_client.conditional_access_policies = {policy_id: policy}
            entra_client.unresolved_directory_object_references = set()

            check = entra_conditional_access_policy_no_deleted_object_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "references no deleted directory objects" in result[0].status_extended
            )
            assert result[0].resource_id == policy_id
            assert result[0].resource_name == "MFA For All"

    def test_all_references_resolve_pass(self):
        """Policy with real identifiers, none in the unresolved set: PASS."""
        entra_client = _entra_client_mock()
        live_user = str(uuid4())
        live_group = str(uuid4())
        policy_id, policy = _make_policy(
            display_name="Targeted Policy",
            included_users=[live_user],
            included_groups=[live_group],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_no_deleted_object_references.entra_conditional_access_policy_no_deleted_object_references import (
                entra_conditional_access_policy_no_deleted_object_references,
            )

            entra_client.conditional_access_policies = {policy_id: policy}
            entra_client.unresolved_directory_object_references = set()

            check = entra_conditional_access_policy_no_deleted_object_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_deleted_user_in_include_fails(self):
        """Policy referencing a deleted user in includeUsers fails with type+side reported."""
        entra_client = _entra_client_mock()
        deleted_user = str(uuid4())
        policy_id, policy = _make_policy(
            display_name="Require MFA",
            included_users=[deleted_user],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_no_deleted_object_references.entra_conditional_access_policy_no_deleted_object_references import (
                entra_conditional_access_policy_no_deleted_object_references,
            )

            entra_client.conditional_access_policies = {policy_id: policy}
            entra_client.unresolved_directory_object_references = {
                ("user", deleted_user)
            }

            check = entra_conditional_access_policy_no_deleted_object_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "1 deleted directory object(s)" in result[0].status_extended
            assert "users:" in result[0].status_extended
            assert deleted_user in result[0].status_extended
            assert "(include)" in result[0].status_extended

    def test_deleted_group_in_exclude_fails(self):
        """Policy referencing a deleted group in excludeGroups fails with exclude side reported."""
        entra_client = _entra_client_mock()
        deleted_group = str(uuid4())
        policy_id, policy = _make_policy(
            display_name="Block Legacy Auth",
            included_users=["All"],
            excluded_groups=[deleted_group],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_no_deleted_object_references.entra_conditional_access_policy_no_deleted_object_references import (
                entra_conditional_access_policy_no_deleted_object_references,
            )

            entra_client.conditional_access_policies = {policy_id: policy}
            entra_client.unresolved_directory_object_references = {
                ("group", deleted_group)
            }

            check = entra_conditional_access_policy_no_deleted_object_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "groups:" in result[0].status_extended
            assert "(exclude)" in result[0].status_extended

    def test_deleted_role_in_disabled_policy_still_fails(self):
        """Disabled policy with a stale role reference still FAILs (per spec)."""
        entra_client = _entra_client_mock()
        deleted_role = str(uuid4())
        policy_id, policy = _make_policy(
            display_name="Legacy Admin Policy",
            state=ConditionalAccessPolicyState.DISABLED,
            included_roles=[deleted_role],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_no_deleted_object_references.entra_conditional_access_policy_no_deleted_object_references import (
                entra_conditional_access_policy_no_deleted_object_references,
            )

            entra_client.conditional_access_policies = {policy_id: policy}
            entra_client.unresolved_directory_object_references = {
                ("role", deleted_role)
            }

            check = entra_conditional_access_policy_no_deleted_object_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "roles:" in result[0].status_extended
            assert deleted_role in result[0].status_extended

    def test_orphans_grouped_by_type_across_collections(self):
        """A single policy with orphans of every type aggregates them grouped by type."""
        entra_client = _entra_client_mock()
        deleted_user = str(uuid4())
        deleted_group = str(uuid4())
        deleted_role = str(uuid4())
        policy_id, policy = _make_policy(
            display_name="Composite Policy",
            included_users=[deleted_user],
            excluded_groups=[deleted_group],
            included_roles=[deleted_role],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_no_deleted_object_references.entra_conditional_access_policy_no_deleted_object_references import (
                entra_conditional_access_policy_no_deleted_object_references,
            )

            entra_client.conditional_access_policies = {policy_id: policy}
            entra_client.unresolved_directory_object_references = {
                ("user", deleted_user),
                ("group", deleted_group),
                ("role", deleted_role),
            }

            check = entra_conditional_access_policy_no_deleted_object_references()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "3 deleted directory object(s)" in result[0].status_extended
            assert "users:" in result[0].status_extended
            assert "groups:" in result[0].status_extended
            assert "roles:" in result[0].status_extended

    def test_multiple_policies_mixed(self):
        """Two policies: one clean, one with an orphan. Distinct PASS/FAIL findings."""
        entra_client = _entra_client_mock()
        deleted_user = str(uuid4())

        clean_id, clean_policy = _make_policy(
            display_name="Clean Policy",
            included_users=["All"],
        )
        dirty_id, dirty_policy = _make_policy(
            display_name="Stale Reference Policy",
            excluded_users=[deleted_user],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_no_deleted_object_references.entra_conditional_access_policy_no_deleted_object_references import (
                entra_conditional_access_policy_no_deleted_object_references,
            )

            entra_client.conditional_access_policies = {
                clean_id: clean_policy,
                dirty_id: dirty_policy,
            }
            entra_client.unresolved_directory_object_references = {
                ("user", deleted_user)
            }

            check = entra_conditional_access_policy_no_deleted_object_references()
            result = check.execute()

            assert len(result) == 2

            clean_result = next(r for r in result if r.resource_id == clean_id)
            dirty_result = next(r for r in result if r.resource_id == dirty_id)

            assert clean_result.status == "PASS"
            assert dirty_result.status == "FAIL"
            assert "(exclude)" in dirty_result.status_extended
