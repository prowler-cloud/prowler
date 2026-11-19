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
    UserAction,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


def _make_policy(
    *,
    display_name="Test Policy",
    state=ConditionalAccessPolicyState.ENABLED,
    included_applications=None,
    excluded_applications=None,
    included_user_actions=None,
    included_auth_context_refs=None,
    application_filter_mode=None,
    application_filter_rule=None,
    application_conditions=None,
):
    """Build a ConditionalAccessPolicy with the minimum fields required by the model."""
    policy_id = str(uuid4())

    if application_conditions is None:
        application_conditions = ApplicationsConditions(
            included_applications=included_applications or [],
            excluded_applications=excluded_applications or [],
            included_user_actions=included_user_actions or [],
            included_authentication_context_class_references=included_auth_context_refs
            or [],
            application_filter_mode=application_filter_mode,
            application_filter_rule=application_filter_rule,
        )

    policy = ConditionalAccessPolicy(
        id=policy_id,
        display_name=display_name,
        conditions=Conditions(
            application_conditions=application_conditions,
            user_conditions=UsersConditions(
                included_users=["All"],
                excluded_users=[],
                included_groups=[],
                excluded_groups=[],
                included_roles=[],
                excluded_roles=[],
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
    """Create a mocked entra_client with default attributes."""
    client = mock.MagicMock()
    client.audited_tenant = "audited_tenant"
    client.audited_domain = DOMAIN
    client.conditional_access_policies_error = None
    return client


CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_conditional_access_policy_target_resources_configured."
    "entra_conditional_access_policy_target_resources_configured.entra_client"
)


class Test_entra_conditional_access_policy_target_resources_configured:
    """Tests for the entra_conditional_access_policy_target_resources_configured check."""

    def test_no_policies(self):
        """No Conditional Access policies and no error: no findings."""
        entra_client = _entra_client_mock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 0

    def test_policy_with_all_apps_pass(self):
        """Policy targeting 'All' cloud apps should PASS."""
        entra_client = _entra_client_mock()
        policy_id, policy = _make_policy(
            display_name="MFA for all",
            included_applications=["All"],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {policy_id: policy}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == policy_id
            assert "targets at least one resource" in result[0].status_extended

    def test_policy_with_specific_app_id_pass(self):
        """Policy targeting a specific app GUID should PASS."""
        entra_client = _entra_client_mock()
        policy_id, policy = _make_policy(
            display_name="Block Legacy App",
            included_applications=["00000003-0000-0000-c000-000000000000"],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {policy_id: policy}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_policy_with_user_actions_pass(self):
        """Policy targeting user actions should PASS."""
        entra_client = _entra_client_mock()
        policy_id, policy = _make_policy(
            display_name="MFA for device registration",
            included_user_actions=[UserAction.REGISTER_SECURITY_INFO],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {policy_id: policy}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_policy_with_auth_context_pass(self):
        """Policy targeting authentication context class references should PASS."""
        entra_client = _entra_client_mock()
        policy_id, policy = _make_policy(
            display_name="Auth context policy",
            included_auth_context_refs=["c1"],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {policy_id: policy}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_policy_with_application_filter_pass(self):
        """Policy targeting an application filter should PASS."""
        entra_client = _entra_client_mock()
        policy_id, policy = _make_policy(
            display_name="App filter policy",
            application_filter_mode="include",
            application_filter_rule="customSecurityAttribute.value -eq 'true'",
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {policy_id: policy}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_policy_with_none_apps_only_fail(self):
        """Policy with includeApplications=['None'] and nothing else should FAIL."""
        entra_client = _entra_client_mock()
        policy_id, policy = _make_policy(
            display_name="Empty policy",
            included_applications=["None"],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {policy_id: policy}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "no target resources" in result[0].status_extended
            assert result[0].resource_id == policy_id

    def test_policy_with_empty_apps_fail(self):
        """Policy with empty includeApplications and no other targets should FAIL."""
        entra_client = _entra_client_mock()
        policy_id, policy = _make_policy(
            display_name="Draft policy",
            included_applications=[],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {policy_id: policy}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_disabled_policy_evaluated(self):
        """Disabled policies are evaluated too (Maester parity)."""
        entra_client = _entra_client_mock()
        policy_id, policy = _make_policy(
            display_name="Disabled draft",
            state=ConditionalAccessPolicyState.DISABLED,
            included_applications=["None"],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {policy_id: policy}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "disabled" in result[0].status_extended

    def test_state_shown_in_pass_message(self):
        """The policy state should be included in the PASS status_extended."""
        entra_client = _entra_client_mock()
        policy_id, policy = _make_policy(
            display_name="Report-only policy",
            state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
            included_applications=["All"],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {policy_id: policy}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "enabledForReportingButNotEnforced" in result[0].status_extended

    def test_error_produces_manual_finding(self):
        """When the service had an error, a MANUAL tenant-level finding is emitted."""
        entra_client = _entra_client_mock()
        entra_client.conditional_access_policies_error = (
            "ODataError: Insufficient privileges"
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_id == "conditionalAccessPolicies"
            assert "could not be fully retrieved" in result[0].status_extended

    def test_error_with_partial_policies(self):
        """Error with partial policies: per-policy findings plus a MANUAL finding."""
        entra_client = _entra_client_mock()
        entra_client.conditional_access_policies_error = "ODataError: Throttled"
        policy_id, policy = _make_policy(
            display_name="Good policy",
            included_applications=["All"],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {policy_id: policy}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 2
            # First finding is the per-policy PASS
            assert result[0].status == "PASS"
            assert result[0].resource_id == policy_id
            # Second is the tenant-level MANUAL
            assert result[1].status == "MANUAL"
            assert result[1].resource_id == "conditionalAccessPolicies"

    def test_multiple_policies_mixed(self):
        """Multiple policies: targeted ones PASS, untargeted ones FAIL."""
        entra_client = _entra_client_mock()
        id1, policy1 = _make_policy(
            display_name="Good policy",
            included_applications=["All"],
        )
        id2, policy2 = _make_policy(
            display_name="Bad policy",
            included_applications=["None"],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {id1: policy1, id2: policy2}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 2
            statuses = {r.resource_id: r.status for r in result}
            assert statuses[id1] == "PASS"
            assert statuses[id2] == "FAIL"

    def test_no_application_conditions_fail(self):
        """Policy with no application_conditions at all should FAIL."""
        entra_client = _entra_client_mock()
        policy_id = str(uuid4())
        policy = ConditionalAccessPolicy(
            id=policy_id,
            display_name="Broken policy",
            conditions=Conditions(
                application_conditions=None,
                user_conditions=UsersConditions(
                    included_users=["All"],
                    excluded_users=[],
                    included_groups=[],
                    excluded_groups=[],
                    included_roles=[],
                    excluded_roles=[],
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
            state=ConditionalAccessPolicyState.ENABLED,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_target_resources_configured.entra_conditional_access_policy_target_resources_configured import (
                entra_conditional_access_policy_target_resources_configured,
            )

            entra_client.conditional_access_policies = {policy_id: policy}

            check = entra_conditional_access_policy_target_resources_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "no target resources" in result[0].status_extended
