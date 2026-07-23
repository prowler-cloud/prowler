from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    GrantControlOperator,
    GrantControls,
    LocationsCondition,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_untrusted_locations_blocked.entra_conditional_access_policy_untrusted_locations_blocked"


def _make_policy(
    state=ConditionalAccessPolicyState.ENABLED,
    include_locations=None,
    exclude_locations=None,
    built_in_controls=None,
):
    return ConditionalAccessPolicy(
        id="policy-1",
        display_name="Block Untrusted Locations",
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=["All"],
                excluded_applications=[],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_groups=[],
                excluded_groups=[],
                included_users=["All"],
                excluded_users=[],
                included_roles=[],
                excluded_roles=[],
            ),
            client_app_types=[],
            locations=LocationsCondition(
                include_locations=(
                    include_locations if include_locations is not None else ["All"]
                ),
                exclude_locations=(
                    exclude_locations
                    if exclude_locations is not None
                    else ["AllTrusted"]
                ),
            ),
        ),
        grant_controls=GrantControls(
            built_in_controls=(
                built_in_controls
                if built_in_controls is not None
                else [ConditionalAccessGrantControl.BLOCK]
            ),
            operator=GrantControlOperator.OR,
            authentication_strength=None,
        ),
        session_controls=SessionControls(
            persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
            sign_in_frequency=SignInFrequency(
                is_enabled=False, frequency=None, type=None, interval=None
            ),
        ),
        state=state,
    )


class Test_entra_conditional_access_policy_untrusted_locations_blocked:
    def _run(self, policies):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_untrusted_locations_blocked.entra_conditional_access_policy_untrusted_locations_blocked import (
                entra_conditional_access_policy_untrusted_locations_blocked,
            )

            entra_client.conditional_access_policies = policies
            entra_client.named_locations = []
            entra_client.tenant_domain = DOMAIN
            return (
                entra_conditional_access_policy_untrusted_locations_blocked().execute()
            )

    def test_no_policies(self):
        assert self._run({})[0].status == "FAIL"

    def test_blocks_untrusted(self):
        policy = _make_policy()
        result = self._run({policy.id: policy})
        assert result[0].status == "PASS"

    def test_no_trusted_exclusion(self):
        policy = _make_policy(exclude_locations=[])
        result = self._run({policy.id: policy})
        assert result[0].status == "FAIL"

    def test_not_block(self):
        policy = _make_policy(built_in_controls=[ConditionalAccessGrantControl.MFA])
        result = self._run({policy.id: policy})
        assert result[0].status == "FAIL"
