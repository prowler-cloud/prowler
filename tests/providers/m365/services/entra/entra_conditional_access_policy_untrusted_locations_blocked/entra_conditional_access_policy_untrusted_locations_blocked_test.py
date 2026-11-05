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
    NamedLocation,
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
    excluded_applications=None,
):
    return ConditionalAccessPolicy(
        id="policy-1",
        display_name="Block Untrusted Locations",
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=["All"],
                excluded_applications=excluded_applications or [],
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
    def _run(self, policies, named_locations=None):
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
            entra_client.named_locations = named_locations or []
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

    def test_policy_excluding_application_does_not_cover_all_applications(self):
        policy = _make_policy(excluded_applications=["excluded-app"])
        result = self._run({policy.id: policy})
        assert result[0].status == "FAIL"

    def test_blocks_explicit_untrusted_named_location(self):
        location_id = "00000000-0000-0000-0000-000000000001"
        policy = _make_policy(include_locations=[location_id])
        result = self._run(
            {policy.id: policy},
            [NamedLocation(id=location_id, is_trusted=False)],
        )
        assert result[0].status == "PASS"

    def test_does_not_accept_explicit_trusted_named_location(self):
        location_id = "00000000-0000-0000-0000-000000000001"
        policy = _make_policy(include_locations=[location_id])
        result = self._run(
            {policy.id: policy},
            [NamedLocation(id=location_id, is_trusted=True)],
        )
        assert result[0].status == "FAIL"

    def test_does_not_accept_unknown_named_location(self):
        policy = _make_policy(
            include_locations=["00000000-0000-0000-0000-000000000001"]
        )
        result = self._run({policy.id: policy})
        assert result[0].status == "FAIL"

    def test_does_not_accept_explicit_untrusted_location_when_excluded(self):
        location_id = "00000000-0000-0000-0000-000000000001"
        policy = _make_policy(
            include_locations=[location_id],
            exclude_locations=["AllTrusted", location_id],
        )
        result = self._run(
            {policy.id: policy},
            [NamedLocation(id=location_id, is_trusted=False)],
        )
        assert result[0].status == "FAIL"

    def test_no_trusted_exclusion(self):
        policy = _make_policy(exclude_locations=[])
        result = self._run({policy.id: policy})
        assert result[0].status == "FAIL"

    def test_policy_report_only(self):
        policy = _make_policy(state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING)

        result = self._run({policy.id: policy})

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "Conditional Access Policy 'Block Untrusted Locations' blocks untrusted "
            "locations but is in report-only mode."
        )

    def test_policy_disabled_is_skipped(self):
        policy = _make_policy(state=ConditionalAccessPolicyState.DISABLED)

        result = self._run({policy.id: policy})

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == "conditionalAccessPolicies"
        assert result[0].status_extended == (
            "No Conditional Access Policy blocks access from untrusted locations."
        )

    def test_not_block(self):
        policy = _make_policy(built_in_controls=[ConditionalAccessGrantControl.MFA])
        result = self._run({policy.id: policy})
        assert result[0].status == "FAIL"
