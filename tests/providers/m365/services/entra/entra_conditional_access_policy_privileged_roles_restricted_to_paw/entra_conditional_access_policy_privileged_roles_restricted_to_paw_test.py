from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationsConditions,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    DeviceConditions,
    DeviceFilterMode,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_conditional_access_policy_privileged_roles_restricted_to_paw.entra_conditional_access_policy_privileged_roles_restricted_to_paw"

# Mirror of DEFAULT_PRIVILEGED_ROLE_IDS from the check module, duplicated here
# to avoid triggering the entra_client import chain at test collection time.
ALL_PRIVILEGED_ROLES = [
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
    "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Billing Administrator
]


def _make_policy(
    policy_id="policy-paw-1",
    display_name="Admins - PAW only",
    state=ConditionalAccessPolicyState.ENABLED,
    included_roles=None,
    excluded_roles=None,
    included_applications=None,
    excluded_applications=None,
    built_in_controls=None,
    device_filter_mode=DeviceFilterMode.EXCLUDE,
    device_filter_rule='device.extensionAttribute1 -eq "PAW"',
):
    """Create a ConditionalAccessPolicy for PAW restriction testing."""
    return ConditionalAccessPolicy(
        id=policy_id,
        display_name=display_name,
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=(
                    included_applications
                    if included_applications is not None
                    else ["All"]
                ),
                excluded_applications=excluded_applications or [],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_groups=[],
                excluded_groups=[],
                included_users=[],
                excluded_users=[],
                included_roles=(
                    included_roles
                    if included_roles is not None
                    else ALL_PRIVILEGED_ROLES
                ),
                excluded_roles=excluded_roles or [],
            ),
            client_app_types=[],
            device_conditions=DeviceConditions(
                device_filter_mode=device_filter_mode,
                device_filter_rule=device_filter_rule,
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


class Test_entra_conditional_access_policy_privileged_roles_restricted_to_paw:
    """Tests for the PAW restriction Conditional Access policy check."""

    def _run(self, policies, audit_config=None):
        """Execute the check with the given policies and optional audit config."""
        entra_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_privileged_roles_restricted_to_paw.entra_conditional_access_policy_privileged_roles_restricted_to_paw import (
                entra_conditional_access_policy_privileged_roles_restricted_to_paw,
            )

            entra_client.conditional_access_policies = policies
            entra_client.tenant_domain = DOMAIN
            entra_client.audit_config = audit_config or {}
            return (
                entra_conditional_access_policy_privileged_roles_restricted_to_paw().execute()
            )

    def _assert_common_fields(self, finding):
        """Assert the tenant-level resource fields that are the same for every finding."""
        assert finding.resource == {}
        assert finding.resource_name == "Conditional Access Policies"
        assert finding.resource_id == "conditionalAccessPolicies"

    # ------------------------------------------------------------------
    # No resources / empty policies
    # ------------------------------------------------------------------

    def test_no_policies(self):
        """FAIL when there are no Conditional Access policies."""
        result = self._run({})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No Conditional Access Policy restricts privileged roles to Privileged Access Workstations (PAWs)."
        )
        self._assert_common_fields(result[0])

    # ------------------------------------------------------------------
    # PASS scenarios
    # ------------------------------------------------------------------

    def test_pass_single_policy_all_roles(self):
        """PASS when a single enabled policy covers all privileged roles with block + device filter."""
        policy = _make_policy()
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "'Admins - PAW only'" in result[0].status_extended
        assert "restricts privileged roles" in result[0].status_extended
        assert "device filter exists but cannot confirm" in result[0].status_extended
        # Single policy uses singular wording
        assert "Policy " in result[0].status_extended
        assert "restricts " in result[0].status_extended
        self._assert_common_fields(result[0])

    def test_pass_multiple_policies_cover_all_roles(self):
        """PASS when multiple policies together cover all privileged roles."""
        mid = len(ALL_PRIVILEGED_ROLES) // 2
        policy1 = _make_policy(
            policy_id="policy-1",
            display_name="PAW Policy Part 1",
            included_roles=ALL_PRIVILEGED_ROLES[:mid],
        )
        policy2 = _make_policy(
            policy_id="policy-2",
            display_name="PAW Policy Part 2",
            included_roles=ALL_PRIVILEGED_ROLES[mid:],
        )
        result = self._run({policy1.id: policy1, policy2.id: policy2})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "PAW Policy Part 1" in result[0].status_extended
        assert "PAW Policy Part 2" in result[0].status_extended
        # Multiple policies use plural wording
        assert "Policies " in result[0].status_extended
        assert "restrict " in result[0].status_extended
        self._assert_common_fields(result[0])

    def test_pass_with_include_device_filter_mode(self):
        """PASS when using include mode for device filter (negated rule targeting non-PAWs)."""
        policy = _make_policy(
            device_filter_mode=DeviceFilterMode.INCLUDE,
            device_filter_rule='device.extensionAttribute1 -ne "PAW"',
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "PASS"
        self._assert_common_fields(result[0])

    def test_pass_custom_role_list_via_audit_config(self):
        """PASS when a custom privileged role list from audit_config is fully covered."""
        custom_roles = [
            "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        ]
        policy = _make_policy(included_roles=custom_roles)
        result = self._run(
            {policy.id: policy},
            audit_config={"privileged_role_template_ids": custom_roles},
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        self._assert_common_fields(result[0])

    def test_pass_qualifying_policy_alongside_non_qualifying(self):
        """PASS when a qualifying policy exists alongside a non-qualifying one."""
        good_policy = _make_policy(
            policy_id="good-policy",
            display_name="Good PAW Policy",
        )
        # Non-qualifying: no block control
        bad_policy = _make_policy(
            policy_id="bad-policy",
            display_name="Bad Policy No Block",
            built_in_controls=[ConditionalAccessGrantControl.MFA],
        )
        result = self._run({good_policy.id: good_policy, bad_policy.id: bad_policy})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "Good PAW Policy" in result[0].status_extended
        # The non-qualifying policy should not appear
        assert "Bad Policy No Block" not in result[0].status_extended
        self._assert_common_fields(result[0])

    def test_pass_excluded_users_do_not_affect_result(self):
        """PASS when a qualifying policy excludes break-glass users (excludeUsers is allowed)."""
        policy = _make_policy()
        # Manually add excluded users to the user conditions (break-glass accounts)
        policy.conditions.user_conditions.excluded_users = [
            "break-glass-user-id-1",
            "break-glass-user-id-2",
        ]
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "PASS"
        self._assert_common_fields(result[0])

    # ------------------------------------------------------------------
    # FAIL scenarios
    # ------------------------------------------------------------------

    def test_fail_disabled_policy(self):
        """FAIL when the only matching policy is disabled."""
        policy = _make_policy(state=ConditionalAccessPolicyState.DISABLED)
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No Conditional Access Policy restricts privileged roles to Privileged Access Workstations (PAWs)."
        )
        self._assert_common_fields(result[0])

    def test_fail_report_only_policy(self):
        """FAIL when the only matching policy is in report-only mode."""
        policy = _make_policy(state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING)
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No Conditional Access Policy restricts privileged roles to Privileged Access Workstations (PAWs)."
        )
        self._assert_common_fields(result[0])

    def test_fail_no_privileged_roles(self):
        """FAIL when policy targets no privileged roles."""
        policy = _make_policy(included_roles=[])
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        self._assert_common_fields(result[0])

    def test_fail_non_privileged_roles_only(self):
        """FAIL when the policy targets roles that are not in the privileged list."""
        policy = _make_policy(
            included_roles=["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        self._assert_common_fields(result[0])

    def test_fail_not_all_cloud_apps(self):
        """FAIL when the policy does not target all cloud applications."""
        policy = _make_policy(
            included_applications=["00000003-0000-0000-c000-000000000000"]
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        self._assert_common_fields(result[0])

    def test_fail_excluded_applications(self):
        """FAIL when the policy excludes applications (weakens coverage)."""
        policy = _make_policy(excluded_applications=["some-app-id"])
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        self._assert_common_fields(result[0])

    def test_fail_no_block_control(self):
        """FAIL when the policy does not have block as a grant control."""
        policy = _make_policy(built_in_controls=[ConditionalAccessGrantControl.MFA])
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        self._assert_common_fields(result[0])

    def test_fail_no_device_filter(self):
        """FAIL when the policy has no device filter configured (both mode and rule are None)."""
        policy = _make_policy(device_filter_mode=None, device_filter_rule=None)
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        self._assert_common_fields(result[0])

    def test_fail_device_filter_rule_empty(self):
        """FAIL when device filter mode is set but rule is None."""
        policy = _make_policy(
            device_filter_mode=DeviceFilterMode.EXCLUDE,
            device_filter_rule=None,
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        self._assert_common_fields(result[0])

    def test_fail_device_filter_mode_none_with_rule(self):
        """FAIL when device filter rule is set but mode is None."""
        policy = _make_policy(
            device_filter_mode=None,
            device_filter_rule='device.extensionAttribute1 -eq "PAW"',
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        self._assert_common_fields(result[0])

    def test_fail_partial_role_coverage(self):
        """FAIL when the policy covers only some privileged roles."""
        partial_roles = ALL_PRIVILEGED_ROLES[:3]
        policy = _make_policy(included_roles=partial_roles)
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "not covered" in result[0].status_extended
        expected_missing = len(ALL_PRIVILEGED_ROLES) - 3
        assert (
            f"{expected_missing} privileged roles are not covered"
            in result[0].status_extended
        )
        self._assert_common_fields(result[0])

    def test_fail_partial_coverage_single_role_missing(self):
        """FAIL with singular wording when exactly one privileged role is not covered."""
        # Include all roles except the last one
        almost_all = ALL_PRIVILEGED_ROLES[:-1]
        policy = _make_policy(included_roles=almost_all)
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "1 privileged role is not covered" in result[0].status_extended
        self._assert_common_fields(result[0])

    def test_fail_excluded_roles_negate_coverage(self):
        """FAIL when included roles are fully negated by excluded roles."""
        policy = _make_policy(
            included_roles=ALL_PRIVILEGED_ROLES,
            excluded_roles=ALL_PRIVILEGED_ROLES,
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        self._assert_common_fields(result[0])

    def test_fail_excluded_roles_partially_negate_coverage(self):
        """FAIL when excluded roles reduce coverage below the full set."""
        # Exclude the first 3 roles
        policy = _make_policy(
            included_roles=ALL_PRIVILEGED_ROLES,
            excluded_roles=ALL_PRIVILEGED_ROLES[:3],
        )
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "not covered" in result[0].status_extended
        assert "3 privileged roles are not covered" in result[0].status_extended
        self._assert_common_fields(result[0])

    def test_fail_all_policies_non_qualifying(self):
        """FAIL when multiple policies exist but none qualifies."""
        # One disabled, one report-only, one missing block
        p1 = _make_policy(
            policy_id="p1",
            display_name="Disabled PAW",
            state=ConditionalAccessPolicyState.DISABLED,
        )
        p2 = _make_policy(
            policy_id="p2",
            display_name="Report Only PAW",
            state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
        )
        p3 = _make_policy(
            policy_id="p3",
            display_name="No Block PAW",
            built_in_controls=[ConditionalAccessGrantControl.MFA],
        )
        result = self._run({p1.id: p1, p2.id: p2, p3.id: p3})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No Conditional Access Policy restricts privileged roles to Privileged Access Workstations (PAWs)."
        )
        self._assert_common_fields(result[0])

    def test_fail_empty_included_applications(self):
        """FAIL when included_applications is empty (does not contain 'All')."""
        policy = _make_policy(included_applications=[])
        result = self._run({policy.id: policy})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        self._assert_common_fields(result[0])
