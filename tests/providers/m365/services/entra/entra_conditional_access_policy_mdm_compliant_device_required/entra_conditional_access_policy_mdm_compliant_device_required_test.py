from types import SimpleNamespace
from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    ApplicationEnforcedRestrictions,
    ApplicationsConditions,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    Conditions,
    GrantControlOperator,
    GrantControls,
    PersistentBrowser,
    SessionControls,
    SignInFrequency,
    SignInFrequencyInterval,
    UsersConditions,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_conditional_access_policy_mdm_compliant_device_required."
    "entra_conditional_access_policy_mdm_compliant_device_required"
)


def build_policy(
    *,
    included_users=None,
    excluded_users=None,
    included_applications=None,
    excluded_applications=None,
    built_in_controls=None,
    operator=GrantControlOperator.OR,
    authentication_strength=None,
    state=ConditionalAccessPolicyState.ENABLED,
    display_name="Test",
):
    policy_id = str(uuid4())
    return ConditionalAccessPolicy(
        id=policy_id,
        display_name=display_name,
        conditions=Conditions(
            application_conditions=ApplicationsConditions(
                included_applications=included_applications or ["All"],
                excluded_applications=excluded_applications or [],
                included_user_actions=[],
            ),
            user_conditions=UsersConditions(
                included_groups=[],
                excluded_groups=[],
                included_users=included_users or ["All"],
                excluded_users=excluded_users or [],
                included_roles=[],
                excluded_roles=[],
            ),
        ),
        grant_controls=GrantControls(
            built_in_controls=built_in_controls
            or [ConditionalAccessGrantControl.COMPLIANT_DEVICE],
            operator=operator,
            authentication_strength=authentication_strength,
        ),
        session_controls=SessionControls(
            persistent_browser=PersistentBrowser(is_enabled=False, mode="always"),
            sign_in_frequency=SignInFrequency(
                is_enabled=False,
                frequency=None,
                type=None,
                interval=SignInFrequencyInterval.TIME_BASED,
            ),
            application_enforced_restrictions=ApplicationEnforcedRestrictions(
                is_enabled=False
            ),
        ),
        state=state,
    )


def build_intune_client(
    *,
    verification_error=None,
    secure_by_default=True,
    assignment_counts=None,
    managed_devices=None,
):
    assignment_counts = assignment_counts if assignment_counts is not None else [1]
    return SimpleNamespace(
        verification_error=verification_error,
        settings=SimpleNamespace(secure_by_default=secure_by_default),
        compliance_policies=[
            SimpleNamespace(
                id=str(uuid4()),
                display_name=f"Compliance Policy {index}",
                assignment_count=assignment_count,
            )
            for index, assignment_count in enumerate(assignment_counts, start=1)
        ],
        managed_devices=(
            managed_devices
            if managed_devices is not None
            else [
                SimpleNamespace(
                    id=str(uuid4()),
                    device_name="Managed Device 1",
                    compliance_state="compliant",
                    management_agent="mdm",
                )
            ]
        ),
    )


class Test_entra_conditional_access_policy_mdm_compliant_device_required:
    def _run_check(self, conditional_access_policies, intune_client):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.conditional_access_policies = conditional_access_policies

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE}.entra_client", new=entra_client),
            mock.patch(f"{CHECK_MODULE}.intune_client", new=intune_client),
        ):
            from prowler.providers.m365.services.entra.entra_conditional_access_policy_mdm_compliant_device_required.entra_conditional_access_policy_mdm_compliant_device_required import (
                entra_conditional_access_policy_mdm_compliant_device_required,
            )

            check = entra_conditional_access_policy_mdm_compliant_device_required()
            return check.execute()

    def test_no_conditional_access_policies(self):
        result = self._run_check({}, build_intune_client())

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
        )
        assert result[0].resource == {}
        assert result[0].resource_name == "Conditional Access Policies"
        assert result[0].resource_id == "conditionalAccessPolicies"
        assert result[0].location == "global"

    def test_reporting_only_policy_fails(self):
        policy = build_policy(state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING)

        result = self._run_check({policy.id: policy}, build_intune_client())

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Conditional Access Policy '{policy.display_name}' reports the requirement of an MDM-compliant device for all cloud app access but does not enforce it."
        )
        assert result[0].resource == policy.dict()
        assert result[0].resource_name == policy.display_name
        assert result[0].resource_id == policy.id
        assert result[0].location == "global"

    def test_specific_users_policy_fails(self):
        policy = build_policy(included_users=["specific-user-id"])

        result = self._run_check({policy.id: policy}, build_intune_client())

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
        )

    def test_policy_with_excluded_users_passes(self):
        policy = build_policy(excluded_users=["break-glass-id"])

        result = self._run_check({policy.id: policy}, build_intune_client())

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Conditional Access Policy '{policy.display_name}' requires an MDM-compliant device for all cloud app access, and Microsoft Intune is configured with assigned compliance policies, secure-by-default compliance evaluation, and at least one compliant MDM-managed device."
        )
        assert result[0].resource == policy.dict()

    def test_policy_with_excluded_applications_fails(self):
        policy = build_policy(excluded_applications=["office-app-id"])

        result = self._run_check({policy.id: policy}, build_intune_client())

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
        )

    def test_policy_with_or_mfa_fails(self):
        policy = build_policy(
            built_in_controls=[
                ConditionalAccessGrantControl.COMPLIANT_DEVICE,
                ConditionalAccessGrantControl.MFA,
            ],
            operator=GrantControlOperator.OR,
        )

        result = self._run_check({policy.id: policy}, build_intune_client())

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
        )

    def test_policy_with_or_authentication_strength_fails(self):
        policy = build_policy(
            operator=GrantControlOperator.OR,
            authentication_strength="Phishing-resistant MFA",
        )

        result = self._run_check({policy.id: policy}, build_intune_client())

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
        )

    def test_intune_verification_error_returns_manual(self):
        policy = build_policy()
        intune_client = build_intune_client(
            verification_error=(
                "Could not read Microsoft Intune device management settings. "
                "Ensure the Service Principal has DeviceManagementServiceConfig.Read.All permission granted."
            )
        )

        result = self._run_check({policy.id: policy}, intune_client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Conditional Access Policy '{policy.display_name}' requires an MDM-compliant device for all cloud app access, but Microsoft Intune MDM compliance prerequisites could not be verified. {intune_client.verification_error}"
        )
        assert result[0].resource == policy.dict()

    def test_no_intune_compliance_policies_fails(self):
        policy = build_policy()
        intune_client = build_intune_client()
        intune_client.compliance_policies = []

        result = self._run_check({policy.id: policy}, intune_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Conditional Access Policy '{policy.display_name}' requires an MDM-compliant device for all cloud app access, but no Microsoft Intune device compliance policies are configured."
        )
        assert result[0].resource == policy.dict()

    def test_unassigned_intune_compliance_policies_fail(self):
        policy = build_policy()

        result = self._run_check(
            {policy.id: policy},
            build_intune_client(assignment_counts=[0, 0]),
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Conditional Access Policy '{policy.display_name}' requires an MDM-compliant device for all cloud app access, but no Microsoft Intune device compliance policy is assigned."
        )
        assert result[0].resource == policy.dict()

    def test_secure_by_default_disabled_fails(self):
        policy = build_policy()

        result = self._run_check(
            {policy.id: policy},
            build_intune_client(secure_by_default=False),
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Conditional Access Policy '{policy.display_name}' requires an MDM-compliant device for all cloud app access, but Microsoft Intune allows devices without an assigned compliance policy to remain compliant."
        )
        assert result[0].resource == policy.dict()

    def test_missing_secure_by_default_does_not_block_pass(self):
        policy = build_policy()

        result = self._run_check(
            {policy.id: policy},
            build_intune_client(secure_by_default=None),
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Conditional Access Policy '{policy.display_name}' requires an MDM-compliant device for all cloud app access, and Microsoft Intune is configured with assigned compliance policies and at least one compliant MDM-managed device. Microsoft Graph did not return device management settings, so secure-by-default compliance evaluation could not be verified."
        )
        assert result[0].resource == policy.dict()

    def test_no_compliant_mdm_managed_devices_fails(self):
        policy = build_policy()

        result = self._run_check(
            {policy.id: policy},
            build_intune_client(managed_devices=[]),
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Conditional Access Policy '{policy.display_name}' requires an MDM-compliant device for all cloud app access, but Microsoft Intune does not currently report any compliant MDM-managed devices."
        )
        assert result[0].resource == policy.dict()

    def test_non_mdm_compliant_devices_do_not_pass(self):
        policy = build_policy()

        result = self._run_check(
            {policy.id: policy},
            build_intune_client(
                managed_devices=[
                    SimpleNamespace(
                        id=str(uuid4()),
                        device_name="EAS Device",
                        compliance_state="compliant",
                        management_agent="eas",
                    )
                ]
            ),
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Conditional Access Policy '{policy.display_name}' requires an MDM-compliant device for all cloud app access, but Microsoft Intune does not currently report any compliant MDM-managed devices."
        )
        assert result[0].resource == policy.dict()

    def test_disabled_policy_is_ignored(self):
        """Disabled policy is properly ignored, resulting in generic FAIL."""
        policy = build_policy(state=ConditionalAccessPolicyState.DISABLED)

        result = self._run_check({policy.id: policy}, build_intune_client())

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
        )
        assert result[0].resource == {}
        assert result[0].resource_name == "Conditional Access Policies"
        assert result[0].resource_id == "conditionalAccessPolicies"

    def test_policy_without_compliant_device_grant_is_skipped(self):
        """Policy without COMPLIANT_DEVICE grant control is skipped."""
        policy = build_policy(
            built_in_controls=[ConditionalAccessGrantControl.MFA],
        )

        result = self._run_check({policy.id: policy}, build_intune_client())

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
        )

    def test_policy_targeting_specific_apps_is_skipped(self):
        """Policy targeting specific apps instead of All is skipped."""
        policy = build_policy(included_applications=["specific-app-id"])

        result = self._run_check({policy.id: policy}, build_intune_client())

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No Conditional Access Policy requires an MDM-compliant device for all cloud app access."
        )

    def test_noncompliant_mdm_device_does_not_count(self):
        """MDM-managed device with compliance_state='noncompliant' doesn't count as compliant."""
        policy = build_policy()

        result = self._run_check(
            {policy.id: policy},
            build_intune_client(
                managed_devices=[
                    SimpleNamespace(
                        id=str(uuid4()),
                        device_name="Noncompliant MDM Device",
                        compliance_state="noncompliant",
                        management_agent="mdm",
                    )
                ]
            ),
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Conditional Access Policy '{policy.display_name}' requires an MDM-compliant device for all cloud app access, but Microsoft Intune does not currently report any compliant MDM-managed devices."
        )
        assert result[0].resource == policy.dict()

    def test_reporting_policy_ignored_when_enabled_policy_exists(self):
        """Report-only policy is ignored when a valid enabled policy also exists."""
        reporting_policy = build_policy(
            state=ConditionalAccessPolicyState.ENABLED_FOR_REPORTING,
            display_name="Reporting Policy",
        )
        enabled_policy = build_policy(
            state=ConditionalAccessPolicyState.ENABLED,
            display_name="Enabled Policy",
        )

        result = self._run_check(
            {reporting_policy.id: reporting_policy, enabled_policy.id: enabled_policy},
            build_intune_client(),
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "Enabled Policy" in result[0].status_extended
        assert result[0].resource == enabled_policy.dict()

    def test_mixed_assigned_unassigned_compliance_policies_pass(self):
        """Mixed assigned/unassigned compliance policies (e.g. [0, 1]) still pass."""
        policy = build_policy()

        result = self._run_check(
            {policy.id: policy},
            build_intune_client(assignment_counts=[0, 1]),
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource == policy.dict()

    def test_enabled_policy_with_intune_prerequisites_passes(self):
        policy = build_policy(
            built_in_controls=[
                ConditionalAccessGrantControl.COMPLIANT_DEVICE,
                ConditionalAccessGrantControl.MFA,
            ],
            operator=GrantControlOperator.AND,
        )

        result = self._run_check({policy.id: policy}, build_intune_client())

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Conditional Access Policy '{policy.display_name}' requires an MDM-compliant device for all cloud app access, and Microsoft Intune is configured with assigned compliance policies, secure-by-default compliance evaluation, and at least one compliant MDM-managed device."
        )
        assert result[0].resource == policy.dict()
        assert result[0].resource_name == policy.display_name
        assert result[0].resource_id == policy.id
        assert result[0].location == "global"
