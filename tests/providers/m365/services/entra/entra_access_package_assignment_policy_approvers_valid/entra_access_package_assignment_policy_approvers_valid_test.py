from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AccessPackageAssignmentPolicy,
    ApprovalStage,
    Approver,
    ApproverResolution,
    ApproverStatus,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_access_package_assignment_policy_approvers_valid."
    "entra_access_package_assignment_policy_approvers_valid.entra_client"
)


def _make_policy(
    *,
    policy_id="policy-1",
    display_name="Test Policy",
    access_package_name="Finance Reports",
    stages=None,
    is_add=True,
    is_update=False,
):
    """Build an AccessPackageAssignmentPolicy for testing."""
    return AccessPackageAssignmentPolicy(
        id=policy_id,
        display_name=display_name,
        access_package_id="ap-1",
        access_package_name=access_package_name,
        is_approval_required_for_add=is_add,
        is_approval_required_for_update=is_update,
        stages=stages if stages is not None else [],
    )


def _valid_user_approver(user_id="user-1"):
    """Build a valid singleUser approver."""
    return Approver(
        odata_type="#microsoft.graph.singleUser",
        user_id=user_id,
        resolution=ApproverResolution(
            status=ApproverStatus.VALID,
            display_name="Alice",
        ),
    )


def _deleted_user_approver(user_id="user-deleted"):
    """Build a deleted singleUser approver."""
    return Approver(
        odata_type="#microsoft.graph.singleUser",
        user_id=user_id,
        resolution=ApproverResolution(status=ApproverStatus.USER_DELETED),
    )


def _disabled_user_approver(user_id="user-disabled"):
    """Build a disabled singleUser approver."""
    return Approver(
        odata_type="#microsoft.graph.singleUser",
        user_id=user_id,
        resolution=ApproverResolution(
            status=ApproverStatus.USER_DISABLED,
            display_name="Bob (disabled)",
        ),
    )


def _valid_group_approver(group_id="group-1"):
    """Build a valid groupMembers approver."""
    return Approver(
        odata_type="#microsoft.graph.groupMembers",
        group_id=group_id,
        resolution=ApproverResolution(
            status=ApproverStatus.VALID,
            display_name="Finance Team",
        ),
    )


def _deleted_group_approver(group_id="group-deleted"):
    """Build a deleted groupMembers approver."""
    return Approver(
        odata_type="#microsoft.graph.groupMembers",
        group_id=group_id,
        resolution=ApproverResolution(status=ApproverStatus.GROUP_DELETED),
    )


def _empty_group_approver(group_id="group-empty"):
    """Build an empty groupMembers approver."""
    return Approver(
        odata_type="#microsoft.graph.groupMembers",
        group_id=group_id,
        resolution=ApproverResolution(
            status=ApproverStatus.GROUP_EMPTY,
            display_name="Empty Group",
        ),
    )


def _manager_approver():
    """Build a requestorManager approver (not validated statically)."""
    return Approver(
        odata_type="#microsoft.graph.requestorManager",
    )


def _internal_sponsors_approver():
    """Build an internalSponsors approver (not validated statically)."""
    return Approver(
        odata_type="#microsoft.graph.internalSponsors",
    )


def _external_sponsors_approver():
    """Build an externalSponsors approver (not validated statically)."""
    return Approver(
        odata_type="#microsoft.graph.externalSponsors",
    )


def _target_user_sponsors_approver():
    """Build a targetUserSponsors approver (not validated statically)."""
    return Approver(
        odata_type="#microsoft.graph.targetUserSponsors",
    )


def _error_user_approver(user_id="user-error"):
    """Build a singleUser approver whose lookup returned a non-404 error."""
    return Approver(
        odata_type="#microsoft.graph.singleUser",
        user_id=user_id,
        resolution=ApproverResolution(status=ApproverStatus.ERROR),
    )


def _error_group_approver(group_id="group-error"):
    """Build a groupMembers approver whose lookup returned a non-404 error."""
    return Approver(
        odata_type="#microsoft.graph.groupMembers",
        group_id=group_id,
        resolution=ApproverResolution(status=ApproverStatus.ERROR),
    )


def _invalid_entry_approver():
    """Build a singleUser approver missing the userId field."""
    return Approver(
        odata_type="#microsoft.graph.singleUser",
        resolution=ApproverResolution(status=ApproverStatus.INVALID_ENTRY),
    )


def _unresolved_approver():
    """Build a singleUser approver with resolution=None (defensive edge case)."""
    return Approver(
        odata_type="#microsoft.graph.singleUser",
        user_id="user-unresolved",
        resolution=None,
    )


def _entra_client_mock():
    client = mock.MagicMock()
    client.audited_tenant = "audited_tenant"
    client.audited_domain = DOMAIN
    client.assignment_policies = []
    client.assignment_policies_error = None
    return client


class Test_entra_access_package_assignment_policy_approvers_valid:
    """Tests for the access package assignment policy approvers check."""

    def _run(self, entra_client):
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_access_package_assignment_policy_approvers_valid.entra_access_package_assignment_policy_approvers_valid import (
                entra_access_package_assignment_policy_approvers_valid,
            )

            return entra_access_package_assignment_policy_approvers_valid().execute()

    # ------------------------------------------------------------------
    # Tenant-level: cannot list policies
    # ------------------------------------------------------------------

    def test_tenant_error_manual(self):
        """When policies cannot be listed, emit a single tenant-level MANUAL."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = None
        entra_client.assignment_policies_error = "ODataError: Forbidden"

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "entitlementManagement"
        assert result[0].resource_name == "Entitlement management"
        assert "EntitlementManagement.Read.All" in result[0].status_extended
        assert "Entra ID P2" in result[0].status_extended
        assert "ODataError: Forbidden" in result[0].status_extended

    def test_tenant_error_manual_unknown_error(self):
        """When error detail is None, fallback to 'unknown error'."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = None
        entra_client.assignment_policies_error = None

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "unknown error" in result[0].status_extended

    # ------------------------------------------------------------------
    # No policies — no findings
    # ------------------------------------------------------------------

    def test_no_policies_no_findings(self):
        """No policies requiring approval means no findings."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = []

        result = self._run(entra_client)

        assert len(result) == 0

    # ------------------------------------------------------------------
    # PASS scenarios
    # ------------------------------------------------------------------

    def test_pass_all_valid_user_approvers(self):
        """All stages have valid user approvers — PASS."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(primary_approvers=[_valid_user_approver()]),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "valid primary approvers" in result[0].status_extended

    def test_pass_manager_approver_accepted(self):
        """Manager approvers are accepted without static validation — PASS."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_manager_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "manager/sponsor" in result[0].status_extended

    def test_pass_internal_sponsors_approver_accepted(self):
        """internalSponsors approvers are accepted without static validation — PASS."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_internal_sponsors_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "manager/sponsor" in result[0].status_extended

    def test_pass_external_sponsors_approver_accepted(self):
        """externalSponsors approvers are accepted without static validation — PASS."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_external_sponsors_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "manager/sponsor" in result[0].status_extended

    def test_pass_target_user_sponsors_approver_accepted(self):
        """targetUserSponsors approvers are accepted without static validation — PASS."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_target_user_sponsors_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "manager/sponsor" in result[0].status_extended

    def test_pass_valid_group_approver(self):
        """Valid group approver — PASS."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_valid_group_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_pass_mixed_valid_user_and_manager_in_same_stage(self):
        """Valid user + manager approver in same stage — PASS with unverified note."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[
                            _valid_user_approver(),
                            _manager_approver(),
                        ],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "valid primary approvers" in result[0].status_extended
        assert "manager/sponsor" in result[0].status_extended

    def test_pass_multiple_valid_stages(self):
        """Multiple stages, all valid — PASS."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_valid_user_approver("u1")],
                    ),
                    ApprovalStage(
                        primary_approvers=[_valid_group_approver("g1")],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_pass_approval_required_for_update_only(self):
        """Policy requires approval for update only (not add) — still evaluated, PASS."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                is_add=False,
                is_update=True,
                stages=[
                    ApprovalStage(
                        primary_approvers=[_valid_user_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "PASS"

    # ------------------------------------------------------------------
    # FAIL scenarios
    # ------------------------------------------------------------------

    def test_fail_no_stages(self):
        """Approval required but no stages — FAIL."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(stages=[]),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "no approval stages" in result[0].status_extended

    def test_fail_empty_primary_approvers(self):
        """Stage has empty primary approvers list — FAIL."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[ApprovalStage(primary_approvers=[])],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "stage 1 has no primary approvers" in result[0].status_extended

    def test_fail_deleted_user(self):
        """User approver is deleted — FAIL."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_deleted_user_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "approver user deleted" in result[0].status_extended
        assert "user-deleted" in result[0].status_extended

    def test_fail_disabled_user(self):
        """User approver is disabled — FAIL."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_disabled_user_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "approver user disabled" in result[0].status_extended
        assert "Bob (disabled)" in result[0].status_extended

    def test_fail_deleted_group(self):
        """Group approver is deleted — FAIL."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_deleted_group_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "approver group deleted" in result[0].status_extended
        assert "group-deleted" in result[0].status_extended

    def test_fail_empty_group(self):
        """Group approver exists but has no members — FAIL."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_empty_group_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "approver group empty" in result[0].status_extended
        assert "Empty Group" in result[0].status_extended

    def test_fail_invalid_entry(self):
        """Approver entry missing userId — FAIL."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_invalid_entry_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "invalid approver entry" in result[0].status_extended

    def test_fail_takes_precedence_over_error(self):
        """Confirmed FAIL plus error approver — still FAIL, mentions unverified."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[
                            _deleted_user_approver(),
                            _error_user_approver(),
                        ],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "approver user deleted" in result[0].status_extended
        assert "could not be verified" in result[0].status_extended

    def test_fail_multiple_problems_single_stage(self):
        """Multiple invalid approvers in one stage — all listed."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[
                            _disabled_user_approver(),
                            _deleted_group_approver(),
                        ],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "approver user disabled" in result[0].status_extended
        assert "approver group deleted" in result[0].status_extended

    def test_fail_second_stage_empty_approvers(self):
        """Stage 2 has no primary approvers — FAIL references stage 2."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_valid_user_approver()],
                    ),
                    ApprovalStage(primary_approvers=[]),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "stage 2 has no primary approvers" in result[0].status_extended

    # ------------------------------------------------------------------
    # MANUAL scenarios (policy-level)
    # ------------------------------------------------------------------

    def test_manual_error_only(self):
        """Only error approvers (no confirmed invalid) — MANUAL."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_error_user_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be fully evaluated" in result[0].status_extended
        assert "user-error" in result[0].status_extended

    def test_manual_error_group_approver(self):
        """Group approver lookup error (non-404) — MANUAL."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_error_group_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "group-error" in result[0].status_extended

    def test_manual_unresolved_approver(self):
        """Approver with resolution=None (defensive path) — MANUAL."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_unresolved_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "approver not resolved" in result[0].status_extended

    def test_manual_valid_plus_error_no_confirmed_fail(self):
        """Valid user + error user, no confirmed fail — MANUAL (not PASS)."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[
                            _valid_user_approver(),
                            _error_user_approver(),
                        ],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"

    # ------------------------------------------------------------------
    # Multiple stages mixed
    # ------------------------------------------------------------------

    def test_multiple_stages_mixed(self):
        """Multiple stages: stage 1 valid, stage 2 has deleted user — FAIL."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                stages=[
                    ApprovalStage(
                        primary_approvers=[_valid_user_approver()],
                    ),
                    ApprovalStage(
                        primary_approvers=[_deleted_user_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "stage 2" in result[0].status_extended

    # ------------------------------------------------------------------
    # Resource naming
    # ------------------------------------------------------------------

    def test_resource_name_format(self):
        """resource_name should be 'access_package / policy_name'."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                display_name="Manager Approval",
                access_package_name="Finance Reports",
                stages=[
                    ApprovalStage(
                        primary_approvers=[_valid_user_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].resource_name == "Finance Reports / Manager Approval"

    def test_unknown_access_package_name(self):
        """Missing access package name uses 'Unknown access package'."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                access_package_name="",
                stages=[
                    ApprovalStage(
                        primary_approvers=[_valid_user_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert "Unknown access package" in result[0].resource_name

    def test_resource_id_is_policy_id(self):
        """resource_id should be the policy's ID."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                policy_id="b2eba9a1-b357-42ee-83a8-336522ed6cbf",
                stages=[
                    ApprovalStage(
                        primary_approvers=[_valid_user_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 1
        assert result[0].resource_id == "b2eba9a1-b357-42ee-83a8-336522ed6cbf"

    # ------------------------------------------------------------------
    # Multiple policies
    # ------------------------------------------------------------------

    def test_multiple_policies(self):
        """Multiple policies produce one finding each."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                policy_id="p1",
                display_name="Policy 1",
                stages=[
                    ApprovalStage(
                        primary_approvers=[_valid_user_approver()],
                    ),
                ],
            ),
            _make_policy(
                policy_id="p2",
                display_name="Policy 2",
                stages=[
                    ApprovalStage(
                        primary_approvers=[_deleted_user_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 2
        assert result[0].status == "PASS"
        assert result[0].resource_id == "p1"
        assert result[1].status == "FAIL"
        assert result[1].resource_id == "p2"

    def test_multiple_policies_mixed_statuses(self):
        """Three policies: PASS, FAIL, MANUAL — one finding each."""
        entra_client = _entra_client_mock()
        entra_client.assignment_policies = [
            _make_policy(
                policy_id="p-pass",
                display_name="Good Policy",
                stages=[
                    ApprovalStage(
                        primary_approvers=[_valid_user_approver()],
                    ),
                ],
            ),
            _make_policy(
                policy_id="p-fail",
                display_name="Bad Policy",
                stages=[
                    ApprovalStage(
                        primary_approvers=[_deleted_group_approver()],
                    ),
                ],
            ),
            _make_policy(
                policy_id="p-manual",
                display_name="Uncertain Policy",
                stages=[
                    ApprovalStage(
                        primary_approvers=[_error_user_approver()],
                    ),
                ],
            ),
        ]

        result = self._run(entra_client)

        assert len(result) == 3
        assert result[0].status == "PASS"
        assert result[0].resource_id == "p-pass"
        assert result[1].status == "FAIL"
        assert result[1].resource_id == "p-fail"
        assert result[2].status == "MANUAL"
        assert result[2].resource_id == "p-manual"
