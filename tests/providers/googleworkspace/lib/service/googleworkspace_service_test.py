from unittest.mock import MagicMock

import pytest

from prowler.providers.googleworkspace.lib.service.service import (
    CUSTOMER_SCOPE,
    OVERRIDE_SCOPE,
    UNKNOWN_SCOPE,
    GoogleWorkspaceService,
    ServicePolicies,
)

ROOT_OU_ID = "03ph8a2z1234"


def _make_service(root_org_unit_id=ROOT_OU_ID):
    """Create a GoogleWorkspaceService with a mocked provider."""
    provider = MagicMock()
    provider.identity.root_org_unit_id = root_org_unit_id
    provider.audit_config = {}
    provider.fixer_config = {}
    provider.session.credentials = MagicMock()
    svc = object.__new__(GoogleWorkspaceService)
    svc.provider = provider
    return svc


class TestIsCustomerLevelPolicy:
    def test_no_policy_query(self):
        """Policy without policyQuery is customer-level"""
        svc = _make_service()
        assert svc._is_customer_level_policy({}) is True

    def test_empty_policy_query(self):
        """Policy with empty policyQuery is customer-level"""
        svc = _make_service()
        assert svc._is_customer_level_policy({"policyQuery": {}}) is True

    def test_root_org_unit_accepted(self):
        """Policy targeting the root OU is customer-level"""
        svc = _make_service()
        assert (
            svc._is_customer_level_policy(
                {"policyQuery": {"orgUnit": f"orgUnits/{ROOT_OU_ID}"}}
            )
            is True
        )

    def test_sub_org_unit_rejected(self):
        """Policy targeting a sub-OU is not customer-level"""
        svc = _make_service()
        assert (
            svc._is_customer_level_policy(
                {"policyQuery": {"orgUnit": "orgUnits/sub_ou_abc123"}}
            )
            is False
        )

    def test_group_targeted(self):
        """Policy targeting a specific group is not customer-level"""
        svc = _make_service()
        assert (
            svc._is_customer_level_policy({"policyQuery": {"group": "groups/xyz789"}})
            is False
        )

    def test_org_unit_and_group_targeted(self):
        """Policy targeting both OU and group is not customer-level"""
        svc = _make_service()
        assert (
            svc._is_customer_level_policy(
                {
                    "policyQuery": {
                        "orgUnit": f"orgUnits/{ROOT_OU_ID}",
                        "group": "groups/xyz789",
                    }
                }
            )
            is False
        )

    def test_no_root_org_unit_id_rejects_all_ou(self):
        """When root OU ID is unknown, all OU-targeted policies are rejected"""
        svc = _make_service(root_org_unit_id=None)
        assert (
            svc._is_customer_level_policy(
                {"policyQuery": {"orgUnit": f"orgUnits/{ROOT_OU_ID}"}}
            )
            is False
        )


class TestPolicyScope:
    @pytest.mark.parametrize(
        "policy, expected",
        [
            ({}, CUSTOMER_SCOPE),
            ({"policyQuery": {}}, CUSTOMER_SCOPE),
            ({"policyQuery": None}, CUSTOMER_SCOPE),
            ({"policyQuery": {"orgUnit": ""}}, CUSTOMER_SCOPE),
            ({"policyQuery": {"orgUnit": f"orgUnits/{ROOT_OU_ID}"}}, CUSTOMER_SCOPE),
            ({"policyQuery": {"orgUnit": "orgUnits/sub_ou"}}, OVERRIDE_SCOPE),
            ({"policyQuery": {"group": "groups/xyz"}}, OVERRIDE_SCOPE),
            (
                {"policyQuery": {"group": "groups/xyz", "orgUnit": "orgUnits/sub_ou"}},
                OVERRIDE_SCOPE,
            ),
        ],
    )
    def test_scope_with_a_known_root_org_unit(self, policy, expected):
        assert _make_service()._policy_scope(policy) == expected

    @pytest.mark.parametrize("org_unit", [f"orgUnits/{ROOT_OU_ID}", "orgUnits/sub_ou"])
    def test_without_the_root_id_an_org_unit_scope_is_unknown(self, org_unit):
        """The root OU and a sub-OU are indistinguishable, so neither may be assumed"""
        svc = _make_service(root_org_unit_id=None)

        assert (
            svc._policy_scope({"policyQuery": {"orgUnit": org_unit}}) == UNKNOWN_SCOPE
        )

    def test_a_group_is_an_override_even_without_the_root_id(self):
        svc = _make_service(root_org_unit_id=None)

        assert (
            svc._policy_scope({"policyQuery": {"group": "groups/xyz"}})
            == OVERRIDE_SCOPE
        )


def _policy(
    setting_type,
    value,
    sort_order=None,
    org_unit=f"orgUnits/{ROOT_OU_ID}",
    group=None,
):
    """Build a policy as the Cloud Identity Policy API returns it."""
    policy = {"setting": {"type": f"settings/{setting_type}", "value": value}}
    query = {}
    if org_unit:
        query["orgUnit"] = org_unit
    if group:
        query["group"] = group
    if sort_order is not None:
        query["sortOrder"] = sort_order
    if query:
        policy["policyQuery"] = query
    return policy


class TestEffectivePolicies:
    def test_the_greatest_sort_order_wins_whatever_the_api_order(self):
        """The ADMIN policy saved in the console outranks Google's SYSTEM defaults, even when the API returns it first"""
        admin = _policy("security.password", {"minimumLength": 12}, 201.00131)
        default_a = _policy("security.password", {"minimumLength": 8}, 100.00001)
        default_b = _policy("security.password", {"minimumLength": 8}, 100.00003)
        svc = _make_service()

        assert svc._effective_policies([admin, default_a, default_b]) == [admin]
        assert svc._effective_policies([default_a, default_b, admin]) == [admin]

    def test_each_setting_type_is_reduced_on_its_own(self):
        password_admin = _policy("security.password", {"minimumLength": 12}, 201.1)
        password_default = _policy("security.password", {"minimumLength": 8}, 100.1)
        session_default = _policy(
            "security.session_controls", {"webSessionDuration": "1209600s"}, 100.3
        )

        assert _make_service()._effective_policies(
            [password_admin, password_default, session_default]
        ) == [password_admin, session_default]

    def test_a_single_policy_is_kept_as_is(self):
        policy = _policy("sites.service_status", {"serviceState": "ENABLED"})

        assert _make_service()._effective_policies([policy]) == [policy]

    def test_without_a_sort_order_the_last_policy_wins(self):
        """No sort order means no documented precedence, so the API order is kept"""
        first = _policy("sites.service_status", {"serviceState": "ENABLED"})
        last = _policy("sites.service_status", {"serviceState": "DISABLED"})

        assert _make_service()._effective_policies([first, last]) == [last]

    def test_policies_outside_the_customer_scope_are_dropped(self):
        root = _policy("security.password", {"minimumLength": 8}, 100.1)
        sub_ou = _policy(
            "security.password", {"minimumLength": 14}, 300.1, org_unit="orgUnits/sub"
        )
        group = _policy(
            "security.password", {"minimumLength": 16}, 400.1, group="groups/g1"
        )

        assert _make_service()._effective_policies([sub_ou, root, group]) == [root]

    def test_rules_are_items_rather_than_values_so_every_one_is_kept(self):
        """Each rule.* policy is a distinct rule, not a competing value for one setting"""
        dlp_a = _policy("rule.dlp", {"displayName": "cards", "state": "ACTIVE"}, 1)
        dlp_b = _policy("rule.dlp", {"displayName": "ids", "state": "INACTIVE"}, 2)
        alert = _policy("rule.system_defined_alerts", {"displayName": "Leaked"}, 1)

        assert _make_service()._effective_policies([dlp_a, dlp_b, alert]) == [
            dlp_a,
            dlp_b,
            alert,
        ]

    def test_no_policies(self):
        assert _make_service()._effective_policies([]) == []


class TestServiceStatus:
    def test_off_at_the_customer_level_with_no_override(self):
        status = _policy("chat.service_status", {"serviceState": "DISABLED"}, 201.1)
        other = _policy("chat.chat_apps_access", {"enableApps": True}, 100.1)

        assert _make_service()._service_status(
            [other, status], "chat.service_status"
        ) == (
            "DISABLED",
            False,
        )

    def test_the_greatest_sort_order_gives_the_state(self):
        default = _policy("chat.service_status", {"serviceState": "ENABLED"}, 100.1)
        admin = _policy("chat.service_status", {"serviceState": "DISABLED"}, 201.1)

        assert _make_service()._service_status(
            [admin, default], "chat.service_status"
        ) == (
            "DISABLED",
            False,
        )

    def test_an_org_unit_or_group_with_its_own_status_is_an_override(self):
        root = _policy("chat.service_status", {"serviceState": "DISABLED"}, 201.1)
        sub_ou = _policy(
            "chat.service_status",
            {"serviceState": "ENABLED"},
            301.1,
            org_unit="orgUnits/sub",
        )
        group = _policy(
            "chat.service_status", {"serviceState": "ENABLED"}, 401.1, group="groups/g1"
        )

        svc = _make_service()
        assert svc._service_status([root, sub_ou], "chat.service_status") == (
            "DISABLED",
            True,
        )
        assert svc._service_status([root, group], "chat.service_status") == (
            "DISABLED",
            True,
        )

    def test_a_sub_org_unit_that_is_also_off_is_not_an_override(self):
        """An org unit that turns the service off as well changes nothing for anyone"""
        root = _policy("chat.service_status", {"serviceState": "DISABLED"}, 201.1)
        sub_ou = _policy(
            "chat.service_status",
            {"serviceState": "DISABLED"},
            301.1,
            org_unit="orgUnits/sub",
        )

        assert _make_service()._service_status(
            [root, sub_ou], "chat.service_status"
        ) == (
            "DISABLED",
            False,
        )

    def test_an_unresolved_scope_counts_as_an_override(self):
        """Without the root OU id a scoped policy may be the root or a sub-OU; neither may be assumed"""
        status = _policy("chat.service_status", {"serviceState": "DISABLED"}, 201.1)

        assert _make_service(root_org_unit_id=None)._service_status(
            [status], "chat.service_status"
        ) == (None, True)

    def test_no_status_policy(self):
        other = _policy("chat.chat_apps_access", {"enableApps": True}, 100.1)

        assert _make_service()._service_status([other], "chat.service_status") == (
            None,
            False,
        )


class TestServicePolicies:
    @pytest.mark.parametrize(
        "state, overridden, expected",
        [
            ("DISABLED", False, True),
            ("DISABLED", True, False),
            ("ENABLED", False, False),
            (None, False, False),
        ],
    )
    def test_off_for_everyone(self, state, overridden, expected):
        policies = ServicePolicies(
            service_state=state, service_state_overridden=overridden
        )

        assert policies.off_for_everyone is expected


class TestListPolicies:
    def test_collects_every_page(self):
        svc = _make_service()
        page_1 = {"policies": [_policy("gmail.pop_access", {"enablePopAccess": True})]}
        page_2 = {
            "policies": [_policy("gmail.imap_access", {"enableImapAccess": True})]
        }
        request_1, request_2 = MagicMock(), MagicMock()
        request_1.execute.return_value = page_1
        request_2.execute.return_value = page_2
        service = MagicMock()
        service.policies().list.return_value = request_1
        service.policies().list_next.side_effect = [request_2, None]

        policies, succeeded = svc._list_policies(
            service, 'setting.type.matches("gmail.*")', "fetching Gmail policies"
        )

        assert succeeded is True
        assert policies == page_1["policies"] + page_2["policies"]
        service.policies().list.assert_called_once_with(
            pageSize=100, filter='setting.type.matches("gmail.*")'
        )

    def test_a_failing_page_keeps_what_was_read_and_reports_the_failure(self):
        svc = _make_service()
        page_1 = {"policies": [_policy("gmail.pop_access", {"enablePopAccess": True})]}
        request_1, request_2 = MagicMock(), MagicMock()
        request_1.execute.return_value = page_1
        request_2.execute.side_effect = Exception("boom")
        service = MagicMock()
        service.policies().list.return_value = request_1
        service.policies().list_next.side_effect = [request_2, None]

        policies, succeeded = svc._list_policies(
            service, 'setting.type.matches("gmail.*")', "fetching Gmail policies"
        )

        assert succeeded is False
        assert policies == page_1["policies"]

    def test_a_failing_list_call_reports_the_failure(self):
        svc = _make_service()
        service = MagicMock()
        service.policies().list.side_effect = Exception("boom")

        policies, succeeded = svc._list_policies(
            service, 'setting.type.matches("gmail.*")', "fetching Gmail policies"
        )

        assert succeeded is False
        assert policies == []
