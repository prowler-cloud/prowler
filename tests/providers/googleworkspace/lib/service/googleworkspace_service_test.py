from unittest.mock import MagicMock

import pytest

from prowler.providers.googleworkspace.lib.service.service import (
    CUSTOMER_SCOPE,
    OVERRIDE_SCOPE,
    UNKNOWN_SCOPE,
    GoogleWorkspaceService,
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
