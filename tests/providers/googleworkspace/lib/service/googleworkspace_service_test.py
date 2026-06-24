from unittest.mock import MagicMock

from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService

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
