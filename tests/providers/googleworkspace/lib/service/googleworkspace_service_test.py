from prowler.providers.googleworkspace.lib.service.service import GoogleWorkspaceService


class TestIsCustomerLevelPolicy:
    def test_no_policy_query(self):
        """Policy without policyQuery is customer-level"""
        assert GoogleWorkspaceService._is_customer_level_policy({}) is True

    def test_empty_policy_query(self):
        """Policy with empty policyQuery is customer-level"""
        assert (
            GoogleWorkspaceService._is_customer_level_policy({"policyQuery": {}})
            is True
        )

    def test_org_unit_targeted(self):
        """Policy targeting a specific OU is not customer-level"""
        assert (
            GoogleWorkspaceService._is_customer_level_policy(
                {"policyQuery": {"orgUnit": "orgUnits/abc123"}}
            )
            is False
        )

    def test_group_targeted(self):
        """Policy targeting a specific group is not customer-level"""
        assert (
            GoogleWorkspaceService._is_customer_level_policy(
                {"policyQuery": {"group": "groups/xyz789"}}
            )
            is False
        )

    def test_org_unit_and_group_targeted(self):
        """Policy targeting both OU and group is not customer-level"""
        assert (
            GoogleWorkspaceService._is_customer_level_policy(
                {
                    "policyQuery": {
                        "orgUnit": "orgUnits/abc123",
                        "group": "groups/xyz789",
                    }
                }
            )
            is False
        )
