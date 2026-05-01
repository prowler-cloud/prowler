from prowler.providers.kubernetes.services.rbac.lib.role_permissions import (
    is_rule_allowing_permissions,
)
from prowler.providers.kubernetes.services.rbac.rbac_service import Rule


class TestCheckRolePermissions:
    def test_is_rule_allowing_permissions(self):
        rules = [
            Rule(resources=["pods", "services"], verbs=["get", "list"]),
            Rule(resources=["deployments"], verbs=["create", "delete"]),
        ]
        assert is_rule_allowing_permissions(
            rules, ["pods", "deployments"], ["get", "create"]
        )

    def test_no_permissions(self):
        assert not is_rule_allowing_permissions([], ["pods"], ["get"])

    def test_no_matching_rules(self):
        rules = [
            Rule(resources=["services"], verbs=["get", "list"]),
            Rule(resources=["pods"], verbs=["create", "delete"]),
        ]
        assert not is_rule_allowing_permissions(
            rules, ["deployments", "configmaps"], ["get", "create"]
        )

    def test_empty_rules(self):
        assert not is_rule_allowing_permissions([], ["pods"], ["get"])

    def test_empty_resources_and_verbs(self):
        rules = [Rule(resources=["pods"], verbs=["get"])]
        assert not is_rule_allowing_permissions(rules, [], [])

    def test_matching_rule_with_empty_resources_or_verbs(self):
        rules = [Rule(resources=["pods"], verbs=["get"])]
        assert not is_rule_allowing_permissions(rules, [], ["get"])
        assert not is_rule_allowing_permissions(rules, ["pods"], [])

    def test_rule_with_non_matching_api_group(self):
        rules = [Rule(resources=["pods"], verbs=["get"], apiGroups=["apps"])]
        assert not is_rule_allowing_permissions(rules, ["pods"], ["get"])

    def test_rule_with_matching_api_group(self):
        rules = [Rule(resources=["pods"], verbs=["get"], apiGroups=[""])]
        assert is_rule_allowing_permissions(rules, ["pods"], ["get"])

    def test_default_api_group_is_core(self):
        rules = [Rule(resources=["pods"], verbs=["get"], apiGroups=[""])]
        assert is_rule_allowing_permissions(rules, ["pods"], ["get"])

        rules = [
            Rule(
                resources=["validatingwebhookconfigurations"],
                verbs=["create"],
                apiGroups=["admissionregistration.k8s.io"],
            )
        ]
        assert not is_rule_allowing_permissions(
            rules, ["validatingwebhookconfigurations"], ["create"]
        )

    def test_explicit_non_core_api_group(self):
        rules = [
            Rule(
                resources=["validatingwebhookconfigurations"],
                verbs=["create"],
                apiGroups=["admissionregistration.k8s.io"],
            )
        ]
        assert is_rule_allowing_permissions(
            rules,
            ["validatingwebhookconfigurations"],
            ["create"],
            ["admissionregistration.k8s.io"],
        )

    def test_rule_with_wildcard_api_group(self):
        rules = [Rule(resources=["pods"], verbs=["get"], apiGroups=["*"])]
        assert is_rule_allowing_permissions(rules, ["pods"], ["get"])
        assert is_rule_allowing_permissions(rules, ["pods"], ["get"], ["apps"])

    def test_rule_with_wildcard_resources(self):
        rules = [Rule(resources=["*"], verbs=["get"], apiGroups=[""])]
        assert is_rule_allowing_permissions(rules, ["pods"], ["get"])

    def test_rule_with_wildcard_verbs(self):
        rules = [Rule(resources=["pods"], verbs=["*"], apiGroups=[""])]
        assert is_rule_allowing_permissions(rules, ["pods"], ["get"])
