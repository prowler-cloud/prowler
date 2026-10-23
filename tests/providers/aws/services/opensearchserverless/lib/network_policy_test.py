from prowler.providers.aws.services.opensearchserverless.lib.network_policy import (
    resource_pattern_matches,
)


class Test_resource_pattern_matches:
    def test_exact_name_matches(self):
        assert resource_pattern_matches("collection/logs-prod", "logs-prod") is True

    def test_prefix_wildcard_with_hyphen_matches(self):
        assert resource_pattern_matches("collection/logs-*", "logs-prod") is True

    def test_prefix_wildcard_without_hyphen_matches(self):
        assert resource_pattern_matches("collection/logs*", "logs-prod") is True

    def test_single_wildcard_matches_everything(self):
        assert resource_pattern_matches("collection/*", "logs-prod") is True

    def test_different_exact_name_does_not_match(self):
        assert (
            resource_pattern_matches("collection/logs-prod-test", "logs-prod") is False
        )

    def test_uppercase_pattern_is_undetermined(self):
        assert resource_pattern_matches("collection/LOGS-PROD", "logs-prod") is None

    def test_leading_wildcard_is_undetermined(self):
        assert resource_pattern_matches("collection/*prod", "logs-prod") is None
