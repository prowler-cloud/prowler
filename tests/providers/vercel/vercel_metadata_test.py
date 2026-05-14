from prowler.lib.check.models import CheckMetadata


class TestVercelMetadata:
    EXPECTED_CATEGORIES = {
        "authentication_no_stale_tokens": [
            "trust-boundaries",
            "vercel-hobby-plan",
        ],
        "authentication_token_not_expired": [
            "trust-boundaries",
            "vercel-hobby-plan",
        ],
        "deployment_production_uses_stable_target": [
            "trust-boundaries",
            "vercel-hobby-plan",
        ],
        "domain_dns_properly_configured": [
            "trust-boundaries",
            "vercel-hobby-plan",
        ],
        "domain_ssl_certificate_valid": ["encryption", "vercel-hobby-plan"],
        "domain_verified": ["trust-boundaries", "vercel-hobby-plan"],
        "project_auto_expose_system_env_disabled": [
            "trust-boundaries",
            "vercel-hobby-plan",
        ],
        "project_deployment_protection_enabled": [
            "internet-exposed",
            "vercel-hobby-plan",
        ],
        "project_directory_listing_disabled": [
            "internet-exposed",
            "vercel-hobby-plan",
        ],
        "project_environment_no_overly_broad_target": [
            "secrets",
            "vercel-hobby-plan",
        ],
        "project_environment_no_secrets_in_plain_type": [
            "secrets",
            "vercel-hobby-plan",
        ],
        "project_environment_production_vars_not_in_preview": [
            "secrets",
            "vercel-hobby-plan",
        ],
        "project_git_fork_protection_enabled": [
            "internet-exposed",
            "vercel-hobby-plan",
        ],
        "project_password_protection_enabled": [
            "internet-exposed",
            "vercel-pro-plan",
        ],
        "project_production_deployment_protection_enabled": [
            "internet-exposed",
            "vercel-pro-plan",
        ],
        "project_skew_protection_enabled": ["resilience", "vercel-pro-plan"],
        "security_custom_rules_configured": [
            "internet-exposed",
            "vercel-pro-plan",
        ],
        "security_ip_blocking_rules_configured": [
            "internet-exposed",
            "vercel-pro-plan",
        ],
        "security_managed_rulesets_enabled": [
            "internet-exposed",
            "vercel-hobby-plan",
        ],
        "security_rate_limiting_configured": [
            "internet-exposed",
            "vercel-pro-plan",
        ],
        "security_waf_enabled": ["internet-exposed", "vercel-pro-plan"],
        "team_directory_sync_enabled": [
            "trust-boundaries",
            "vercel-enterprise-plan",
        ],
        "team_member_role_least_privilege": [
            "trust-boundaries",
            "vercel-hobby-plan",
        ],
        "team_no_stale_invitations": ["trust-boundaries", "vercel-hobby-plan"],
        "team_saml_sso_enabled": ["trust-boundaries", "vercel-pro-plan"],
        "team_saml_sso_enforced": ["trust-boundaries", "vercel-pro-plan"],
    }

    def test_vercel_checks_use_legacy_and_plan_categories(self):
        vercel_metadata = CheckMetadata.get_bulk(provider="vercel")

        assert set(vercel_metadata) == set(self.EXPECTED_CATEGORIES)

        for check_id, expected_categories in self.EXPECTED_CATEGORIES.items():
            assert vercel_metadata[check_id].Categories == expected_categories
