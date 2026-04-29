from prowler.lib.check.models import CheckMetadata


class TestVercelMetadata:
    EXPECTED_PLAN_CATEGORIES = {
        "authentication_no_stale_tokens": "vercel_hobby_plan",
        "authentication_token_not_expired": "vercel_hobby_plan",
        "deployment_production_uses_stable_target": "vercel_hobby_plan",
        "domain_dns_properly_configured": "vercel_hobby_plan",
        "domain_ssl_certificate_valid": "vercel_hobby_plan",
        "domain_verified": "vercel_hobby_plan",
        "project_auto_expose_system_env_disabled": "vercel_hobby_plan",
        "project_deployment_protection_enabled": "vercel_hobby_plan",
        "project_directory_listing_disabled": "vercel_hobby_plan",
        "project_environment_no_overly_broad_target": "vercel_hobby_plan",
        "project_environment_no_secrets_in_plain_type": "vercel_hobby_plan",
        "project_environment_production_vars_not_in_preview": "vercel_hobby_plan",
        "project_git_fork_protection_enabled": "vercel_hobby_plan",
        "project_password_protection_enabled": "vercel_pro_plan",
        "project_production_deployment_protection_enabled": "vercel_pro_plan",
        "project_skew_protection_enabled": "vercel_pro_plan",
        "security_custom_rules_configured": "vercel_pro_plan",
        "security_ip_blocking_rules_configured": "vercel_pro_plan",
        "security_managed_rulesets_enabled": "vercel_hobby_plan",
        "security_rate_limiting_configured": "vercel_pro_plan",
        "security_waf_enabled": "vercel_pro_plan",
        "team_directory_sync_enabled": "vercel_enterprise_plan",
        "team_member_role_least_privilege": "vercel_hobby_plan",
        "team_no_stale_invitations": "vercel_hobby_plan",
        "team_saml_sso_enabled": "vercel_pro_plan",
        "team_saml_sso_enforced": "vercel_pro_plan",
    }

    def test_vercel_checks_use_exactly_one_plan_category(self):
        vercel_metadata = CheckMetadata.get_bulk(provider="vercel")

        assert set(vercel_metadata) == set(self.EXPECTED_PLAN_CATEGORIES)

        for check_id, expected_category in self.EXPECTED_PLAN_CATEGORIES.items():
            assert vercel_metadata[check_id].Categories == [expected_category]
