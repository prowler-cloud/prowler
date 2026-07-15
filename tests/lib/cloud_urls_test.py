from prowler.lib.cloud_urls import (
    PROWLER_CLI_UTM_SOURCE,
    PROWLER_LOCAL_DASHBOARD_UTM_SOURCE,
    build_cloud_signup_url,
)


class TestBuildCloudSignupUrl:
    def test_builds_local_dashboard_url_with_content(self):
        assert build_cloud_signup_url(
            PROWLER_LOCAL_DASHBOARD_UTM_SOURCE, "lighthouse-ai"
        ) == (
            "https://cloud.prowler.com/sign-up?"
            "utm_source=prowler-local-dashboard&utm_content=lighthouse-ai"
        )

    def test_builds_cli_url_without_content(self):
        assert build_cloud_signup_url(PROWLER_CLI_UTM_SOURCE) == (
            "https://cloud.prowler.com/sign-up?utm_source=prowler-cli"
        )
