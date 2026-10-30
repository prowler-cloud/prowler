from unittest import mock

from prowler.config.config import prowler_version
from prowler.lib.banner import (
    DASHBOARD_CTA_URL,
    NO_PROMOTIONS_ENV,
    print_dashboard_banner,
    print_dashboard_loading,
    print_dashboard_promotion,
    print_prowler_cloud_banner,
    promotions_disabled,
)


class TestPromotionsDisabled:
    def test_unset_is_enabled(self, monkeypatch):
        monkeypatch.delenv(NO_PROMOTIONS_ENV, raising=False)
        assert promotions_disabled() is False

    def test_truthy_values_disable(self, monkeypatch):
        for value in ("1", "true", "YES", "anything"):
            monkeypatch.setenv(NO_PROMOTIONS_ENV, value)
            assert promotions_disabled() is True, value

    def test_falsy_values_keep_enabled(self, monkeypatch):
        for value in ("0", "false", "no", "", "  "):
            monkeypatch.setenv(NO_PROMOTIONS_ENV, value)
            assert promotions_disabled() is False, value


class TestDashboardBanner:
    def test_header_has_identity_and_version(self, capsys):
        print_dashboard_banner()
        out = capsys.readouterr().out
        assert f"Local Dashboard - v{prowler_version}" in out
        assert "Date:" in out
        assert "Loading CSV files" not in out
        # The long commercial banner is not part of the dashboard header
        assert "snapshot" not in out
        assert "Start free" not in out
        assert "aws s3 cp" not in out

    def test_loading_line_names_the_directory(self, capsys):
        print_dashboard_loading("/tmp/synthetic/output")
        out = capsys.readouterr().out
        assert "Loading CSV files from /tmp/synthetic/output ..." in out

    def test_promotion_block_content(self, monkeypatch, capsys):
        monkeypatch.delenv(NO_PROMOTIONS_ENV, raising=False)
        print_dashboard_promotion()
        out = capsys.readouterr().out
        assert "Keep scanning locally. Bring your findings to Prowler Cloud." in out
        assert (
            "Import your accompanying OCSF report to explore managed security workflows."
            in out
        )
        assert "Explore Prowler Cloud" in out
        assert "\u2713" in out and "\u2502" in out  # check and bar like the CLI banner
        assert "Nothing is uploaded automatically." in out
        # The UTM-tagged URL is only the OSC 8 target; the visible text is the domain
        assert f"\033]8;;{DASHBOARD_CTA_URL}\033\\cloud.prowler.com" in out
        assert f"\n{DASHBOARD_CTA_URL}" not in out
        assert out.count(DASHBOARD_CTA_URL) == 1
        assert DASHBOARD_CTA_URL == (
            "https://cloud.prowler.com/sign-up?utm_source=prowler-dashboard-terminal"
            "&utm_medium=oss&utm_campaign=report-handoff"
        )
        assert out.count("Keep scanning locally.") == 1
        # Readable in 80 columns: every non-URL line fits
        for line in out.splitlines():
            if "http" not in line and "\033" not in line:
                assert len(line) <= 80, line

    def test_promotion_skipped_when_disabled(self, monkeypatch, capsys):
        monkeypatch.setenv(NO_PROMOTIONS_ENV, "1")
        print_dashboard_promotion()
        assert capsys.readouterr().out == ""

    def test_scan_banner_untouched(self, capsys):
        with mock.patch("prowler.lib.banner.print_prowler_cloud_banner") as cloud:
            from prowler.lib.banner import print_banner

            print_banner()
        out = capsys.readouterr().out
        assert f"CLI - v{prowler_version}" in out
        cloud.assert_called_once_with(None)


class TestCliCloudBanner:
    def test_content_is_brief_and_tailored(self, monkeypatch, capsys):
        monkeypatch.delenv(NO_PROMOTIONS_ENV, raising=False)
        monkeypatch.setenv("NO_COLOR", "1")
        print_prowler_cloud_banner("aws")
        out = capsys.readouterr().out
        assert "Prowler Cloud gives you the full picture." in out
        assert "Exploitable Issues" in out
        assert "AWS Organization" in out
        assert "cloud.prowler.com" in out
        assert "Nothing is uploaded automatically." in out
        assert "Bulk Provisioning" not in out
        assert len([ln for ln in out.splitlines() if ln.strip()]) <= 12

    def test_unknown_provider_uses_generic_line(self, monkeypatch, capsys):
        monkeypatch.delenv(NO_PROMOTIONS_ENV, raising=False)
        print_prowler_cloud_banner("github")
        out = capsys.readouterr().out
        assert "connect all your accounts" in out
        assert "AWS Organization" not in out

    def test_respects_no_promotions(self, monkeypatch, capsys):
        monkeypatch.setenv(NO_PROMOTIONS_ENV, "1")
        print_prowler_cloud_banner("aws")
        assert capsys.readouterr().out == ""
