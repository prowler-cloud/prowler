from prowler.lib.banner import (
    CLOUD_BANNER_URL,
    CLOUD_DISPLAY_TEXT,
    _hyperlink,
)


class TestProwlerCloudBanner:
    def test_uses_cli_source_without_content(self):
        assert CLOUD_BANNER_URL == (
            "https://cloud.prowler.com/sign-up?utm_source=prowler-cli"
        )

    def test_wraps_display_text_in_cloud_hyperlink(self):
        assert _hyperlink(CLOUD_BANNER_URL, CLOUD_DISPLAY_TEXT) == (
            f"\033]8;;{CLOUD_BANNER_URL}\033\\" f"{CLOUD_DISPLAY_TEXT}\033]8;;\033\\"
        )
