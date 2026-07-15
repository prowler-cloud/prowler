from urllib.parse import urlencode

CLOUD_SIGN_UP_URL = "https://cloud.prowler.com/sign-up"
PROWLER_CLI_UTM_SOURCE = "prowler-cli"
PROWLER_LOCAL_DASHBOARD_UTM_SOURCE = "prowler-local-dashboard"


def build_cloud_signup_url(source: str, content: str | None = None) -> str:
    """Build a Prowler Cloud sign-up URL with canonical UTM attribution.

    Args:
        source: Surface that sent the visitor.
        content: Optional feature or CTA slug within that surface.

    Returns:
        Prowler Cloud sign-up URL with the supplied UTM values.
    """
    params = {"utm_source": source}
    if content is not None:
        params["utm_content"] = content

    return f"{CLOUD_SIGN_UP_URL}?{urlencode(params)}"
